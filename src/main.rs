use std::{
  fs::File,
  io::{BufRead, BufReader},
  path::PathBuf,
  sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
  },
};

use anyhow::Result;
use chrono::NaiveDateTime;
use indexmap::IndexMap;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use sqlx::MySqlPool;
use structopt::StructOpt;
use tokio::sync::{RwLock, Semaphore};

/// Import Caddy logs to MySQL for analysis.
#[derive(StructOpt)]
struct Opt {
  /// Path to Caddy's log file in JSON format.
  input: PathBuf,

  /// MySQL connection string.
  output: String,
}

#[derive(Deserialize)]
struct LogEntry {
  ts: f64,
  user_id: Option<String>,
  duration: f64,
  size: u64,
  status: u16,
  resp_headers: IndexMap<String, Vec<String>>,
  request: RequestInfo,
}

#[derive(Deserialize)]
struct RequestInfo {
  remote_addr: String,
  proto: String,
  method: String,
  host: String,
  uri: String,
  headers: IndexMap<String, Vec<String>>,
}

#[derive(Default)]
struct Stats {
  rows_inserted: AtomicU64,
  rows_processed: AtomicU64,
}

fn main() -> Result<()> {
  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap()
    .block_on(async_main())
}

async fn async_main() -> Result<()> {
  tracing_subscriber::fmt::init();

  let opt = Opt::from_args();
  let logfile = BufReader::new(File::open(&opt.input)?);
  let db = MySqlPool::connect(&opt.output).await?;

  sqlx::migrate!().run(&db).await?;

  eprintln!("Importing from file {}.", opt.input.to_string_lossy());

  // The file id is the BLAKE3 hash of the first line
  let mut file_id: Option<String> = None;
  let insertion_concurrency = Arc::new(Semaphore::new(50));
  let insertion_busy = Arc::new(RwLock::new(()));
  let stats: Arc<Stats> = Arc::new(Default::default());

  let spinner_style = ProgressStyle::default_spinner().template("{spinner} {wide_msg}");
  let pb = ProgressBar::new(0);
  pb.set_style(spinner_style);

  for (i, line) in logfile.lines().enumerate() {
    let line_no = i + 1;
    let line = line?;
    if line.is_empty() {
      continue;
    }
    let pre_decoded: serde_json::Value = match serde_json::from_str(&line) {
      Ok(x) => x,
      Err(e) => {
        tracing::error!(line_no, error = %e, "json decode error");
        continue;
      }
    };
    if !pre_decoded
      .get("msg")
      .and_then(|x| x.as_str())
      .map(|x| x == "handled request")
      .unwrap_or(false)
    {
      continue;
    }

    if file_id.is_none() {
      file_id = Some(blake3::hash(line.as_bytes()).to_hex().to_string());
      tracing::info!(file_id = %file_id.as_ref().unwrap(), "generated file id");
    }
    let file_id = file_id.as_ref().unwrap().clone();

    let entry: LogEntry = match serde_json::from_value(pre_decoded) {
      Ok(x) => x,
      Err(e) => {
        tracing::error!(error = %e, raw = %line, line_no, "cannot decode log");
        continue;
      }
    };

    let permit = insertion_concurrency.clone().acquire_owned().await.unwrap();
    let busy = insertion_busy.clone().read_owned().await;
    let db = db.clone();
    let stats = stats.clone();
    let pb = pb.clone();
    tokio::spawn(async move {
      let res = sqlx::query!(
        r#"
        insert ignore into logs
        (
          file_id,
          line_no,
          ts,
          user_id,
          duration,
          size,
          status_code,
          resp_headers,
          remote_addr,
          proto,
          method,
          host,
          uri,
          req_headers
        ) values(
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
      "#,
        file_id,
        line_no as u64,
        NaiveDateTime::from_timestamp(entry.ts as i64, (entry.ts.fract() * 1_000_000_000.0) as u32),
        entry.user_id.as_ref().map(|x| x.as_str()).unwrap_or(""),
        entry.duration,
        entry.size,
        entry.status,
        serde_json::to_string(&entry.resp_headers).unwrap(),
        entry.request.remote_addr,
        entry.request.proto,
        entry.request.method,
        entry.request.host,
        entry.request.uri,
        serde_json::to_string(&entry.request.headers).unwrap(),
      )
      .execute(&db)
      .await;

      match res {
        Ok(res) => {
          let rows_inserted = if res.rows_affected() == 0 {
            tracing::debug!(line_no, "did not insert log entry");
            stats.rows_inserted.load(Ordering::Relaxed)
          } else {
            tracing::debug!(line_no, "inserted log entry");
            stats.rows_inserted.fetch_add(1, Ordering::Relaxed) + 1
          };
          let rows_processed = stats.rows_processed.fetch_add(1, Ordering::Relaxed) + 1;
          pb.set_message(format!(
            "Adding logs... {}/{}",
            rows_inserted, rows_processed
          ));
          pb.inc(1);
        }
        Err(e) => {
          tracing::error!(line_no, %file_id, error = %e, "failed to insert log entry");
        }
      }

      drop(busy);
      drop(permit);
    });
  }
  insertion_busy.write().await;
  pb.finish();
  eprintln!("Success.");

  Ok(())
}
