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
use indexmap::IndexMap;
use serde::Deserialize;
use sqlx::MySqlPool;
use structopt::StructOpt;
use tokio::sync::{RwLock, Semaphore};

/// Import Caddy logs to MySQL for analysis.
#[derive(StructOpt)]
struct Opt {
  /// Path to the log file.
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

  // The file id is the BLAKE3 hash of the first line
  let mut file_id: Option<String> = None;
  let insertion_concurrency = Arc::new(Semaphore::new(50));
  let insertion_busy = Arc::new(RwLock::new(()));
  let rows_inserted: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

  for (i, line) in logfile.lines().enumerate() {
    let line_no = i + 1;
    let line = line?;
    if line.is_empty() {
      continue;
    }
    let pre_decoded: serde_json::Value = serde_json::from_str(&line)?;
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
    let rows_inserted = rows_inserted.clone();
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
        entry.ts,
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
          if res.rows_affected() == 0 {
            tracing::debug!(line_no, "did not insert log entry");
          } else {
            rows_inserted.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(line_no, "inserted log entry");
          }
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
  eprintln!(
    "Success. {} entries inserted.",
    rows_inserted.load(Ordering::Relaxed)
  );

  Ok(())
}
