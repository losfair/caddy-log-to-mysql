-- Add migration script here
create table logs(
  file_id varchar(255) not null,
  line_no int not null,
  ts double not null,
  user_id varchar(255) not null,
  duration double not null,
  size int not null,
  status_code int not null,
  resp_headers json not null,

  -- `.request`
  remote_addr varchar(255) not null,
  proto varchar(255) not null,
  method varchar(255) not null,
  host varchar(255) not null,
  uri text not null,
  req_headers json not null,

  primary key (file_id, line_no)
);
