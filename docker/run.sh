#!/bin/sh

exec /bin/caddy-log-to-mysql "$LOGFILE" "$MYSQL_URI"
