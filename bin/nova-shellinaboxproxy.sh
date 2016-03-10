#!/bin/bash

LISTEN_HOST="0.0.0.0"
LISTEN_PORT="6084"
WORKERS="1"
APPLICATION="shellinaboxproxy:server"
#LOG_LEVEL="DEBUG"
LOG_LEVEL="INFO"
PID_FILE="/var/run/nova-shellinaboxproxy.pid"
LOGFILE="/var/log/nova/nova-shellinaboxproxy.log"

OPTS="--bind=${LISTEN_HOST}:${LISTEN_PORT}"
OPTS="${OPTS} --workers=${WORKERS}"
#OPTS="${OPTS} --daemon"
OPTS="${OPTS} --log-leve=${LOG_LEVEL}"
OPTS="${OPTS} --pid=${PID_FILE}"
gunicorn ${OPTS} ${APPLICATION} > ${LOGFILE} 2>&1 &



