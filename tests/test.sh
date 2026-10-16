#!/bin/bash

set -u

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd "$SCRIPT_DIR" || {
    echo "Error: Failed to change directory to $SCRIPT_DIR" >&2
    exit 1
}

server="../build/server"

if [ ! -x "$server" ]; then
    echo "Error: $server executable not found or lacks execute permissions." >&2
    exit 1
fi

port=$(python socket_utils.py)
port_err=$?
if [ $port_err -ne 0 ]; then
    echo "Error: Failed to locate an available port." >&2
    exit 1
fi

"$server" test_static/ correlated.txt "$port" &
server_pid=$!

cleanup() {
    if kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid"
        wait "$server_pid"
    fi
}

trap cleanup EXIT INT TERM

# Give the server a moment to bind to the socket
sleep 0.2

if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "Error: Server failed to start or crashed unexpectedly." >&2
    exit 1
fi

python test-runner.py "$port"
retval=$?

if [ "$retval" -ne 0 ]; then
    echo "Test runner failed with exit code $retval." >&2
    exit "$retval"
fi

# TODO test same port
