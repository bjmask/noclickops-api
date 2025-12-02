#!/bin/sh
# Kill any process listening on port 8080

set -ex

PID=$(lsof -ti:8080 2>/dev/null || true)

if [ -n "$PID" ]; then
  echo "Killing process $PID on port 8080..."
  kill -9 $PID
  
  # Wait for port to be released
  for i in $(seq 1 20); do
    if ! lsof -ti:8080 > /dev/null; then
      echo "Port 8080 released."
      break
    fi
    echo "Waiting for port 8080 to close..."
    sleep 0.1
  done
fi

# Double check
if lsof -ti:8080 > /dev/null; then
  echo "WARNING: Port 8080 is still in use; continuing without kill."
fi

# Start the application
echo "Starting application..."
APP_ENV=dev APP_USER=air air
 