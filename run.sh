#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <filename>"
  exit 1
fi

FILE="$1"

REMOTE_USER="group8"
REMOTE_HOST="130.89.144.10"
REMOTE_PATH="/home/group8/backups/$FILE"
LOCAL_PATH="src/data/"

# Use scp to copy the file or directory
scp -r "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}" "${LOCAL_PATH}"

# Run analysing script
yarn start

