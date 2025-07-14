#!/bin/bash
# Wrapper script for rapidsnark to ensure clean JSON output

# Run rapidsnark and capture its exit code
./rapidsnark/rapidsnark "$@" > /tmp/rapidsnark.log 2>&1
EXIT_CODE=$?

# If successful, the JSON files should be created
if [ $EXIT_CODE -eq 0 ]; then
  # Files are already created by rapidsnark
  exit 0
else
  # Print error and exit with same code
  cat /tmp/rapidsnark.log >&2
  exit $EXIT_CODE
fi 