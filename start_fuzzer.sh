#!/bin/bash

# JAM Fuzzer Startup Script
# This script starts the JAM fuzzer server and adapter

set -e

echo "Starting JAM Fuzzer Implementation..."

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    pkill -f "uvicorn.*server.server" || true
    pkill -f "adapter.py" || true
    rm -f /tmp/jam_target.sock
    exit 0
}

# Set up cleanup on script exit
trap cleanup EXIT INT TERM

# Start the server
echo "Starting JAM server..."
cd "$PROJECT_ROOT/server"
python -m uvicorn server:app --host 0.0.0.0 --port 8000 --log-level info &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to start..."
sleep 5

# Check if server is running
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "Failed to start server"
    exit 1
fi

echo "Server started successfully"

# Start the fuzzer adapter
echo "Starting fuzzer adapter..."
cd "$PROJECT_ROOT/jam_fuzzer_adapter"
python adapter.py --socket /tmp/jam_target.sock --api-url http://localhost:8000 &
ADAPTER_PID=$!

# Wait for adapter to start
echo "Waiting for adapter to start..."
sleep 3

# Check if socket exists
if [ ! -S /tmp/jam_target.sock ]; then
    echo "Failed to start fuzzer adapter"
    exit 1
fi

echo "Fuzzer adapter started successfully"
echo "Fuzzer is ready for testing!"
echo ""
echo "To test with minifuzz, run:"
echo "cd jam-conformance/fuzz-proto/minifuzz"
echo "python minifuzz.py -d ../examples/v1/no_forks --target-sock /tmp/jam_target.sock"
echo ""
echo "Press Ctrl+C to stop the fuzzer"

# Wait for user interrupt
wait
