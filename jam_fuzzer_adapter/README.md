# JAM Fuzzer Adapter

This adapter bridges the gap between the JAM fuzzer (which expects a Unix socket) and your FastAPI HTTP API.

## Directory Structure

```
jam_fuzzer_adapter/
├── adapter.py     # Main adapter code
├── requirements.txt  # Python dependencies
└── README.md     # This file
```

## Prerequisites

- Python 3.7+
- Your JAM FastAPI server running and accessible

## Installation

1. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

You can configure the adapter using command-line arguments or environment variables:

| Parameter  | Env Variable | Default | Description |
|------------|--------------|---------|-------------|
| `--socket` | `SOCKET_PATH` | `/tmp/jam_target.sock` | Path to the Unix socket |
| `--api-url` | `API_URL` | `http://localhost:8000` | Base URL of your JAM API |
| `--debug` | `DEBUG` | `False` | Enable debug logging |

## Running the Adapter

### Basic Usage

```bash
python adapter.py --api-url http://localhost:8000
```

### With Environment Variables

```bash
export API_URL=http://localhost:8000
export SOCKET_PATH=/tmp/jam_fuzzer.sock
python adapter.py
```

### Running in the Background

```bash
nohup python adapter.py > adapter.log 2>&1 &
```

## Testing the Adapter

1. Start your FastAPI server if it's not already running.

2. In a new terminal, start the adapter:
   ```bash
   python adapter.py --debug
   ```

3. In another terminal, test the socket connection:
   ```bash
   # Install netcat if you don't have it
   # On macOS: brew install netcat
   # On Ubuntu: sudo apt-get install netcat
   
   # Test connection
   echo -n "test" | nc -U /tmp/jam_target.sock
   ```

4. Run the fuzzer against your adapter:
   ```bash
   # From the jam-conformance directory
   python fuzz-proto/minifuzz/minifuzz.py -d /path/to/trace/dir
   ```

## Implementation Notes

1. The adapter currently forwards raw binary data to your API. You'll need to implement the appropriate endpoint in your FastAPI server to handle these messages.

2. The adapter expects your API to have an endpoint at `/fuzzer/message` that accepts POST requests with the raw message data.

3. You may need to modify the `process_message` method in `adapter.py` to properly map between the fuzzer's message format and your API's expected format.

## Troubleshooting

- **Permission denied** when accessing the socket:
  ```bash
  chmod 666 /tmp/jam_target.sock
  ```
  
- **Address already in use**:
  ```bash
  rm -f /tmp/jam_target.sock
  ```
  
- Check the logs for detailed error messages:
  ```bash
  tail -f adapter.log
  ```

## Next Steps

1. Implement the `/fuzzer/message` endpoint in your FastAPI server
2. Add proper message serialization/deserialization
3. Add more detailed logging and error handling as needed
