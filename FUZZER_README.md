# JAM Fuzzer Implementation

This document describes the JAM fuzzer implementation that has been created to test JAM protocol conformance.

## Overview

The fuzzer implementation consists of three main components:

1. **JAM Server** (`server/server.py`) - The main JAM protocol implementation that processes fuzzer messages
2. **Fuzzer Adapter** (`jam_fuzzer_adapter/adapter.py`) - A bridge between the fuzzer and the JAM server
3. **Minifuzz Tool** (`jam-conformance/fuzz-proto/minifuzz/minifuzz.py`) - The actual fuzzer that generates test cases

## Architecture

```
Minifuzz Tool → Unix Socket → Fuzzer Adapter → HTTP → JAM Server
```

The fuzzer communicates with the target implementation using a synchronous request-response protocol over Unix domain sockets, as specified in the JAM conformance testing protocol.

## Protocol Implementation

The fuzzer implements the complete JAM fuzzer protocol v1 as specified in `jam-conformance/fuzz-proto/fuzz-v1.asn`:

### Message Types Supported

| Message Type | Code | Description | Response |
|--------------|------|-------------|----------|
| PeerInfo | 0 | Handshake and versioning exchange | PeerInfo |
| Initialize | 1 | Initialize or reset target state | StateRoot |
| StateRoot | 2 | State root response | N/A |
| ImportBlock | 3 | Import block and return resulting state root | StateRoot |
| GetState | 4 | Retrieve posterior state associated to given header hash | State |
| State | 5 | State response | N/A |
| Error | 255 | Error message | N/A |

### Features Supported

- **Ancestry Feature**: Support for block ancestry up to 24 items (tiny spec)
- **Forking Feature**: Support for simple forking with maximum depth of 1
- **State Management**: Full state tracking and retrieval
- **Error Handling**: Proper error message encoding and handling

## Quick Start

### 1. Start the Fuzzer

```bash
# Make the startup script executable
chmod +x start_fuzzer.sh

# Start the fuzzer (starts both server and adapter)
./start_fuzzer.sh
```

### 2. Test with Minifuzz

```bash
# Test with no-forks examples
cd jam-conformance/fuzz-proto/minifuzz
python minifuzz.py -d ../examples/v1/no_forks --target-sock /tmp/jam_target.sock

# Test with forks examples
python minifuzz.py -d ../examples/v1/forks --target-sock /tmp/jam_target.sock

# Test with faulty examples (intentionally wrong state root)
python minifuzz.py -d ../examples/v1/faulty --target-sock /tmp/jam_target.sock
```

### 3. Run Tests

```bash
# Run the comprehensive test suite
python test_fuzzer.py
```

## Manual Testing

### 1. Start Components Separately

**Terminal 1 - Start the JAM Server:**
```bash
cd server
python -m uvicorn server:app --host 0.0.0.0 --port 8000 --log-level info
```

**Terminal 2 - Start the Fuzzer Adapter:**
```bash
cd jam_fuzzer_adapter
python adapter.py --socket /tmp/jam_target.sock --api-url http://localhost:8000
```

**Terminal 3 - Run Minifuzz:**
```bash
cd jam-conformance/fuzz-proto/minifuzz
python minifuzz.py -d ../examples/v1/no_forks --target-sock /tmp/jam_target.sock --verbose
```

### 2. Check Server Status

```bash
# Health check
curl http://localhost:8000/health

# Fuzzer status
curl http://localhost:8000/fuzzer/status
```

## Implementation Details

### Server Implementation

The JAM server (`server/server.py`) implements:

- **Message Decoding**: Uses `jam_types` library to decode JAM-encoded messages
- **Protocol Compliance**: Follows the exact message format specified in the protocol
- **State Management**: Maintains blockchain state and processes blocks
- **Error Handling**: Returns proper JAM error messages for all error conditions

### Adapter Implementation

The fuzzer adapter (`jam_fuzzer_adapter/adapter.py`) provides:

- **Unix Socket Server**: Listens on `/tmp/jam_target.sock` for fuzzer connections
- **HTTP Bridge**: Forwards messages to the JAM server via HTTP
- **Protocol Translation**: Handles the binary message format correctly
- **Error Propagation**: Properly forwards errors back to the fuzzer

### Message Flow

1. **Handshake**: Fuzzer sends `PeerInfo`, server responds with `PeerInfo`
2. **Initialization**: Fuzzer sends `Initialize`, server responds with `StateRoot`
3. **Block Processing**: Fuzzer sends `ImportBlock` messages, server responds with `StateRoot`
4. **State Retrieval**: On state root mismatch, fuzzer sends `GetState`, server responds with `State`

## Configuration

### Server Configuration

The server can be configured via environment variables or command line arguments:

- `--host`: Server host (default: 0.0.0.0)
- `--port`: Server port (default: 8000)
- `--log-level`: Logging level (default: info)

### Adapter Configuration

The adapter can be configured via command line arguments:

- `--socket`: Unix socket path (default: /tmp/jam_target.sock)
- `--api-url`: JAM server URL (default: http://localhost:8000)
- `--debug`: Enable debug logging

## Testing

### Test Cases

The implementation has been tested against:

1. **No-Forks Examples**: Basic block processing without forks
2. **Forks Examples**: Block processing with simple forking
3. **Faulty Examples**: Error handling and state retrieval

### Test Results

The fuzzer implementation should pass all test cases in the `examples/v1/` directories, demonstrating:

- Correct message encoding/decoding
- Proper state management
- Error handling compliance
- Protocol conformance

## Troubleshooting

### Common Issues

1. **Permission Denied on Socket**:
   ```bash
   chmod 666 /tmp/jam_target.sock
   ```

2. **Address Already in Use**:
   ```bash
   rm -f /tmp/jam_target.sock
   ```

3. **Server Not Responding**:
   - Check if server is running: `curl http://localhost:8000/health`
   - Check server logs for errors

4. **Adapter Connection Failed**:
   - Ensure server is running first
   - Check adapter logs for connection errors

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Server debug mode
cd server
python -m uvicorn server:app --host 0.0.0.0 --port 8000 --log-level debug

# Adapter debug mode
cd jam_fuzzer_adapter
python adapter.py --socket /tmp/jam_target.sock --api-url http://localhost:8000 --debug
```

## Protocol Compliance

The implementation is fully compliant with the JAM fuzzer protocol v1 specification:

- ✅ All message types implemented
- ✅ Proper message encoding/decoding
- ✅ Correct error handling
- ✅ State management
- ✅ Feature support (ancestry, forks)
- ✅ Protocol flow compliance

## Next Steps

1. **Performance Testing**: Test with larger datasets and longer fuzzing sessions
2. **Integration Testing**: Test with different JAM implementations
3. **Error Injection**: Test error handling with various failure modes
4. **Conformance Testing**: Submit for official JAM conformance testing

## References

- [JAM Conformance Testing Protocol](jam-conformance/fuzz-proto/README.md)
- [Fuzzer Protocol Specification](jam-conformance/fuzz-proto/fuzz-v1.asn)
- [Minifuzz Tool](jam-conformance/fuzz-proto/minifuzz/minifuzz.py)
- [Example Test Cases](jam-conformance/fuzz-proto/examples/v1/)
