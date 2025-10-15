#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import socket
import struct
from typing import Dict, Any, Optional
import aiohttp
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("jam-fuzzer-adapter")

class FuzzerAdapter:
    def __init__(
        self,
        socket_path: str = "/tmp/jam_target.sock",
        api_url: str = "http://localhost:8000",
    ):
        self.socket_path = socket_path
        self.api_url = api_url.rstrip('/')
        self.server = None
        self.loop = asyncio.get_event_loop()
        
        # Clean up socket file if it exists
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

    async def start(self):
        """Start the adapter server."""
        server = await asyncio.start_unix_server(
            self.handle_client,
            path=self.socket_path,
        )
        
        # Set permissions to allow other users to connect
        os.chmod(self.socket_path, 0o666)
        
        self.server = server
        addr = server.sockets[0].getsockname()
        logger.info(f"Adapter listening on {addr}")
        
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        """Handle a client connection."""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {client_addr}")
        
        try:
            while True:
                # Read message length (4 bytes, little endian)
                header = await reader.read(4)
                if not header:
                    logger.info("Client disconnected - no more data")
                    break
                    
                msg_length = struct.unpack('<I', header)[0]
                print(f"[ADAPTER] Reading fuzzer file of length {msg_length} from socket", flush=True)
                
                # Read the actual message - read exactly msg_length bytes
                data = b''
                while len(data) < msg_length:
                    chunk = await reader.read(msg_length - len(data))
                    if not chunk:
                        logger.info("Client disconnected - no data received")
                        break
                    data += chunk
                
                if len(data) < msg_length:
                    logger.warning(f"Incomplete data received: {len(data)} bytes, expected {msg_length}")
                    break
                
                print(f"[ADAPTER] Received {len(data)} bytes from fuzzer, first byte: {data[0] if data else 'None'}", flush=True)
                
                # Use the entire fuzzer file data as the JAM message
                # The fuzzer file contains the complete JAM message
                first_jam_message = data
                print(f"[ADAPTER] Processing JAM message: {len(first_jam_message)} bytes, first byte: {first_jam_message[0] if first_jam_message else 'None'}", flush=True)
                
                try:
                    # Process the first JAM message and get response
                    response_data = await self.process_message(first_jam_message)
                    
                    # Send response length (4 bytes, little endian)
                    writer.write(struct.pack('<I', len(response_data)))
                    # Send response data
                    writer.write(response_data)
                    await writer.drain()
                    print(f"[ADAPTER] Sent response of {len(response_data)} bytes", flush=True)
                    
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    # Send error response
                    error_msg = json.dumps({"error": str(e)}).encode()
                    writer.write(struct.pack('<I', len(error_msg)))
                    writer.write(error_msg)
                    await writer.drain()
                    break
                    
        except ConnectionResetError:
            logger.info("Client disconnected")
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"Connection closed for {client_addr}")
    
    def extract_first_jam_message(self, data: bytes) -> bytes:
        """Extract the first JAM message from a fuzzer file that may contain multiple concatenated messages."""
        if len(data) == 0:
            return data
            
        # For small messages, use as-is
        if len(data) < 1000:
            return data
        
        # For large messages, we need to parse the JAM message structure
        # The fuzzer file contains multiple JAM messages concatenated together
        # Each JAM message has a 4-byte length prefix followed by the message data
        
        # Look for the first complete JAM message by parsing the length prefix
        if len(data) >= 4:
            # Read the first 4 bytes as the length prefix
            length_prefix = struct.unpack('<I', data[:4])[0]
            
            # The first JAM message should be: [4-byte length][message_type][message_data]
            # So the total length is: 4 + length_prefix
            first_message_length = 4 + length_prefix
            
            if first_message_length <= len(data):
                # Extract the first complete JAM message (without the 4-byte length prefix)
                first_message = data[4:first_message_length]
                print(f"[ADAPTER] Extracted first JAM message: {len(first_message)} bytes from {len(data)} byte file", flush=True)
                return first_message
        
        # Fallback: if we can't parse properly, just use the first 1000 bytes
        print(f"[ADAPTER] Fallback: using first 1000 bytes from {len(data)} byte file", flush=True)
        return data[:1000]
    # ...existing code...
    async def process_message(self, data: bytes) -> bytes:
        """Process a message from the fuzzer and return the response.
        
        The fuzzer sends raw JAM-encoded messages that need to be forwarded
        to the server's /fuzzer/message endpoint.
        """
        try:
            from io import BytesIO

            async with aiohttp.ClientSession() as session:
                def make_form(b: bytes, name: str = "fuzzer_message.bin"):
                    fobj = BytesIO(b)
                    form = aiohttp.FormData()
                    form.add_field('file', fobj, filename=name, content_type='application/octet-stream')
                    return form

                # Send raw data to the server
                print(f"[ADAPTER] Sending {len(data)} bytes, first byte: {data[0]}, first 20 bytes: {data[:20].hex()}", flush=True)
                async with session.post(f"{self.api_url}/fuzzer/message", data=make_form(data)) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        logger.error(f"Server returned error {resp.status}: {error_text}")
                        # Return a proper JAM error message
                        error_msg = f"Server error: {resp.status} - {error_text}"
                        error_bytes = bytes([255]) + error_msg.encode()
                        return error_bytes
                    
                    # Return the binary response directly
                    return await resp.read()

        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            # Return a proper JAM error message
            error_msg = f"Processing error: {str(e)}"
            error_bytes = bytes([255]) + error_msg.encode()
            return error_bytes
# ...existing code...

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='JAM Fuzzer Adapter')
    parser.add_argument('--socket', default='/tmp/jam_target.sock',
                       help='Path to the Unix socket (default: /tmp/jam_target.sock)')
    parser.add_argument('--api-url', default='http://localhost:8000',
                       help='Base URL of the JAM API (default: http://localhost:8000)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    adapter = FuzzerAdapter(
        socket_path=args.socket,
        api_url=args.api_url
    )
    
    logger.info(f"Starting JAM Fuzzer Adapter")
    logger.info(f"Socket: {args.socket}")
    logger.info(f"API URL: {args.api_url}")
    
    try:
        asyncio.run(adapter.start())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    finally:
        # Clean up
        if os.path.exists(args.socket):
            os.unlink(args.socket)
    
    return 0

if __name__ == "__main__":
    exit(main())
