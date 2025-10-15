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
                    break
                    
                msg_length = struct.unpack('<I', header)[0]
                
                # Read the actual message
                data = await reader.read(msg_length)
                if not data:
                    break
                
                logger.debug(f"Received {len(data)} bytes from fuzzer")
                
                try:
                    # Process the message and get response
                    response_data = await self.process_message(data)
                    
                    # Send response length (4 bytes, little endian)
                    writer.write(struct.pack('<I', len(response_data)))
                    # Send response data
                    writer.write(response_data)
                    await writer.drain()
                    
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
