#!/usr/bin/env python3
"""
Test script for the JAM fuzzer implementation.
This script tests the fuzzer adapter and server integration.
"""

import asyncio
import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent
sys.path.append(str(project_root))
sys.path.append(str(project_root / "server"))

def test_server_startup():
    """Test if the server can start up properly."""
    print("Testing server startup...")
    try:
        # Start the server in the background
        server_process = subprocess.Popen([
            sys.executable, "-m", "uvicorn", 
            "server.server:app", 
            "--host", "0.0.0.0", 
            "--port", "8000"
        ], cwd=project_root)
        
        # Wait a bit for the server to start
        time.sleep(3)
        
        # Check if the server is running
        import requests
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                print("✓ Server started successfully")
                return server_process
            else:
                print(f"✗ Server health check failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"✗ Server health check failed: {e}")
            return None
            
    except Exception as e:
        print(f"✗ Failed to start server: {e}")
        return None

def test_fuzzer_adapter():
    """Test the fuzzer adapter."""
    print("Testing fuzzer adapter...")
    try:
        # Start the adapter in the background
        adapter_process = subprocess.Popen([
            sys.executable, "adapter.py",
            "--socket", "/tmp/jam_target.sock",
            "--api-url", "http://localhost:8000"
        ], cwd=project_root / "jam_fuzzer_adapter")
        
        # Wait for the adapter to start
        time.sleep(2)
        
        # Check if the socket exists
        if Path("/tmp/jam_target.sock").exists():
            print("✓ Fuzzer adapter started successfully")
            return adapter_process
        else:
            print("✗ Fuzzer adapter socket not created")
            return None
            
    except Exception as e:
        print(f"✗ Failed to start fuzzer adapter: {e}")
        return None

def test_minifuzz():
    """Test the minifuzz tool against our implementation."""
    print("Testing minifuzz integration...")
    try:
        # Run minifuzz with a simple test
        minifuzz_path = project_root / "jam-conformance" / "fuzz-proto" / "minifuzz" / "minifuzz.py"
        examples_path = project_root / "jam-conformance" / "fuzz-proto" / "examples" / "v1" / "no_forks"
        
        if not minifuzz_path.exists():
            print("✗ Minifuzz tool not found")
            return False
            
        if not examples_path.exists():
            print("✗ Minifuzz examples not found")
            return False
        
        # Run minifuzz with limited iterations
        result = subprocess.run([
            sys.executable, str(minifuzz_path),
            "-d", str(examples_path),
            "--target-sock", "/tmp/jam_target.sock",
            "--stop-after", "5",
            "--verbose"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✓ Minifuzz test passed")
            return True
        else:
            print(f"✗ Minifuzz test failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Minifuzz test timed out")
        return False
    except Exception as e:
        print(f"✗ Minifuzz test failed: {e}")
        return False

def cleanup_processes(processes):
    """Clean up background processes."""
    for process in processes:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

def main():
    """Main test function."""
    print("JAM Fuzzer Implementation Test")
    print("=" * 40)
    
    processes = []
    
    try:
        # Test 1: Server startup
        server_process = test_server_startup()
        if not server_process:
            print("Failed to start server, aborting tests")
            return 1
        processes.append(server_process)
        
        # Test 2: Fuzzer adapter
        adapter_process = test_fuzzer_adapter()
        if not adapter_process:
            print("Failed to start fuzzer adapter, aborting tests")
            return 1
        processes.append(adapter_process)
        
        # Test 3: Minifuzz integration
        if test_minifuzz():
            print("\n✓ All tests passed!")
            return 0
        else:
            print("\n✗ Some tests failed")
            return 1
            
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        return 1
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        return 1
    finally:
        # Clean up
        cleanup_processes(processes)
        print("Cleanup completed")

if __name__ == "__main__":
    sys.exit(main())
