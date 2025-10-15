#!/usr/bin/env python3

import sys
sys.path.append('/Users/anishgajbhare/Downloads/JAM-FINAL-FUZZER/Jam_implementation_full/venv/lib/python3.13/site-packages')

from jam_types.fuzzer import FuzzerMessage, PeerInfo, PeerVersion
from jam_types import ScaleBytes
from jam_types.types import String

# Test with the actual binary data from the examples
test_data = bytes([0, 1, 2, 0, 0, 0, 0, 7, 0, 0, 1, 25, 6, 102, 117, 122, 122, 101, 114])
print(f"Test data: {test_data.hex()}")
print(f"Length: {len(test_data)}")

try:
    # Try to decode the raw data
    scale_bytes = ScaleBytes(test_data)
    fuzzer_msg = FuzzerMessage(data=scale_bytes)
    decoded = fuzzer_msg.decode()
    print(f"Decoded: {decoded}")
    
    # Check the message type
    print(f"Message type: {fuzzer_msg.index}")
    print(f"Message value: {fuzzer_msg.value}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()