#!/usr/bin/env python3

import sys
sys.path.append('/Users/anishgajbhare/Downloads/JAM-FINAL-FUZZER/Jam_implementation_full/venv/lib/python3.13/site-packages')

from jam_types.fuzzer import FuzzerMessage
from jam_types import ScaleBytes

# Test with a simple peer info message
test_data = bytes([0, 1, 2, 0, 0, 0, 0, 7, 0, 0, 1, 25, 6, 102, 117, 122, 122, 101, 114])
print(f"Test data: {test_data.hex()}")
print(f"Length: {len(test_data)}")

try:
    # Try to decode as a simple message
    scale_bytes = ScaleBytes(test_data)
    print(f"ScaleBytes created: {scale_bytes}")
    
    # Try to create a FuzzerMessage
    fuzzer_msg = FuzzerMessage(data=scale_bytes)
    print(f"FuzzerMessage created: {fuzzer_msg}")
    
    # Try to decode
    decoded = fuzzer_msg.decode()
    print(f"Decoded: {decoded}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
