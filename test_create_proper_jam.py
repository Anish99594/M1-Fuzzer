#!/usr/bin/env python3

import sys
sys.path.append('/Users/anishgajbhare/Downloads/JAM-FINAL-FUZZER/Jam_implementation_full/venv/lib/python3.13/site-packages')

from jam_types.fuzzer import FuzzerMessage, PeerInfo, PeerVersion
from jam_types import ScaleBytes
from jam_types.types import String

# Create a proper PeerInfo message
try:
    # Create version objects
    jam_version = PeerVersion()
    jam_version.major = 0
    jam_version.minor = 7
    jam_version.patch = 0

    app_version = PeerVersion()
    app_version.major = 0
    app_version.minor = 1
    app_version.patch = 25

    # Create PeerInfo
    peer_info = PeerInfo()
    peer_info.fuzz_version = 1
    peer_info.fuzz_features = 2
    peer_info.jam_version = jam_version
    peer_info.app_version = app_version
    peer_info.app_name = String(ScaleBytes("fuzzer".encode()))

    # Encode the PeerInfo
    peer_info_bytes = peer_info.encode()
    print(f"Encoded PeerInfo: {peer_info_bytes.hex()}")
    print(f"Length: {len(peer_info_bytes)}")

    # Create a FuzzerMessage with the PeerInfo
    fuzzer_msg = FuzzerMessage()
    fuzzer_msg.value = peer_info
    fuzzer_msg.index = 0  # PEER_INFO

    # Encode the FuzzerMessage
    fuzzer_bytes = fuzzer_msg.encode()
    print(f"Encoded FuzzerMessage: {fuzzer_bytes.hex()}")
    print(f"Length: {len(fuzzer_bytes)}")

    # Try to decode it back
    scale_bytes = ScaleBytes(fuzzer_bytes)
    decoded_msg = FuzzerMessage(data=scale_bytes)
    decoded = decoded_msg.decode()
    print(f"Decoded: {decoded}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
