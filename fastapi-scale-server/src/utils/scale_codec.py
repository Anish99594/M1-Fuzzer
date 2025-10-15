from typing import Any, Dict, Union
import json
from enum import Enum
import struct
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScaleCodecError(Exception):
    """Custom exception for SCALE codec errors."""
    pass

def encode_scale(data: Union[Dict[str, Any], Enum]) -> bytes:
    """Encode data using SCALE codec.

    Args:
        data: The data to encode, which can be a dictionary or an Enum.

    Returns:
        The encoded bytes.

    Raises:
        ScaleCodecError: If encoding fails.
    """
    try:
        if isinstance(data, Enum):
            # Convert Enum to its value
            data = data.value
        
        # Serialize the data to JSON and then encode to bytes
        json_data = json.dumps(data)
        encoded_data = json_data.encode('utf-8')
        
        # Prepend the length of the encoded data
        length = struct.pack('<I', len(encoded_data))
        return length + encoded_data

    except Exception as e:
        logger.error(f"Encoding error: {e}")
        raise ScaleCodecError("Failed to encode data") from e

def decode_scale(encoded_data: bytes) -> Any:
    """Decode data from SCALE codec.

    Args:
        encoded_data: The encoded bytes to decode.

    Returns:
        The decoded data.

    Raises:
        ScaleCodecError: If decoding fails.
    """
    try:
        # Extract the length of the data
        length = struct.unpack('<I', encoded_data[:4])[0]
        json_data = encoded_data[4:4 + length].decode('utf-8')
        
        # Deserialize the JSON data
        return json.loads(json_data)

    except Exception as e:
        logger.error(f"Decoding error: {e}")
        raise ScaleCodecError("Failed to decode data") from e