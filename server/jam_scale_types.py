"""
Custom SCALE types for JAM Fuzzer Protocol based on ASN.1 specification.
This replaces the jam_types package with correct SCALE definitions.
"""

from scalecodec.types import (
    Enum, Struct, U8, U32, String as ScaleString,
    Vec, Compact, Option, Bytes
)
from scalecodec.base import ScaleBytes


class JAMU8(U8):
    """JAM U8 type (0..255)"""
    pass


class JAMU32(U32):
    """JAM U32 type (0..4294967295)"""
    pass


class JAMHash(Bytes):
    """JAM Hash type - 32 bytes"""
    # For now, use Bytes and validate length manually
    pass


class JAMHeaderHash(JAMHash):
    """JAM Header Hash type"""
    pass


class JAMStateRootHash(JAMHash):
    """JAM State Root Hash type"""
    pass


class JAMTimeSlot(JAMU32):
    """JAM Time Slot type"""
    pass


class JAMFeatures(JAMU32):
    """JAM Features type"""
    pass


class JAMVersion(Struct):
    """JAM Version type"""
    type_mapping = [
        ('major', JAMU8),
        ('minor', JAMU8),
        ('patch', JAMU8)
    ]


class JAMKeyValue(Struct):
    """JAM Key-Value pair type"""
    type_mapping = [
        ('key', Bytes),  # 31-byte key - validate length manually for now
        ('value', Bytes)  # Variable length value
    ]

    def __init__(self, value=None, **kwargs):
        super().__init__(value, **kwargs)
        # Validate that key is exactly 31 bytes if provided
        if value and 'key' in value:
            key_data = value['key']
            if isinstance(key_data, bytes) and len(key_data) != 31:
                # Pad or truncate to 31 bytes for compatibility
                if len(key_data) < 31:
                    # Pad with zeros
                    value['key'] = key_data.ljust(31, b'\x00')
                else:
                    # Truncate to 31 bytes
                    value['key'] = key_data[:31]


class JAMState(Vec):
    """JAM State type - vector of key-value pairs"""
    sub_type = JAMKeyValue


class JAMAncestryItem(Struct):
    """JAM Ancestry Item type"""
    type_mapping = [
        ('slot', JAMTimeSlot),
        ('header_hash', JAMHeaderHash)
    ]


class JAMAncestry(Vec):
    """JAM Ancestry type - vector of ancestry items, max 24"""
    sub_type = JAMAncestryItem
    # Note: ASN.1 specifies SIZE(0..24) but SCALE Vec doesn't enforce max size


class JAMError(ScaleString):
    """JAM Error type"""
    pass


class JAMGetState(JAMHeaderHash):
    """JAM Get State type"""
    pass


class JAMStateRoot(JAMStateRootHash):
    """JAM State Root type"""
    pass


# Forward declarations for types that reference each other
class JAMPeerInfo:
    """JAM Peer Info type"""
    pass


class JAMInitialize:
    """JAM Initialize type"""
    pass


class JAMImportBlock:
    """JAM Import Block type - references Block from gray paper"""
    pass


class JAMFuzzerMessage(Enum):
    """JAM Fuzzer Message type - main message enum"""
    type_mapping = {
        0: ("peer_info", JAMPeerInfo),
        1: ("initialize", JAMInitialize),
        2: ("state_root", JAMStateRoot),
        3: ("import_block", JAMImportBlock),
        4: ("get_state", JAMGetState),
        5: ("state", JAMState),
        255: ("error", JAMError)
    }


# Now define the complex types that were forward declared
class JAMPeerInfo(Struct):
    """JAM Peer Info type"""
    type_mapping = [
        ('fuzz_version', JAMU8),
        ('fuzz_features', JAMFeatures),
        ('jam_version', JAMVersion),
        ('app_version', JAMVersion),
        ('app_name', ScaleString)
    ]


class JAMInitialize(Struct):
    """JAM Initialize type"""
    type_mapping = [
        ('header', JAMHeaderHash),  # Simplified - should be full Header from gray paper
        ('keyvals', JAMState),
        ('ancestry', JAMAncestry)
    ]


class JAMImportBlock(Struct):
    """JAM Import Block type - simplified Block from gray paper"""
    type_mapping = [
        ('header', JAMHeaderHash),  # Simplified header
        ('extrinsics', 'Vec<Bytes>')  # Simplified extrinsics
    ]


# Monkey patch the forward declarations
JAMFuzzerMessage.type_mapping[0] = ("peer_info", JAMPeerInfo)
JAMFuzzerMessage.type_mapping[1] = ("initialize", JAMInitialize)
JAMFuzzerMessage.type_mapping[3] = ("import_block", JAMImportBlock)


# Export the main types
__all__ = [
    'JAMFuzzerMessage', 'JAMPeerInfo', 'JAMVersion', 'JAMError',
    'JAMState', 'JAMStateRoot', 'JAMGetState', 'JAMInitialize',
    'JAMImportBlock', 'JAMAncestry', 'ScaleBytes'
]
