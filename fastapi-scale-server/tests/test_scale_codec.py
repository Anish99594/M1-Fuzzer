import pytest
from src.utils.scale_codec import encode, decode
from src.models.scale_enum import ScaleEnum
from src.types.custom_enum import CustomEnum

def test_encode_valid_data():
    data = {
        "field1": "value1",
        "field2": 123,
        "enum_field": ScaleEnum.VALUE_ONE
    }
    encoded_data = encode(data)
    assert isinstance(encoded_data, bytes)

def test_decode_valid_data():
    encoded_data = b'\x01\x00\x00\x00value1\x00\x00\x00\x7b\x00\x01'
    decoded_data = decode(encoded_data)
    assert decoded_data["field1"] == "value1"
    assert decoded_data["field2"] == 123
    assert decoded_data["enum_field"] == ScaleEnum.VALUE_ONE

def test_encode_invalid_data():
    with pytest.raises(ValueError):
        encode(None)

def test_decode_invalid_data():
    with pytest.raises(ValueError):
        decode(b'invalid_data')

def test_enum_serialization():
    enum_value = CustomEnum.VALUE_A
    encoded_enum = encode({"enum_field": enum_value})
    decoded_enum = decode(encoded_enum)
    assert decoded_enum["enum_field"] == enum_value

def test_edge_case_empty_data():
    encoded_data = encode({})
    decoded_data = decode(encoded_data)
    assert decoded_data == {}

def test_edge_case_large_numbers():
    data = {
        "large_number": 2**64 - 1
    }
    encoded_data = encode(data)
    decoded_data = decode(encoded_data)
    assert decoded_data["large_number"] == data["large_number"]