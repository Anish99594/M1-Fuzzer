from enum import Enum

class ScaleType(Enum):
    INTEGER = 1
    FLOAT = 2
    STRING = 3
    BOOLEAN = 4
    BYTE_ARRAY = 5

    def __str__(self):
        return self.name

    @classmethod
    def from_value(cls, value):
        if isinstance(value, int):
            return cls.INTEGER
        elif isinstance(value, float):
            return cls.FLOAT
        elif isinstance(value, str):
            return cls.STRING
        elif isinstance(value, bool):
            return cls.BOOLEAN
        elif isinstance(value, bytes):
            return cls.BYTE_ARRAY
        else:
            raise ValueError(f"Unsupported type: {type(value)}")

    @classmethod
    def to_value(cls, scale_type):
        if scale_type == cls.INTEGER:
            return 0
        elif scale_type == cls.FLOAT:
            return 0.0
        elif scale_type == cls.STRING:
            return ""
        elif scale_type == cls.BOOLEAN:
            return False
        elif scale_type == cls.BYTE_ARRAY:
            return b""
        else:
            raise ValueError(f"Unsupported ScaleType: {scale_type}")