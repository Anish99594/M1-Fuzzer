from enum import Enum

class CustomEnum(Enum):
    OPTION_A = "option_a"
    OPTION_B = "option_b"
    OPTION_C = "option_c"

    @classmethod
    def from_string(cls, value: str):
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"{value} is not a valid {cls.__name__}")

    @classmethod
    def list_options(cls):
        return [option.value for option in cls]