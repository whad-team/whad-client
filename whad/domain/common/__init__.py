from . import metadata
from dataclasses import dataclass


@dataclass
class RegisterMask:
    mask : int = 0
    offset : int = 0
