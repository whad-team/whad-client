"""WHAD mock device

This module provides various classes and helpers to implement mock devices
for WHAD:

- WhadDevice
"""

from .base import MockDevice
from .replay import ReplayMock
from .connector import MockConnector

__all__ = [
    "MockConnector",
    "MockDevice",
    "ReplayMock",
]
