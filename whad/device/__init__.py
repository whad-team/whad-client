"""WHAD hardware module

This module provides various classes to interact with WHAD-enabled hardware:

- :py:class:`whad.hw.Interface`
- :py:class:`whad.hw.VirtInterface`

This module replaces the previous `whad.device` module and its ambiguous class
names and features. The `whad.device` module is still available but will be
considered deprecated in a future release.
"""

# Load interface base classes
from .device import Device, VirtualDevice, DeviceEvt, Disconnected, MessageReceived, \
    WhadDevice, WhadVirtualDevice
from .connector import Connector, Event, LockedConnector, WhadDeviceConnector
from .bridge import Bridge

# Base device classes
from .uart import Uart
from .tcp import TcpSocket
from .unix import UnixSocket

__all__ = [
    # Base classes
    "Device",
    "VirtualDevice",
    "Connector",
    "WhadDeviceConnector",
    "Bridge",
    "DeviceEvt",
    "Disconnected",
    "MessageReceived",
    "Event",

    # Kept for compatibility
    "WhadDevice",
    "WhadVirtualDevice",
    "WhadDeviceConnector",
    "LockedConnector",

    # Base devices
    "TcpSocket",
    "Uart",
    "UnixSocket",
]
