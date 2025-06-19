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

# Load supported hardware interfaces
from .unix import UnixSocket
from .uart import Uart
from .tcp import TcpSocket

# Load supported virtual interfaces
from .hci import Hci
from .pcap import Pcap
from .apimote import Apimote
from .rfstorm import RfStorm
from .rzusbstick import RzUsbStick
from .ubertooth import Ubertooth
from .yard import YardStickOne

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
    
    # Virtual devices
    "Hci",
    "Pcap",
    "Uart",
    "TcpSocket",
    "UnixSocket",
    "Apimote",
    "RfStorm",
    "RzUsbStick",
    "Ubertooth",
    "YardStickOne",
]