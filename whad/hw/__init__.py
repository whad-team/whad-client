"""WHAD hardware module

This module provides various classes to interact with WHAD-enabled hardware:

- :py:class:`whad.hw.Interface`
- :py:class:`whad.hw.VirtInterface`

This module replaces the previous `whad.device` module and its ambiguous class
names and features. The `whad.device` module is still available but will be
considered deprecated in a future release.
"""

# Load interface base classes
from .iface import Interface, VirtualInterface, IfaceEvt, Disconnected, MessageReceived, \
    WhadDevice, WhadVirtualDevice
from .connector import Connector, WhadDeviceConnector, Event, LockedConnector, WhadDeviceConnector
from .bridge import Bridge

# Load supported hardware interfaces
from .unix import UnixSocketDevice
from .pcap import PcapIface
from .uart import Uart
from .hci import HciIface

__all__ = [
    "Interface",
    "VirtualInterface",
    "Connector",
    "WhadDeviceConnector",
    "Bridge",
    "IfaceEvt",
    "Disconnected",
    "MessageReceived",
    "HciIface",
    "PcapIface",
    "UnixSocketDevice",
    "WhadDevice",
    "WhadVirtualDevice",
    "WhadDeviceConnector",
    "LockedConnector",
    "Event"
]