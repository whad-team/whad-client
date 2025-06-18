"""
WHAD Device module

This module provides a set of classes used to interact with devices
running compatible firmwares, as well as the default connector class used
to handle messages coming from or sent to the device.
"""
# Logging
import warnings

from cryptography.utils import CryptographyDeprecationWarning

# Whad device-related classes
from .info import WhadDeviceInfo
from .device import WhadDevice, WhadVirtualDevice
from .connector import WhadDeviceConnector
from .bridge import Bridge

# Import virtual devices
from .virtual import PCAPDevice, HCIDevice, UARTDevice, \
    TCPSocketDevice, UnixSocketDevice, APIMoteDevice, RFStormDevice, \
    RZUSBStickDevice, UbertoothDevice, YardStickOneDevice


# Remove scapy deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

__all__ = [
    "WhadDeviceInfo",
    "WhadDevice",
    "WhadVirtualDevice",
    "WhadDeviceConnector",
    "Bridge",
    "HCIDevice",
    "UartDevice",
    "TCPSocketDevice",
    "UnixSocketDevice",
    "HCIDevice",
    "APIMoteDevice",
    "RFStormDevice",
    "RZUSBStickDevice",
    "UbertoothDevice",
    "YardStickOneDevice",
    "PCAPDevice"
]
