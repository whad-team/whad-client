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
from whad.device.info import WhadDeviceInfo
from whad.device.connector import WhadDeviceConnector
from whad.device.bridge import Bridge
from whad.device.device import WhadDevice, VirtualDevice

# Import derived classes
from whad.device.uart import UartDevice
from whad.device.tcp import TCPSocketDevice
from whad.device.unix import UnixSocketDevice
from whad.device.virtual import HCIDevice, APIMoteDevice, RFStormDevice, RZUSBStickDevice, \
    UbertoothDevice, YardStickOneDevice, ANTStickDevice

# Remove scapy deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

__all__ = [
    "Bridge",
    "WhadDeviceConnector",
    "WhadDeviceInfo",
    "WhadDevice",
    "UartDevice",
    "VirtualDevice",
    "TCPSocketDevice",
    "UnixSocketDevice",
    "HCIDevice",
    "APIMoteDevice",
    "RFStormDevice",
    "RZUSBStickDevice",
    "UbertoothDevice",
    "ANTStickDevice",
    "YardStickOneDevice"
]
