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
from .device import WhadDevice
from .connector import WhadDeviceConnector
from .bridge import Bridge

from whad.hw.unix import UnixSocketDevice

# Import derived classes
#from whad.device.uart import Uart
#from whad.device.tcp import TCPSocketDevice
#from whad.device.unix import UnixSocketDevice
#from whad.device.virtual import HCIDevice, APIMoteDevice, RFStormDevice, RZUSBStickDevice, \
#    UbertoothDevice, YardStickOneDevice, PCAPDevice

# Remove scapy deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

__all__ = [
    "Bridge",
    "Connector",
    "WhadDevice",
    "WhadDeviceInfo",
    "WhadDeviceConnector",
    "Interface",
    "Uart",
    "VirtualInterface",
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
