"""This module provides a VirtuaDevice class that can be used with a WhadDeviceConnector
to interact with a device that doesn't support WHAD protocol. It allows to convert WHAD messages
to the corresponding specific API calls.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""
from .ubertooth import UbertoothDevice
from .rzusbstick import RZUSBStickDevice
from .apimote import APIMoteDevice
from .hci import HCIDevice
from .rfstorm import RFStormDevice
from .yard import YardStickOneDevice
from .pcap import PCAPDevice

__all__ = [
    "UbertoothDevice",
    "RZUSBStickDevice",
    "APIMoteDevice",
    "HCIDevice",
    "RFStormDevice",
    "YardStickOneDevice",
    "PCAPDevice"
]