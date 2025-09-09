"""
WHAD - Wireless HAcking Devices

This is the main WHAD client module.
"""
import logging

from whad.device import WhadDevice
from whad.exceptions import RequiredImplementation, UnsupportedDomain, \
    UnsupportedCapability, WhadDeviceNotReady, WhadDeviceNotFound, \
    WhadDeviceAccessDenied

# Force scapy to hide warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


__all__ = [
    'UartDevice',
    'VirtualDevice',
    'WhadDevice',
    'RequiredImplementation',
    'UnsupportedDomain',
    'UnsupportedCapability',
    'WhadDeviceNotReady',
    'WhadDeviceNotFound',
    'WhadDeviceAccessDenied'
]
