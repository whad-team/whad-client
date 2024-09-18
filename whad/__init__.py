"""
WHAD - Wireless HAcking Devices

This is the main WHAD client module.
"""
import logging
# Import device related classes
from whad.device import UartDevice, VirtualDevice
from whad.exceptions import RequiredImplementation, UnsupportedDomain, \
    UnsupportedCapability, WhadDeviceNotReady, WhadDeviceNotFound, \
    WhadDeviceAccessDenied

# Force scapy to hide warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


__all__ = [
    'Domain',
    'Capability',
    'UartDevice',
    'VirtualDevice',
    'RequiredImplementation',
    'UnsupportedDomain',
    'UnsupportedCapability',
    'WhadDeviceNotReady',
    'WhadDeviceNotFound',
    'WhadDeviceAccessDenied'
]
