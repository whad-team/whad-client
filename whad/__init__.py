from whad.protocol.device_pb2 import Domain, Capability

class WhadDomain(object):
    """
    Domain wrappers (mask protocol).
    """
    Phy = Domain.Phy
    BtClassic = Domain.BtClassic
    BtLE = Domain.BtLE
    Dot15d4 = Domain.Dot15d4
    SixLowPan = Domain.SixLowPan
    Esb = Domain.Esb
    LogitechUnifying = Domain.LogitechUnifying
    Mosart = Domain.Mosart
    ANT = Domain.ANT
    ANT_Plus = Domain.ANT_Plus
    ANT_FS = Domain.ANT_FS

class WhadCapability(object):
    """
    Capabilities wrappers (mask protocol).
    """
    Scan = Capability.Scan
    Sniff = Capability.Sniff
    Inject = Capability.Inject
    Jam = Capability.Jam
    Hijack = Capability.Hijack
    Hook = Capability.Hook
    SimulateRole = Capability.SimulateRole
    NoRawData = Capability.NoRawData

# Force scapy to hide warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Import device related classes
from whad.device import UartDevice, VirtualDevice
from whad.exceptions import RequiredImplementation, UnsupportedDomain, \
    UnsupportedCapability, WhadDeviceNotReady, WhadDeviceNotFound, \
    WhadDeviceAccessDenied

__all__ = [
    'UartDevice',
    'VirtualDevice',
]
