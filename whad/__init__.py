
from whad.protocol.device_pb2 import Domain, Capability
from whad.device.uart import UartDevice

class WhadDomain(object):
    """
    Domain wrappers (mask protocol).
    """
    Generic = Domain.Generic
    BtClassic = Domain.BtClassic
    BtLE = Domain.BtLE
    Zigbee = Domain.Zigbee
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
    MasterRole = Capability.MasterRole
    SlaveRole = Capability.SlaveRole
    NoRawData = Capability.NoRawData
    EndDeviceRole = Capability.EndDeviceRole
    RouterRole = Capability.RouterRole
    CoordinatorRole = Capability.CoordinatorRole
