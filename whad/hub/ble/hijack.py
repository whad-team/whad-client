"""WHAD Protocol BLE hijacking messages abstraction layer.
"""

from whad.hub.message import pb_bind, PbFieldInt, PbMessageWrapper, PbFieldBool
from whad.hub.ble import BleDomain

@pb_bind(BleDomain, "hijack_master", 1)
class HijackMaster(PbMessageWrapper):
    """BLE hijack master message class
    """
    access_address = PbFieldInt("ble.hijack_master.access_address")

@pb_bind(BleDomain, "hijack_slave", 1)
class HijackSlave(PbMessageWrapper):
    """BLE hijack slave message class
    """
    access_address = PbFieldInt("ble.hijack_slave.access_address")

@pb_bind(BleDomain, "hijack_both", 1)
class HijackBoth(PbMessageWrapper):
    """BLE hijack both message class
    """
    access_address = PbFieldInt("ble.hijack_both.access_address")

@pb_bind(BleDomain, "hijacked", 1)
class Hijacked(PbMessageWrapper):
    """BLE hijack both message class.
    """
    success = PbFieldBool("ble.hijacked.success")
    access_address = PbFieldInt("ble.hijacked.access_address")
