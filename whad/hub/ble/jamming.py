"""WHAD Protocol BLE jamming messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import JamAdvCmd
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from whad.hub.ble import BleDomain, BlePhy

@pb_bind(BleDomain, "jam_adv", 1)
class JamAdv(PbMessageWrapper):
    """BLE advertisement jamming message class
    """

    def __init__(self, version: int, message: Message = None):
        super().__init__(version, message=message)
        self.message.ble.jam_adv.CopyFrom(JamAdvCmd())

@pb_bind(BleDomain, "jam_adv_chan", 1)
class JamAdvChan(PbMessageWrapper):
    """BLE advertisement channel jamming message class
    """
    channel = PbFieldInt("ble.jam_adv_chan.channel")


@pb_bind(BleDomain, "jam_conn", 1)
class JamConn(PbMessageWrapper):
    """BLE advertisement channel jamming message class
    """
    access_address = PbFieldInt("ble.jam_conn.access_address")

    # Introduced in version 3, set by default to LE_1M for previous versions.
    phy = PbFieldInt('ble.jam_conn.phy', min_version=3, default=BlePhy.LE_1M)

@pb_bind(BleDomain, "reactive_jam", 1)
class ReactiveJam(PbMessageWrapper):
    """BLE reactive jamming message class
    """
    channel = PbFieldInt("ble.reactive_jam.channel")
    pattern = PbFieldBytes("ble.reactive_jam.pattern")
    position = PbFieldInt("ble.reactive_jam.position")
