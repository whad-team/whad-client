"""WHAD Protocol BLE jamming messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import JamAdvCmd
from whad.protocol.hub import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool
from whad.protocol.hub.ble import BleDomain

@pb_bind(BleDomain, 'jam_adv', 1)
class JamAdv(PbMessageWrapper):
    """BLE advertisement jamming message class
    """
    
    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.ble.jam_adv.CopyFrom(JamAdvCmd())

@pb_bind(BleDomain, 'jam_adv_chan', 1)
class JamAdvChan(PbMessageWrapper):
    """BLE advertisement channel jamming message class
    """
    channel = PbFieldInt('ble.jam_adv_chan.channel')


@pb_bind(BleDomain, 'jam_conn', 1)
class JamConn(PbMessageWrapper):
    """BLE advertisement channel jamming message class
    """
    access_address = PbFieldInt('ble.jam_conn.access_address')