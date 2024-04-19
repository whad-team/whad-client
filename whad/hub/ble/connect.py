"""WHAD Protocol BLE jamming messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from whad.hub.ble import BleDomain

@pb_bind(BleDomain, 'connect', 1)
class ConnectTo(PbMessageWrapper):
    """BLE connect message class
    """
    bd_address = PbFieldBytes('ble.connect.bd_address')
    addr_type = PbFieldInt('ble.connect.addr_type')
    access_address = PbFieldInt('ble.connect.access_address')
    channel_map = PbFieldBytes('ble.connect.channel_map')
    hop_interval = PbFieldInt('ble.connect.hop_interval')
    hop_increment = PbFieldInt('ble.connect.hop_increment')
    crc_init = PbFieldInt('ble.connect.crc_init')

@pb_bind(BleDomain, 'disconnect', 1)
class Disconnect(PbMessageWrapper):
    """BLE connect message class
    """
    conn_handle = PbFieldInt('ble.disconnect.conn_handle')

@pb_bind(BleDomain, 'synchronized', 1)
class Synchronized(PbMessageWrapper):
    """BLE synchronized notification message class
    """
    access_address = PbFieldInt('ble.synchronized.access_address')
    crc_init = PbFieldInt('ble.synchronized.crc_init')
    hop_interval = PbFieldInt('ble.synchronized.hop_interval')
    hop_increment = PbFieldInt('ble.synchronized.hop_increment')
    channel_map = PbFieldBytes('ble.synchronized.channel_map')


@pb_bind(BleDomain, 'connected', 1)
class Connected(PbMessageWrapper):
    """BLE connected message class
    """
    initiator = PbFieldBytes('ble.connected.initiator')
    advertiser = PbFieldBytes('ble.connected.advertiser')
    access_address = PbFieldInt('ble.connected.access_address')
    conn_handle = PbFieldInt('ble.connected.conn_handle')
    adv_addr_type = PbFieldInt('ble.connected.adv_addr_type')
    init_addr_type = PbFieldInt('ble.connected.init_addr_type')

@pb_bind(BleDomain, 'disconnected', 1)
class Disconnected(PbMessageWrapper):
    """BLE connected message class
    """
    reason = PbFieldInt('ble.disconnected.reason')
    conn_handle = PbFieldBytes('ble.disconnected.conn_handle')

@pb_bind(BleDomain, 'desynchronized', 1)
class Desynchronized(PbMessageWrapper):
    """BLE connect message class
    """
    access_address = PbFieldInt('ble.desynchronized.access_address')