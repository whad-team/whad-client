"""WHAD Protocol BLE jamming messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from whad.hub.ble import BleDomain
from whad.hub.events import ConnectionEvt, DisconnectionEvt, DesyncEvt, SyncEvt

@pb_bind(BleDomain, 'connect', 1)
class ConnectTo(PbMessageWrapper):
    """BLE connect message class
    """
    bd_address = PbFieldBytes('ble.connect.bd_address')
    addr_type = PbFieldInt('ble.connect.addr_type')
    access_address = PbFieldInt('ble.connect.access_address', optional=True)
    channel_map = PbFieldBytes('ble.connect.channel_map', optional=True)
    hop_interval = PbFieldInt('ble.connect.hop_interval', optional=True)
    hop_increment = PbFieldInt('ble.connect.hop_increment', optional=True)
    crc_init = PbFieldInt('ble.connect.crc_init', optional=True)

@pb_bind(BleDomain, 'disconnect', 1)
class Disconnect(PbMessageWrapper):
    """BLE connect message class
    """
    conn_handle = PbFieldInt('ble.disconnect.conn_handle')

@pb_bind(BleDomain, 'synchronized', 1)
class Synchronized(PbMessageWrapper):
    """BLE synchronized notification message class.

    This class implements WHAD's AbstractEvent interface and can be converted
    into a `SyncEvt` object.
    """
    access_address = PbFieldInt('ble.synchronized.access_address')
    crc_init = PbFieldInt('ble.synchronized.crc_init')
    hop_interval = PbFieldInt('ble.synchronized.hop_interval')
    hop_increment = PbFieldInt('ble.synchronized.hop_increment')
    channel_map = PbFieldBytes('ble.synchronized.channel_map')

    def to_event(self):
        """Convert this message to an event.
        """
        return SyncEvt(
            access_address=self.access_address,
            crc_init=self.crc_init,
            hop_interval=self.hop_interval,
            hop_increment=self.hop_increment,
            channel_map=self.channel_map
        )
    
    @staticmethod
    def from_event(event):
        return Synchronized(
            access_address=event.access_address,
            crc_init=event.crc_init,
            hop_interval=event.hop_interval,
            hop_increment=event.hop_increment,
            channel_map=event.channel_map
        )

@pb_bind(BleDomain, 'connected', 1)
class Connected(PbMessageWrapper):
    """BLE connected message class.

    This class implements WHAD's AbstractEvent interface and can be converted
    into a `ConnectionEvt` object.
    """
    initiator = PbFieldBytes('ble.connected.initiator')
    advertiser = PbFieldBytes('ble.connected.advertiser')
    access_address = PbFieldInt('ble.connected.access_address')
    conn_handle = PbFieldInt('ble.connected.conn_handle')
    adv_addr_type = PbFieldInt('ble.connected.adv_addr_type')
    init_addr_type = PbFieldInt('ble.connected.init_addr_type')

    def to_event(self):
        """Convert this message to an event.
        """
        return ConnectionEvt(
            initiator=self.initiator,
            advertiser=self.advertiser,
            access_address=self.access_address,
            conn_handle=self.conn_handle,
            adv_addr_type=self.adv_addr_type,
            init_addr_type=self.init_addr_type
        )
    
    @staticmethod
    def from_event(event):
        return Connected(
            initiator=event.initiator,
            advertiser=event.advertiser,
            access_address=event.access_address,
            conn_handle=event.conn_handle,
            adv_addr_type=event.adv_addr_type,
            init_addr_type=event.init_addr_type
        )

@pb_bind(BleDomain, 'disconnected', 1)
class Disconnected(PbMessageWrapper):
    """BLE connected message class.

    This class implements WHAD's AbstractEvent interface and can be converted
    into a `DisconnectionEvt` object.
    """
    reason = PbFieldInt('ble.disconnected.reason')
    conn_handle = PbFieldBytes('ble.disconnected.conn_handle')

    def to_event(self):
        """Convert this message to an event.
        """
        return DisconnectionEvt(
            conn_handle=self.conn_handle,
            reason=self.reason
        )
    
    @staticmethod
    def from_event(event):
        return Disconnected(
            conn_handle=event.conn_handle,
            reason=event.reason
        )

@pb_bind(BleDomain, 'desynchronized', 1)
class Desynchronized(PbMessageWrapper):
    """BLE connect message class.

    This class implements WHAD's AbstractEvent interface and can be converted
    into a `DesyncEvt` object.
    """
    access_address = PbFieldInt('ble.desynchronized.access_address')

    def to_event(self):
        """Convert this message to an event.
        """
        return DesyncEvt(
            access_address=self.access_address,
        )
    
    @staticmethod
    def from_event(event):
        return Desynchronized(
            access_address=event.access_address,
        )