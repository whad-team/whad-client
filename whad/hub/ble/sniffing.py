"""WHAD Protocol BLE sniffing messages abstraction layer.
"""

from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool
from whad.hub.ble import BleDomain, BlePhy, BleCsa

@pb_bind(BleDomain, 'sniff_adv', 1)
class SniffAdv(PbMessageWrapper):
    """BLE advertisement sniffing message class
    """
    use_ext_adv = PbFieldBool('ble.sniff_adv.use_ext_adv')
    channel = PbFieldInt('ble.sniff_adv.channel')
    bd_address = PbFieldBytes('ble.sniff_adv.bd_address')

@pb_bind(BleDomain, 'sniff_connreq', 1)
class SniffConnReq(PbMessageWrapper):
    """BLE connection request sniffing message class
    """
    show_empty_packets = PbFieldBool('ble.sniff_connreq.show_empty_packets')
    show_advertisements = PbFieldBool('ble.sniff_connreq.show_advertisements')
    channel = PbFieldInt('ble.sniff_connreq.channel')
    bd_address = PbFieldBytes('ble.sniff_connreq.bd_address')

@pb_bind(BleDomain, 'sniff_aa', 1)
class SniffAccessAddress(PbMessageWrapper):
    """BLE connection access address sniffing message class
    """
    monitored_channels = PbFieldBytes('ble.sniff_aa.monitored_channels')
    phy = 0

@pb_bind(BleDomain, 'sniff_aa', 3)
class SniffAccessAddressV3(SniffAccessAddress):
    """BLE connection access address sniffing message class (proto v3)
    """
    monitored_channels = PbFieldBytes('ble.sniff_aa.monitored_channels')
    phy = PbFieldInt('ble.sniff_aa.phy')

@pb_bind(BleDomain, 'sniff_conn', 1)
class SniffActiveConn(PbMessageWrapper):
    """BLE connection access address sniffing message class
    """
    access_address = PbFieldInt('ble.sniff_conn.access_address')
    crc_init = PbFieldInt('ble.sniff_conn.crc_init')
    channel_map = PbFieldBytes('ble.sniff_conn.channel_map')
    hop_interval = PbFieldInt('ble.sniff_conn.hop_interval')
    hop_increment = PbFieldInt('ble.sniff_conn.hop_increment')
    monitored_channels = PbFieldBytes('ble.sniff_conn.monitored_channels')
    phy = BlePhy.LE_1M

@pb_bind(BleDomain, 'sniff_conn', 3)
class SniffActiveConnV3(SniffActiveConn):
    """BLE connection access address sniffing message class
    """
    access_address = PbFieldInt('ble.sniff_conn.access_address')
    crc_init = PbFieldInt('ble.sniff_conn.crc_init')
    channel_map = PbFieldBytes('ble.sniff_conn.channel_map')
    hop_interval = PbFieldInt('ble.sniff_conn.hop_interval')
    hop_increment = PbFieldInt('ble.sniff_conn.hop_increment')
    monitored_channels = PbFieldBytes('ble.sniff_conn.monitored_channels')

    phy = PbFieldInt('ble.sniff_conn.phy')

@pb_bind(BleDomain, 'aa_disc', 1)
class AccessAddressDiscovered(PbMessageWrapper):
    """BLE connection access address discovered notification message class
    """
    access_address = PbFieldInt('ble.aa_disc.access_address')
    rssi = PbFieldInt('ble.aa_disc.rssi')
    timestamp = PbFieldInt('ble.aa_disc.timestamp')
