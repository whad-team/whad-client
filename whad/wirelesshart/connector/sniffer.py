import logging

from scapy.packet import Packet
from whad.hub.dot15d4.events import DiscoveryEvt
from whad.wirelesshart.connector import WirelessHart
from whad.wirelesshart.connector.linkexplorer import LinkExplorer
from whad.wirelesshart.connector.superframes import Superframes

from whad.wirelesshart.connector.channelmap import ChannelMap
from whad.wirelesshart.connector.link import Link
from whad.wirelesshart.sniffing import SnifferConfiguration
from whad.scapy.layers.wirelesshart import WirelessHart_Add_Link_Response, WirelessHart_DataLink_Advertisement, WirelessHart_Network_Security_SubLayer_Hdr, WirelessHart_Transport_Layer_Hdr
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter
from whad.wirelesshart.crypto import WirelessHartDecryptor
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected
from whad.device import WhadDevice

logger = logging.getLogger(__name__)

class Sniffer(WirelessHart, EventsManager):
    """
    Wireless Hart Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        """Sniffer initialization.

        :param device: Device to use for sniffing
        :type device: WhadDevice
        """
        WirelessHart.__init__(self, device)
        EventsManager.__init__(self)

        self.__decryptor = WirelessHartDecryptor()
        self.__configuration = SnifferConfiguration()
        self.superframes = Superframes(self)
        self.channelmap = ChannelMap()
        self.linkexplorer = LinkExplorer(self)
        
        self.add_event_listener(self.on_event)
        
        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)
        self.sniff_wirelesshart(channel=self.__configuration.channel)

    def on_event(self, event):
        if isinstance(event, DiscoveryEvt):
            self.on_discovery_evt(event)
        
    def add_key(self, key: bytes):
        """Add an encryption key to our sniffer.

        :param key: encryption key to add
        :type key: bytes
        """
        self.__configuration.keys.append(key)
    
    def add_decryption_key(self, key: bytes):
        """Add a decryption key to our sniffer.

        :param key: decryption key to add
        :type key: bytes
        """
        self.__decryptor.keys.append(key)

    def clear_keys(self):
        """Clear all stored encryption keys.
        """
        self.__configuration.keys = []

    @property
    def decrypt(self) -> bool:
        """Decryption enabled
        """
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt: bool):
        """Set decryption status
        """
        self.__configuration.decrypt = decrypt


    @property
    def channel(self) -> int:
        """Current channel
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel: int = 11):
        """Set current channel.

        :param channel: new Wireless Hart channel to use
        :type channel: int
        """
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    @property
    def configuration(self) -> SnifferConfiguration:
        """Current sniffer configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def process_packet(self, packet: Packet):
        """Process received Wireless Hart packet.

        :param packet: received packet
        :type packet: :class:`scapy.packet.Packet`
        :return: received packet
        :rtype: :class:`scapy.packet.Packet`
        """
        if WirelessHart_Network_Security_SubLayer_Hdr in packet and self.__configuration.decrypt:
            decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
            if success:
                packet = decrypted 
                for cmd in decrypted.getlayer(WirelessHart_Transport_Layer_Hdr).commands:
                    if WirelessHart_Add_Link_Response in cmd:
                        c = cmd[WirelessHart_Add_Link_Response]
                        if c.status == 0:
                            print("add link response")
                            self.superframes.create_and_add_link(c.superframe_id, 
                                                      c.slot_number,
                                                      c.channel_offset, 
                                                      packet.src_addr,
                                                      c.neighbor_nickname,
                                                      Link.OPTIONS_TRANSMIT if c.transmit else Link.OPTIONS_RECEIVE if c.receive else Link.OPTIONS_SHARED, 
                                                      c.link_type)
                   
        if WirelessHart_DataLink_Advertisement in packet:
            self.process_advertisement(packet)
        else:
            packet.show()
        return packet
    
    def process_advertisement(self, pkt:Packet):
        """Updates the channel map and the join links based on the packet"""
        self.superframes.update_from_advertisement(pkt)
        self.channelmap.update_from_advertisement(pkt)
        return pkt
    
    def delete_superframe(self, id)->bool:
        print("delete supefrframe wihart")
        super().delete_superframe(id)
        self.superframes.delete_superframe(id)
        self.linkexplorer.delete_superframe(id) 
                
    def on_discovery_evt(self, evt: DiscoveryEvt):
        """Calls linkexplorer to take into account the discovery of the new communication"""
        params = getattr(evt, '_WhadEvent__parameters', {})
        src = params.get("src")
        dst = params.get("dst")
        slot = params.get("slot")
        offset = params.get("offset")
        if all(p is not None for p in [src, dst, slot, offset]):
            self.linkexplorer.discovered_communication(src, dst, slot, offset)
        else:
            print("[Warning] DiscoveryEvt missing parameters.")
            
    def sniff(self):
        try:
            while True:
                if self.support_raw_pdu():
                    message_type = RawPduReceived
                else:
                    message_type = PduReceived

                message = self.wait_for_message(filter=message_filter(message_type), timeout=0.1)
                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()
                    self.monitor_packet_rx(packet)
                    packet = self.process_packet(packet)
                    yield packet
        except WhadDeviceDisconnected:
            return