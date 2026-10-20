import json
import logging
from typing import Generator
from time import time

from scapy.packet import Packet
from whad.scapy.layers.wirelesshart import WirelessHart_Network_Security_SubLayer_Hdr, \
    WirelessHart_DataLink_Advertisement, WirelessHart_Transport_Layer_Hdr, \
    WirelessHart_Add_Link_Response, WirelessHart_Add_Link_Request, \
    WirelessHart_DataLink_Advertisement,  WirelessHart_Network_Security_SubLayer_Hdr, WirelessHart_Transport_Layer_Hdr
from whad.wihart.connector import WirelessHart
from whad.wihart.sniffing import SnifferConfiguration, TimeSynchronizationEvent, \
    NewLinkEvent, NewSuperframeEvent, NewSessionKeyEvent, NewNetworkKeyEvent

from whad.wihart.crypto import WirelessHartDecryptor, WirelessHartNetworkKeyExtractor,\
    WirelessHartSessionKeyExtractor
from whad.wihart.exceptions import MissingCryptographicMaterial
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived, RawPduReceivedV3, PduReceivedV3, \
    LinkOptions, LinkType
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected



logger = logging.getLogger(__name__)

class Sniffer(WirelessHart, EventsManager):
    """
    Wireless Hart Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device, configuration=SnifferConfiguration()):
        WirelessHart.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = configuration
        self.__decryptor = WirelessHartDecryptor()
        
        self.__network_key_extractor = WirelessHartNetworkKeyExtractor()
        self.__session_key_extractor = WirelessHartSessionKeyExtractor()

        self._synchronized = False

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _provision_keys_from_configuration(self):
        if self.__configuration.join_key is not None:
            self.__decryptor.set_join_key(self.__configuration.join_key)

        if self.__configuration.network_key is not None:
            self.__decryptor.set_network_key(self.__configuration.network_key)

        for ext_key in self.__configuration.broadcast_session_keys:
            self.__decryptor.add_broadcast_extended_session_key(ext_key)

        for ext_key in self.__configuration.unicast_session_keys:
            self.__decryptor.add_unicast_extended_session_key(ext_key)
        

    def is_synchronized(self):
        return self._synchronized

    def detect_channel(self, duration : int = 1, show : bool = True) -> int:
        """
        Detects a first channel used to transmit WirelessHART traffic to permit synchronization to the network
        
        :param duration: duration to listen for on each cahnnel used by WirelessHART in seconds
        :type duration: int
        :param show: show the captured packets while detecting the channel used
        :type show: bool

        :return: a channel used by the network 
        :rtype: int
        """
        while not self.is_synchronized():
            for channel in range(11,26):
                #Set channel on which our sniffer will listen
                self.channel = channel

                for packet in self.sniff(timeout=duration):
                    if show :
                        packet.show()
                    if self.is_synchronized():
                        return channel
        return self.channel
    
    def _enable_sniffing(self):
        self._provision_keys_from_configuration()        
        self.enable_tsch()
        if self.__configuration.load_file is not None:
            self.load_network_state(self.__configuration.load_file)
            self.__configuration.load_file = None
        self.sniff_wihart(channel=self.__configuration.channel)
        
    
    @property
    def decryptor(self):
        return self.__decryptor

    def add_join_key(self, key):
        """
        Add a join key to the sniffer configuration and provision it to the decryptor.
        Every constructor provides its own join key to its devices. Here is a non-exhaustive list of known join keys for some manufacturers:
        ### Dust :            0x445553544E4554574F524B53524F434B
        ### Pepperl+Fuchs :   0xE090D6E2DADACE94C7E9C8D1E781D5ED
        ### Emerson:          0x24924760000000000000000000000000 
        ### Endress+Hauser :  0x456E6472657373202B20486175736572"""
        self.__configuration.join_key = key
        self._provision_keys_from_configuration()

    def add_network_key(self, key):
        self.trigger_event(
            NewNetworkKeyEvent(key)
        )
        self.__configuration.network_key = key
        self._provision_keys_from_configuration()

    def add_unicast_session_key(self, key, source, destination=0x0001, nonce=1):
        self.trigger_event(
            NewSessionKeyEvent(session_key=key, source=source, destination=destination, nonce=nonce, key_type="unicast")
        )
        
        skey = key 
        if isinstance(key, bytes) and len(key) == 16:
            skey = key.hex()
        
        self.__configuration.unicast_session_keys.append(
            str(source) + "," +
            str(destination) + "," +
            skey + "," +
            str(nonce)   
        )

    def add_broadcast_session_key(self, key, source, destination=0xFFFF, nonce=1):
        self.trigger_event(
            NewSessionKeyEvent(session_key=key, source=source, destination=destination, nonce=nonce, key_type="broadcast")
        )
        skey = key 
        if isinstance(key, bytes) and len(key) == 16:
            skey = key.hex()
        
        self.__configuration.broadcast_session_keys.append(
            str(source) + "," +
            str(destination) + "," +
            skey + "," +
            str(nonce)   
        )

    def clear_session_keys(self):
        self.__configuration.unicast_session_keys = []
        self.__configuration.broadcast_session_keys = []

    @property
    def decrypt(self):
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt):
        self.__configuration.decrypt = decrypt


    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=15):
        #self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    @property
    def configuration(self):
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        #self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def process_commands(self, packet):
        self.__session_key_extractor.process_packet(packet)

        new_key_discovered = False
        while self.__session_key_extractor.completed:
            output = self.__session_key_extractor.output
            if output["type"] == "unicast":
                self.add_unicast_session_key(output["key"], output["source"], output["destination"], output["nonce"])
            elif output["type"] == "broadcast":
                self.add_broadcast_session_key(output["key"], output["source"], output["destination"], output["nonce"])
            
            new_key_discovered = True
            self.__session_key_extractor.reset()
            self.__session_key_extractor.process_packet(packet)
            
        self.__network_key_extractor.process_packet(packet)
        if self.__network_key_extractor.completed:
            output = self.__network_key_extractor.output
            self.add_network_key(output["key"])
            new_key_discovered = True
            self.__network_key_extractor.reset()

        if new_key_discovered:
            self._provision_keys_from_configuration()

        if WirelessHart_Transport_Layer_Hdr not in packet:
            return

        for cmd in packet.getlayer(WirelessHart_Transport_Layer_Hdr).commands:
            if WirelessHart_Add_Link_Response in cmd:
                c = cmd[WirelessHart_Add_Link_Response]
                if c.status == 0:
                    #print(f"add link response src = {packet.src_addr}, neighbor = {c.neighbor_nickname}")
                    self.add_link(
                        superframe_id=c.superframe_id, 
                        source=packet.src_addr,
                        time_slot=c.slot_number,
                        channel_offset=c.channel_offset, 
                        neighbor=c.neighbor_nickname if c.link_type==LinkType.NORMAL else 0xffff,
                        options=LinkOptions.TRANSMIT if c.transmit else LinkOptions.RECEIVE if c.receive else LinkOptions.SHARED, 
                        link_type=c.link_type
                    )

            if WirelessHart_Add_Link_Request in cmd:
                c = cmd[WirelessHart_Add_Link_Request]
                #print(f"add link request src = {packet.nwk_dest_addr}, neighbor = {c.neighbor_nickname}")
                self.add_link(
                    superframe_id=c.superframe_id, 
                    source=packet.nwk_dest_addr,
                    time_slot=c.slot_number,
                    channel_offset=c.channel_offset, 
                    neighbor=c.neighbor_nickname if c.link_type==LinkType.NORMAL else 0xffff, 
                    options=LinkOptions.TRANSMIT if c.transmit else LinkOptions.RECEIVE if c.receive else LinkOptions.SHARED, 
                    link_type=c.link_type
                )

    def update_superframe(self, superframe_id, number_of_slots, flags=0, asn=0):
        self.trigger_event(
            NewSuperframeEvent(
                superframe_id=superframe_id,
                number_of_slots=number_of_slots, 
                flags=flags,
                asn=asn
            )
        )
        return super().update_superframe(superframe_id, number_of_slots, flags, asn)

    def add_link(self, superframe_id, source, time_slot, channel_offset, neighbor, options, link_type):
        self.trigger_event(
            NewLinkEvent(
                    superframe_id,
                    source,
                    time_slot,
                    channel_offset,
                    neighbor,
                    options,
                    link_type
            )
        )
        return super().add_link(superframe_id, source, time_slot, channel_offset, neighbor, options, link_type)

    def process_packet(self, packet: Packet):
        """Process received Wireless Hart packet.

        :param packet: received packet
        :type packet: :class:`scapy.packet.Packet`
        :return: received packet
        :rtype: :class:`scapy.packet.Packet`
        """
        #print("offset:", packet.metadata.timestamp - packet.metadata.start_of_slot_timestamp)
        if hasattr(packet.metadata, "asn") and self.network is not None:
            self.network.asn = packet.metadata.asn
            
        if WirelessHart_Network_Security_SubLayer_Hdr in packet and self.__configuration.decrypt:
            try:
                decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
                if success:
                    packet.metadata.decrypted = True
                    metadata = packet.metadata
                    packet = decrypted
                    packet.metadata = metadata
                    self.process_commands(packet)
                    
                    
            except MissingCryptographicMaterial:
                pass

        elif WirelessHart_DataLink_Advertisement in packet:
            if not self._synchronized:
                adv = packet[WirelessHart_DataLink_Advertisement]
                
                if self.network is not None:
                    self.network.panid = packet.dest_panid

                self.trigger_event(TimeSynchronizationEvent(asn=packet.asn))
                
                try:
                    self.set_channel_map(adv.channel_map)
                    
                    probable_offset = 0
                    smallest_superframe = None

                    for superframe in adv.superframes:

                        if smallest_superframe is None:
                            smallest_superframe = (superframe.superframe_id, superframe.superframe_number_of_slots)
                        elif superframe.superframe_number_of_slots < smallest_superframe[1]:
                            smallest_superframe = (superframe.superframe_id, superframe.superframe_number_of_slots)

                        self.update_superframe(
                            superframe_id=superframe.superframe_id,
                            number_of_slots=superframe.superframe_number_of_slots, 
                            flags=0,
                            asn=0
                        )
                        for link in superframe.superframe_links:
                            if smallest_superframe is not None and smallest_superframe[0] == superframe.superframe_id:
                                probable_offset = link.link_channel_offset

                            self.add_link(
                                superframe_id=superframe.superframe_id, 
                                source=packet.src_addr if hasattr(packet, 'src_addr') else 0x0001,
                                time_slot=link.link_join_slot,
                                channel_offset=link.link_channel_offset,
                                neighbor=0xFFFF,
                                options=LinkOptions.RECEIVE,
                                link_type=LinkType.JOIN
                            )
                    
                    if smallest_superframe is not None:
                        self.add_link(
                            superframe_id=smallest_superframe[0],               
                            source=0x0001,           
                            time_slot=0,                   
                            channel_offset=probable_offset,              
                            neighbor=0xFFFF,               
                            options=LinkOptions.RECEIVE,   
                            link_type=LinkType.DISCOVERY   
                        )
                    
                
                    self._synchronized = True

                except Exception as e:
                    logger.error(f"Error during Wireless Hart network synchronization: {e}")

        if self.__configuration.hide_adv and WirelessHart_DataLink_Advertisement in packet and self._synchronized:
            return None

        return packet
        
    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Sniff Wireless Hart packets out of thin air.

        :param timeout: Number of seconds after which sniffing will stop. Wait
                        forever if set to `None`.
        :type timeout: float
        """
        
        if self.support_raw_pdu():
            message_type = (RawPduReceived, RawPduReceivedV3)
        else:
            message_type = (PduReceived, PduReceivedV3)

        try:
            for message in super().capture(messages=(message_type), timeout=timeout):
                if message is not None:
                    packet = message.to_packet()
                    print("Time offset:", packet.metadata.timestamp - packet.metadata.start_of_slot_timestamp)

                    if self.__configuration.hide_adv and WirelessHart_DataLink_Advertisement in packet and self._synchronized:
                        continue

                    if packet is not None:
                            
                        packet = self.process_packet(packet)
                        if packet is not None:
                            self.monitor_packet_rx(packet)
                            yield packet
                        

        except WhadDeviceDisconnected:
            return

    def stop(self):
        """Stop sniffing and save the requested WirelessHART network state."""
        self._save_configured_network_state()
        return super().stop()

    def _save_configured_network_state(self):
        filename = getattr(self.__configuration, "export_file", None)
        if filename is not None:
            self.save_network_state(filename)
            logger.info("Saved network parameters to %s", filename)
            self.__configuration.export_file = None # for a reason i ignore stop was called twice so here's a method to ignore the second call after the destruction of the object

    def save_network_state(self, filename: str):
        """Save the current network state to a JSON file.

        The saved state contains the keys and TSCH network state required
        to restore the current network state without performing the joining procedure again.
        Be careful: a network may update its state while the sniffer is not running, so the
        saved state may no longer be valid when restoring it (for example, after network
        key rotation or superframe/link updates).
        """
        data = self.network_state_to_dict()
        with open(filename, "w", encoding="utf-8") as output:
            json.dump(data, output, indent=2)

    def network_state_to_dict(self):
        superframes = {str(superframe_id): self.network.superframes[superframe_id].to_dict() for superframe_id in self.network.superframes}
        return {
            "join_key": (
                self.__configuration.join_key.hex()
                if self.__configuration.join_key is not None else None
            ),
            "network_key": (
                self.__configuration.network_key.hex()
                if self.__configuration.network_key is not None else None
            ),
            "unicast_session_keys": self.__configuration.unicast_session_keys,
            "broadcast_session_keys": self.__configuration.broadcast_session_keys,
            "superframe": superframes,
        }

    def dict_to_network_state(self, data):
        # Keys extraction
        if data.get("join_key") is not None :
            self.add_join_key(bytes.fromhex(data["join_key"]))

        if data.get("network_key") is not None:
            self.add_network_key(bytes.fromhex(data["network_key"]))
        
        self.clear_session_keys()

        for entry in data.get("unicast_session_keys", []):
            source, destination, key_hex, nonce = entry.split(",")
            self.add_unicast_session_key(
                key=bytes.fromhex(key_hex),
                source=int(source),
                destination=int(destination),
                nonce=int(nonce)
            )

        for entry in data.get("broadcast_session_keys", []):
            source, destination, key_hex, nonce = entry.split(",")
            self.add_broadcast_session_key(
                key=bytes.fromhex(key_hex),
                source=int(source),
                destination=int(destination),
                nonce=int(nonce)
            )  

        # Superframes and links extraction
        for sf_id, superframe in data.get("superframe", {}).items():
            self.update_superframe(
                superframe_id=int(sf_id),
                number_of_slots=superframe["number_of_slots"],
                flags=superframe["flags"],
                asn=superframe["asn"]
            )
            for link in superframe.get("links", []):
                self.add_link(
                    superframe_id=int(sf_id),
                    source=link["source"],
                    time_slot=link["time_slot"],
                    channel_offset=link["channel_offset"],
                    neighbor=link["neighbor"],
                    options=LinkOptions[link["options"]],
                    link_type=LinkType[link["link_type"]]
                )
        self._provision_keys_from_configuration()

    def load_network_state(self, filename: str):
        """Load a previously saved network state from a JSON file.

        The loaded state contains the keys and TSCH network state required
        to restore the current network state without performing the joining procedure again.
        Be careful: a network may update its state while the sniffer is not running, so the
        loaded state may no longer be valid when restoring it 
        
        :param filename: path to the JSON file produced by `save_network_state`
        :type filename: str
        """
        with open(filename, "r", encoding="utf-8") as input_file:
            data = json.load(input_file)
        
        self.dict_to_network_state(data)
        logger.info("Loaded network parameters from %s", filename)