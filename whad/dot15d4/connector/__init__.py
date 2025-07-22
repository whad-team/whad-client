from typing import Union, Tuple

# Scapy imports
from scapy.compat import raw
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4 as Dot15d4NoFCS
from scapy.layers.dot15d4 import Dot15d4FCS
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr
from whad.hub.dot15d4 import Dot15d4Metadata
# Main whad imports
from whad.hub.discovery import Domain, Capability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability


# WHAD Protocol hub
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.dot15d4 import NodeAddress, Commands, NodeAddressType, PduReceived, \
    RawPduReceived, EnergyDetectionSample
from whad.hub.events import JammedEvt


class Dot15d4(WhadDeviceConnector):
    """
    802.15.4 protocol connector.

    This connector drives a 802.15.4-capable device with 802.15.4-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "dot15d4"

    def __init__(self, device=None, synchronous=False, scapy_config='zigbee'):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        self.__ready = False
        self.hopping = False #frequency hopping capability disabled
        super().__init__(device)

        # Capability cache
        self.__can_send = None
        self.__can_send_raw = None

        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Check if device supports 802.15.4
        if not self.device.has_domain(Domain.Dot15d4):
            raise UnsupportedDomain("IEEE 802.15.4")
        else:
            self.__ready = True
            conf.dot15d4_protocol = scapy_config

        self.enable_synchronous(synchronous)

    def close(self):
        """
        Close the connector and the underlying device.
        """
        self.stop()
        self.device.close()

    def format(self, packet:Union[Dot15d4NoFCS,Dot15d4FCS]) -> Tuple[Dot15d4TAP_Hdr, int]:
        """
        Format a packet using the underlying translator.
        """
        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)
        return self.hub.dot15d4.format(packet)

    def can_sniff(self) -> bool:
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.Sniff)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def can_synchronize(self) -> bool:
        """
        Determine if the device can synchronize with a TSCH-based network.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.Sync)) > 0
        )


    def can_set_node_address(self) -> bool:
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.SetNodeAddress)) > 0
        )

    def can_be_end_device(self) -> bool:
        """
        Determine if the device implements an End Device role mode.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.EndDeviceMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_send(self) -> bool:
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(Domain.Dot15d4)
            self.__can_send = ((commands & (1 << Commands.Send)) > 0 or (commands & (1 << Commands.SendRaw)) > 0)
        return self.__can_send

    def can_perform_ed_scan(self) -> bool:
        """
        Determine if the device can perform energy detection scan.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.EnergyDetection)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def support_raw_pdu(self) -> bool:
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(Domain.Dot15d4)
            self.__can_send_raw = not (capabilities & Capability.NoRawData)
        return self.__can_send_raw

    def sniff_dot15d4(self, channel:int = 11) -> bool:
        """
        Sniff 802.15.4 packets (on a single channel).
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        # Create a SniffMode message
        msg = self.hub.dot15d4.create_sniff_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def set_node_address(self, address:int, mode:NodeAddressType = NodeAddressType.SHORT) -> bool:
        """
        Modify 802.15.4 node address.
        """
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Create node address from parameters
        node_addr = NodeAddress(address, mode)

        # Create a SetNodAddress message
        msg = self.hub.dot15d4.create_set_node_address(node_addr)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def set_end_device_mode(self, channel:int = 11) -> bool:
        """
        Acts as a 802.15.4 End Device.
        """
        if not self.can_be_end_device():
            raise UnsupportedCapability("EndDevice")

        # Create EndDeviceMode message
        msg = self.hub.dot15d4.create_end_device_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_be_coordinator(self) -> bool:
        """
        Determine if the device implements a Coordinator role mode.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.CoordinatorMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def set_coordinator_mode(self, channel:int = 11) -> bool:
        """
        Acts as a 802.15.4 Coordinator.
        """
        if not self.can_be_coordinator():
            raise UnsupportedCapability("Coordinator")

        # Create EndDeviceMode message
        msg = self.hub.dot15d4.create_coord_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def enable_hopping(self)-> bool:
        """
        Enables frequency hopping
        """
        # check if hopping is already activated
        if not self.hopping:
            self.hopping = True
            msg = self.hub.dot15d4.create_hopping_cmd(True)
            print("enable : msg=",repr(msg))
            resp = self.send_command(msg, message_filter(CommandResult))
            return isinstance(resp, Success)
        else:
            return True #already activated
        
    def disable_hopping(self)-> bool:
        """
        Disables frequency hopping
        """
        # check if hopping is activated
        if self.hopping:
            self.hopping = False
            msg = self.hub.dot15d4.create_hopping_cmd(False)
            print("disable : msg=",repr(msg))
            resp = self.send_command(msg, message_filter(CommandResult))
            return isinstance(resp, Success)
        else:
            return True #already disactivated
        
    def update_dongle_channel_map(self, channel_map) ->bool :
        """
        Sends channel map to dongle
        """
        msg = self.hub.dot15d4.create_channel_map_cmd(channel_map)
        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)
    
    def write_modify_superframe(self, id, nb_slots, flags, asn = None)->bool:
        """
        Sends a command to add or modify a superframe
        """
        msg = self.hub.dot15d4.create_write_modify_superframe_cmd(id, nb_slots, flags, asn)
        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)
    
    def delete_superframe(self, id)->bool:
        "Sends a command to delete the superframe corresponding to the given id"
        msg = self.hub.dot15d4.delete_superframe_cmd(id)
        print(f"msg = {msg.message}")
        resp = self.send_command(msg, message_filter(CommandResult))
        print(f"resp = {resp}")
        return isinstance(resp, Success)
    
    def add_links(self, links:bytearray) -> bool:
        """
        Sends a command to add a new link : modifying a link should go by deleting it first otherwise the operation will be discarded
        For each link 8 bytes :  1 for superframe id, 2 for join slot nb, 1 for offset, 2 for neighbor, 1 for flags, 1 for type
        """
        nb_links:int = len(links)//8 #each link a an 8 length byte array
        msg = self.hub.dot15d4.create_add_links_cmd(nb_links, links)
        print("add link msg=", msg)
        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)
        
    def delete_link(self, superframeId, slotNumber, neighbor)->bool:
        """"
        Sends a command to delete a link
        """
        msg = self.hub.dot15d4.delete_link_cmd(superframeId, slotNumber, neighbor)
        print(f"msg = {msg.message}")
        resp = self.send_command(msg, message_filter(CommandResult))
        print(f"resp = {resp}")
        return isinstance(resp, Success)
    
    ''' Deprecated
    def synchronize(self, timestamp : int, asn : int) -> bool:
        """
        Synchronize with a TSCH-based network.
        """
        if not self.can_synchronize():
            raise UnsupportedCapability("Synchronization")

        # Create Sync message
        msg = self.hub.dot15d4.create_sync(timestamp, asn)
        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)'''

    def send(self, pdu, channel:int = 11) -> bool:
        """
        Send 802.15.4 packets (on a single channel).

        :param pdu: 802.15.4 packet to send
        :type pdu: scapy.layers.dot15d4.Dot15d4, scapy.layers.dot15d4.Dot15d4FCS
        :param channel: Channel on which the packet has to be sent
        :type channel: int
        :return: `True` if packet has been correctly sent, `False` otherwise.
        :rtype: bool
        """
        if self.can_send():
            metadata = Dot15d4Metadata()
            metadata.raw = False
            metadata.channel = channel
            if self.support_raw_pdu():
                metadata.raw = True

                if Dot15d4FCS not in pdu:
                    packet = Dot15d4FCS(raw(pdu) + Dot15d4FCS().compute_fcs(raw(pdu)))
                else:
                    packet = pdu

            elif Dot15d4FCS in pdu:
                packet = Dot15d4NoFCS(raw(pdu)[:-2])
            else:
                packet = pdu
            
            if hasattr(packet, "reserved"):
                packet.reserved = packet.reserved

            # Set metadata
            packet.metadata = metadata
            # Send packet
            return super().send_packet(packet)
        else:
            return False


    def send_mac(self, pdu, channel=11, add_fcs=False):
        if self.can_send():
            if add_fcs:
                fcs = Dot15d4FCS().compute_fcs(bytes(pdu))
                pdu += fcs
                raw_mode = True
            else:
                packet = pdu / raw(b'\x00\x00')
                raw_mode = False

            # Add Dot15d4 metadata
            packet.metadata = Dot15d4Metadata()
            packet.metadata.raw = raw_mode

            # Send packet
            return super().send_packet(packet)
        else:
            return False

    def perform_ed_scan(self, channel:int = 11) -> bool:
        """
        Perform an Energy Detection scan.
        """
        if self.can_perform_ed_scan():
            # Create an EnergyDetectionMode message
            msg = self.hub.dot15d4.create_energy_detection_mode(channel)

            resp = self.send_command(msg, message_filter(CommandResult))
            return isinstance(resp, Success)
        else:
            return False

    def start(self) -> bool:
        """
        Start currently enabled mode.
        """
        # Create a Start message
        msg = self.hub.dot15d4.create_start()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def stop(self) -> bool:
        """
        Stop currently enabled mode.
        """
        # Create a Stop message
        msg = self.hub.dot15d4.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def on_generic_msg(self, message):
        """
        Generic message handler.
        """
        pass

    def on_discovery_msg(self, message):
        """
        Discovery message handler.
        """
        pass

    def on_domain_msg(self, domain:str, message):
        """
        Domain message handler. Dispatches domain message to processing methods.
        """
        if not self.__ready:
            return

        assert domain == "dot15d4"
        if isinstance(message, EnergyDetectionSample):
            self.on_ed_sample(message.timestamp, message.sample)

    def on_packet(self, packet):
        """Dot15d4 packet dispatch.
        """
        if not self.__ready:
            return

        # Dispatch packet.
        if packet.metadata.raw:
            self.on_raw_pdu(packet)
        else:
            self.on_pdu(packet)

    def on_event(self, event):
        """Dot15d4 event dispatch.
        """
        if not self.__ready:
            return

        if isinstance(event, JammedEvt):
            self.on_jammed(event.timestamp)

    def on_raw_pdu(self, packet):
        """
        Raw PDU processing (Dot15d4FCS).
        """
        # Ugly hack but we need a forced rebuild in specific cases...
        if hasattr(packet, "reserved"):
            packet.reserved = packet.reserved

        pdu = Dot15d4NoFCS(packet.do_build()[:-2])
        pdu.metadata = packet.metadata
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        """
        Normal PDU processing (Dot15d4).
        """
        # Enqueue PDU if in synchronous mode
        if self.is_synchronous():
            self.add_pending_packet(packet)
        else:
            pass

    def on_ed_sample(self, timestamp, sample):
        """
        Energy Detection sample processing.
        """
        pass

    def on_jammed(self, timestamp: int):
        """Jammed event handler.
        """
        pass

from whad.dot15d4.connector.sniffer import Sniffer
from whad.dot15d4.connector.enddevice import EndDevice
from whad.dot15d4.connector.coordinator import Coordinator

__all__ = [
    "Dot15d4",
    "Sniffer",
    "EndDevice",
    "Coordinator"
]
