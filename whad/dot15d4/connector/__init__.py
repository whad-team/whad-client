import logging
from typing import Union, Tuple

# packaging
from packaging.version import Version

# Scapy imports
from scapy.packet import Packet, Raw
from scapy.compat import raw
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4 as Dot15d4NoFCS
from scapy.layers.dot15d4 import Dot15d4FCS

from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr
from whad.hub.dot15d4 import Dot15d4Metadata
# Main whad imports
from whad.scapy.layers.dot15d4tap import Dot15d4Raw
from whad.hub.discovery import Domain, Capability
from whad.cli.app import CommandLineApp
from whad.device.connector import Connector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability


# WHAD Protocol hub
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.dot15d4 import NodeAddress, Commands, NodeAddressType, PduReceived, \
    RawPduReceived, EnergyDetectionSample
from whad.hub.events import JammedEvt

logger = logging.getLogger(__name__)

class Dot15d4(Connector):
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
        super().__init__(device)

        # Capability cache
        self.__can_send = None
        self.__can_send_raw = None

        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Display a warning message if ButteRFly version is less than 1.0.2 as
        # a critical bug has been found and fixed in version 1.0.2. FCS values
        # will be wrong if using a version prior to 1.0.2.
        if device.info.fw_url == "https://github.com/whad-team/butterfly":
            if Version(device.info.version_str) < Version("1.0.2"):
                message = ((
                    "You are using a ButteRFly version prior to 1.0.2 that does not correctly compute FCS values, "
                    "this will result in invalid FCS values in packets and PCAP files that may cause errors when "
                    "used with other WHAD tools. Please consider upgrading firmware to the latest version "
                    "(see https://github.com/whad-team/butterfly). "
                    "You can also use `winstall --flash butterfly` to reprogram your USB dongle."
                ))

                # Use application warning method if available
                app = CommandLineApp.get_instance()
                if app is not None:
                    app.warning(message)
                else:
                    # If not available, use basic logging capabilities
                    logger.warning(message)

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

    def send(self, pdu: Union[Packet, bytes, Dot15d4NoFCS, Dot15d4FCS], channel:int = 11) -> bool:
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

            # If PDU is provided as bytes, wrap it into a Raw packet
            if isinstance(pdu, bytes):
                pdu = Raw(pdu)

            if self.support_raw_pdu():
                metadata.raw = True

                if Dot15d4FCS not in pdu:
                    # Compute FCS if required by the hardware
                    packet = Dot15d4FCS(raw(pdu) + Dot15d4FCS().compute_fcs(raw(pdu)))
                else:
                    packet = pdu

            elif Dot15d4FCS in pdu:
                # Remove FCS if hardware cannot set it
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


    def send_mac(self, pdu: bytes, channel: int = 11, add_fcs: bool = False):
        """
        Send raw 802.15.4 packets (on a single channel).

        :param pdu: 802.15.4 packet to send
        :type pdu: bytes
        :param channel: Channel on which the packet has to be sent
        :type channel: int
        :param add_fcs: Add FCS field if set to `True`
        :type add_fcs: bool
        :return: `True` if packet has been correctly sent, `False` otherwise.
        :rtype: bool
        """
        if self.can_send():
            # If raw mode is supported by the hardware, handle FCS value
            if self.support_raw_pdu():
                # Enable raw mode
                raw_mode = True

                # Add FCS if required
                if add_fcs:
                    fcs = Dot15d4FCS().compute_fcs(bytes(pdu))
                    packet = Dot15d4Raw(pdu + fcs)
                else:
                    packet = Dot15d4Raw(pdu)
            else:
                # Disable raw mode
                raw_mode = False

                # Cannot add/remove FCS, let hardware generate it
                logger.debug((
                    "[dot15d4::send_mac()] cannot add or remove FCS because HW"
                    "does not support raw packets, rollback to classic 802.15.4"
                    "frames with valid FCS."
                ))
                packet = Dot15d4Raw(pdu)

            # Add Dot15d4 metadata
            packet.metadata = Dot15d4Metadata()
            packet.metadata.raw = raw_mode
            packet.metadata.channel = channel

            # Send packet
            return super().send_packet(packet)

        # Failed at sending packet.
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

    def on_discovery_msg(self, message):
        """
        Discovery message handler.
        """

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
