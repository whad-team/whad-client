from scapy.compat import raw
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS

# Main whad imports
from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability

# Dot15d4 message translator
from whad.zigbee.connector.translator import ZigbeeMessageTranslator

# WHAD Protocol hub
from whad.hub.generic.cmdresult import Success
from whad.hub.dot15d4 import NodeAddress, Commands, NodeAddressType, PduReceived, \
    RawPduReceived, EnergyDetectionSample

class Zigbee(WhadDeviceConnector):
    """
    Zigbee protocol connector.

    This connector drives a Zigbee-capable device with Zigbee-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """

    def __init__(self, device=None, synchronous=False):
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

        # Check if device supports Zigbee
        if not self.device.has_domain(WhadDomain.Zigbee):
            raise UnsupportedDomain()
        else:
            self.__ready = True
            conf.dot15d4_protocol = 'zigbee'
            self.translator = ZigbeeMessageTranslator(self.hub)

        self.enable_synchronous(synchronous)

    def close(self):
        self.stop()
        self.device.close()

    def format(self, packet):
        return self.translator.format(packet)

    def can_sniff(self):
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Zigbee)
        return (
            (commands & (1 << Commands.Sniff)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def can_set_node_address(self):
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(WhadDomain.Zigbee)
        return (
            (commands & (1 << Commands.SetNodeAddress)) > 0
        )

    def can_be_end_device(self):
        """
        Determine if the device implements an End Device role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Zigbee)
        return (
            (commands & (1 << Commands.EndDeviceMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_send(self):
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(WhadDomain.Zigbee)
            self.__can_send = ((commands & (1 << Commands.Send))>0 or (commands & (1 << Commands.SendRaw)))
        return self.__can_send

    def can_perform_ed_scan(self):
        """
        Determine if the device can perform energy detection scan.
        """
        commands = self.device.get_domain_commands(WhadDomain.Zigbee)
        return (
            (commands & (1 << Commands.EnergyDetection)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def support_raw_pdu(self):
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(WhadDomain.Zigbee)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw

    def sniff_zigbee(self, channel=11):
        """
        Sniff Zigbee packets (on a single channel).
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        # Create a SniffMode message
        msg = self.hub.dot15d4.createSniffMode(channel)

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return isinstance(resp, Success)

    def set_node_address(self, address, mode=NodeAddressType.SHORT):
        """
        Modify Zigbee node address.
        """
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Create node address from parameters
        node_addr = NodeAddress(address, mode)

        # Create a SetNodAddress message
        msg = self.hub.dot15d4.createSetNodeAddress(node_addr)

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return isinstance(resp, Success)

    def set_end_device_mode(self, channel=11):
        """
        Acts as a ZigBee End Device.
        """
        if not self.can_be_end_device():
            raise UnsupportedCapability("EndDevice")

        # Create EndDeviceMode message
        msg = self.hub.dot15d4.createEndDeviceMode(channel)

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return isinstance(resp, Success)

    def send(self, pdu, channel:int = 11) -> bool:
        """
        Send Zigbee packets (on a single channel).

        :param pdu: Zigbee packet to send
        :type pdu: scapy.layers.dot15d4.Dot15d4, scapy.layers.dot15d4.Dot15d4FCS
        :param channel: Channel on which the packet has to be sent
        :type channel: int
        :return: `True` if packet has been correctly sent, `False` otherwise.
        :rtype: bool
        """
        if self.can_send():
            if self.support_raw_pdu():
                if Dot15d4FCS not in pdu:
                    packet = Dot15d4FCS(raw(pdu)+Dot15d4FCS().compute_fcs(raw(pdu)))
                else:
                    packet = pdu
            elif Dot15d4FCS in pdu:
                packet = Dot15d4(raw(pdu)[:-2])
            else:
                packet = pdu

            self.monitor_packet_tx(packet)

            msg = self.translator.from_packet(packet, channel)
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return isinstance(resp, Success)

        else:
            return False
        
    def send_mac(self, pdu, channel=11, add_fcs=False):
        if self.can_send():
            if add_fcs:
                fcs = Dot15d4FCS().compute_fcs(bytes(pdu))
                pdu += fcs
            else:
                packet = pdu / raw(b'\x00\x00')

            msg = self.translator.from_packet(packet, channel)
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return isinstance(resp, Success)
        else:
            return False            

    def perform_ed_scan(self, channel=11):
        """
        Perform an Energy Detection scan.
        """
        if self.can_perform_ed_scan():
            # Create an EnergyDetectionMode message
            msg = self.hub.dot15d4.createEnergyDetectionMode(channel)

            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return isinstance(resp, Success)
        else:
            return False

    def start(self):
        """
        Start currently enabled mode.
        """
        # Create a Start message
        msg = self.hub.dot15d4.createStart()

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return isinstance(resp, Success)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        # Create a Stop message
        msg = self.hub.dot15d4.createStop()

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return isinstance(resp, Success)

    def on_generic_msg(self, message):
        pass

    def on_discovery_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        if not self.__ready:
            return

        assert domain == "zigbee"

        if isinstance(message, PduReceived):
            packet = self.translator.from_message(message)
            self.monitor_packet_rx(packet)
            self.on_pdu(packet)

        elif isinstance(message, RawPduReceived):
            packet = self.translator.from_message(message)
            self.monitor_packet_rx(packet)
            self.on_raw_pdu(packet)
        elif isinstance(message, EnergyDetectionSample):
            self.on_ed_sample(message.timestamp, message.sample)

    def on_raw_pdu(self, packet):
        pdu = Dot15d4(raw(packet)[:-2])
        pdu.metadata = packet.metadata
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        # Enqueue PDU if in synchronous mode
        if self.is_synchronous():
            self.add_pending_pdu(packet)
        else:
            pass

    def on_ed_sample(self, timestamp, sample):
        pass

from whad.zigbee.connector.sniffer import Sniffer
from whad.zigbee.connector.enddevice import EndDevice
