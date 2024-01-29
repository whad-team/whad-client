from scapy.compat import raw
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4FCS
from scapy.layers.dot15d4 import Dot15d4 as Dot15d4NoFCS
from whad.dot15d4.connector.translator import Dot15d4MessageTranslator
from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.dot15d4.metadata import generate_dot15d4_metadata, Dot15d4Metadata
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from typing import Union, Tuple
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr
from whad.protocol.dot15d4.dot15d4_pb2 import Sniff, Start, Stop, StartCmd, StopCmd, \
    Send, SendCmd, EnergyDetection, EnergyDetectionCmd, EndDeviceMode, SetNodeAddress, \
    AddressType, SendRawCmd, SendRaw


class Dot15d4(WhadDeviceConnector):
    """
    802.15.4 protocol connector.

    This connector drives a 802.15.4-capable device with 802.15.4-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """

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

        # Check if device supports 802.15.4
        if not self.device.has_domain(WhadDomain.Dot15d4):
            raise UnsupportedDomain()
        else:
            self.__ready = True
            conf.dot15d4_protocol = scapy_config
            self.translator = Dot15d4MessageTranslator()

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
        return self.translator.format(packet)

    def can_sniff(self) -> bool:
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Dot15d4)
        return (
            (commands & (1 << Sniff)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_set_node_address(self) -> bool:
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(WhadDomain.Dot15d4)
        return (
            (commands & (1 << SetNodeAddress)) > 0
        )

    def can_be_end_device(self) -> bool:
        """
        Determine if the device implements an End Device role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Dot15d4)
        return (
            (commands & (1 << EndDeviceMode)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_send(self) -> bool:
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(WhadDomain.Dot15d4)
            self.__can_send = ((commands & (1 << Send)) > 0 or (commands & (1 << SendRaw)) > 0)
        return self.__can_send

    def can_perform_ed_scan(self) -> bool:
        """
        Determine if the device can perform energy detection scan.
        """
        commands = self.device.get_domain_commands(WhadDomain.Dot15d4)
        return (
            (commands & (1 << EnergyDetection)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def support_raw_pdu(self) -> bool:
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(WhadDomain.Dot15d4)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw

    def sniff_dot15d4(self, channel:int = 11) -> bool:
        """
        Sniff 802.15.4 packets (on a single channel).
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        msg = Message()
        msg.dot15d4.sniff.channel = channel
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def set_node_address(self, address:int, mode:AddressType = AddressType.SHORT) -> bool:
        """
        Modify 802.15.4 node address.
        """
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        msg = Message()
        msg.dot15d4.set_node_addr.address = address
        msg.dot15d4.set_node_addr.address_type = mode
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def set_end_device_mode(self, channel:int = 11) -> bool:
        """
        Acts as a 802.15.4 End Device.
        """
        if not self.can_be_end_device():
            raise UnsupportedCapability("EndDevice")

        msg = Message()
        msg.dot15d4.end_device.channel = channel
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

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
            # If we support raw PDU, regenerate the FCS if not already present, otherwise use as is
            if self.support_raw_pdu():
                if Dot15d4FCS not in pdu:
                    packet = Dot15d4FCS(raw(pdu)+Dot15d4FCS().compute_fcs(raw(pdu)))
                else:
                    packet = pdu
            # If we only support normal PDU, crop the FCS
            elif Dot15d4FCS in pdu:
                packet = Dot15d4NoFCS(raw(pdu)[:-2])
            else:
                packet = pdu

            self.monitor_packet_tx(packet)

            msg = self.translator.from_packet(packet, channel)
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return (resp.generic.cmd_result.result == ResultCode.SUCCESS)
        else:
            return False


    def perform_ed_scan(self, channel:int = 11) -> bool:
        """
        Perform an Energy Detection scan.
        """
        if self.can_perform_ed_scan():
            msg = Message()
            msg.dot15d4.ed.channel = channel
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return (resp.generic.cmd_result.result == ResultCode.SUCCESS)
        else:
            return False

    def start(self) -> bool:
        """
        Start currently enabled mode.
        """
        msg = Message()
        msg.dot15d4.start.CopyFrom(StartCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def stop(self) -> bool:
        """
        Stop currently enabled mode.
        """
        msg = Message()
        msg.dot15d4.stop.CopyFrom(StopCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def on_generic_msg(self, message:Message):
        """
        Generic message handler.
        """
        pass

    def on_discovery_msg(self, message:Message):
        """
        Discovery message handler.
        """
        pass

    def on_domain_msg(self, domain:str, message:Message):
        """
        Domain message handler. Dispatches domain message to processing methods.
        """
        if not self.__ready:
            return
        if domain == 'dot15d4':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'pdu':
                packet = self.translator.from_message(message, msg_type)
                self.monitor_packet_rx(packet)
                self.on_pdu(packet)

            elif msg_type == 'raw_pdu':
                packet = self.translator.from_message(message, msg_type)
                self.monitor_packet_rx(packet)
                self.on_raw_pdu(packet)

            elif msg_type == "ed_sample":
                self.on_ed_sample(message.ed_sample.timestamp, message.ed_sample.sample)

    def on_raw_pdu(self, packet):
        """
        Raw PDU processing (Dot15d4FCS).
        """
        pdu = Dot15d4NoFCS(raw(packet)[:-2])
        pdu.metadata = packet.metadata
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        """
        Normal PDU processing (Dot15d4).
        """
        # Enqueue PDU if in synchronous mode
        if self.is_synchronous():
            self.add_pending_pdu(packet)
        else:
            pass

    def on_ed_sample(self, timestamp, sample):
        """
        Energy Detection sample processing.
        """
        pass

from whad.dot15d4.connector.sniffer import Sniffer
from whad.dot15d4.connector.enddevice import EndDevice
