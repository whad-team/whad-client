import logging
from typing import Union, Tuple

# packaging
from packaging.version import Version

# scapy imports
from whad.scapy.layers.ant import ANT_Hdr

# Main whad imports
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability

# WHAD Protocol hub
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.discovery import Domain, Capability
from whad.hub.ant import Commands

# ANT-specific imports
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY

logger = logging.getLogger(__name__)

class ANT(WhadDeviceConnector):
    """
    ANT protocol connector.

    This connector drives an ANT-capable device with ANT-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "ant"

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

        # Check if device supports ANT
        if not self.device.has_domain(Domain.ANT):
            raise UnsupportedDomain("ANT")
        else:
            self.__ready = True

        self.enable_synchronous(synchronous)

    def close(self):
        """
        Close the connector and the underlying device.
        """
        self.stop()
        self.device.close()


    def format(self, packet:Union[bytes, ANT_Hdr]) -> Tuple[ANT_Hdr, int]:
        """
        Format a packet using the underlying translator.
        """
        if isinstance(packet, bytes):
            packet = ANT_Hdr(packet)
        return self.hub.ant.format(packet)
        
    def can_sniff(self) -> bool:
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(Domain.ANT)
        return (
            (commands & (1 << Commands.Sniff)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )



    def start(self) -> bool:
        """
        Start currently enabled mode.
        """
        # Create a Start message
        msg = self.hub.ant.create_start()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def stop(self) -> bool:
        """
        Stop currently enabled mode.
        """
        # Create a Stop message
        msg = self.hub.ant.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def sniff_ant(
                    self, 
                    device_number : int, 
                    device_type : int, 
                    transmission_type : int,
                    network_key : bytes = ANT_PLUS_NETWORK_KEY, 
                    frequency : int = 2457
    ) -> bool:
        """
        Sniff ANT packets (on a single channel).
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        # Create a SniffMode message
        msg = self.hub.ant.create_sniff(
            frequency = frequency, 
            network_key = network_key, 
            device_number = device_number, 
            device_type = device_type, 
            transmission_type = transmission_type
        )

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

    def on_packet(self, packet):
        """ANT packet dispatch.
        """
        if not self.__ready:
            return

        # Dispatch packet.
        if packet.metadata.raw:
            self.on_raw_pdu(packet)
        else:
            self.on_pdu(packet)

    
    def on_raw_pdu(self, packet):
        """
        Raw PDU processing (ANT_Hdr).
        """
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        """
        Normal PDU processing (???).
        """
        packet.show()
        # Enqueue PDU if in synchronous mode
        if self.is_synchronous():
            self.add_pending_packet(packet)
        else:
            pass

    def on_event(self, event):
        """ANT event dispatch.
        """
        if not self.__ready:
            return


