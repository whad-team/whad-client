from whad.device import WhadDeviceConnector
from whad.dot15d4.connector import Dot15d4
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Hdr

class WirelessHart(Dot15d4):
    """
    Wireless Hart protocol connector.

    This connector drives a Wireless Hart-capable device with Wireless Hart-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "wirelesshart"

    def __init__(self, device=None, synchronous=False):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        super().__init__(device, synchronous=synchronous, scapy_config='wirelesshart')

    def sniff_wirelesshart(self, channel:int = 11) -> bool:
        return super().sniff_dot15d4(channel=channel)

from whad.wirelesshart.connector.sniffer import Sniffer