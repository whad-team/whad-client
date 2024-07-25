from whad.device import WhadDeviceConnector
from whad.dot15d4.connector import Dot15d4
from whad.scapy.layers.rf4ce import RF4CE_Hdr

class RF4CE(Dot15d4):
    """
    RF4CE protocol connector.

    This connector drives a RF4CE-capable device with RF4CE-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "rf4ce"

    def __init__(self, device=None, synchronous=False):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        super().__init__(device, synchronous=synchronous, scapy_config='rf4ce')

    def sniff_rf4ce(self, channel:int = 15) -> bool:
        return super().sniff_dot15d4(channel=channel)


from whad.rf4ce.connector.sniffer import Sniffer
from whad.rf4ce.connector.target import Target
from whad.rf4ce.connector.controller import Controller
