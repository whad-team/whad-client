from whad.device import WhadDeviceConnector
from whad.dot15d4.connector import Dot15d4

class Zigbee(Dot15d4):
    """
    Zigbee protocol connector.

    This connector drives a Zigbee-capable device with Zigbee-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "zigbee"

    def __init__(self, device=None, synchronous=False):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        super().__init__(device, synchronous=synchronous, scapy_config='zigbee')

    def sniff_zigbee(self, channel:int = 11) -> bool:
        return super().sniff_dot15d4(channel=channel)

from whad.zigbee.connector.sniffer import Sniffer
from whad.zigbee.connector.enddevice import EndDevice
from whad.zigbee.connector.coordinator import Coordinator
