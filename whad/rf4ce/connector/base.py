"""Base RF4CE connector
"""
from whad.dot15d4.connector import Dot15d4

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
