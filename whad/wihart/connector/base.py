"""Base Wireless Hart connector
"""
from whad.dot15d4.connector import Dot15d4

class WirelessHart(Dot15d4):
    """
    WirelessHart protocol connector.

    This connector drives a WirelessHart-capable device with WirelessHart-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "wihart"

    def __init__(self, device=None, synchronous=False):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        super().__init__(device, synchronous=synchronous, scapy_config='wihart')

    def sniff_wihart(self, channel:int = 15) -> bool:
        return super().sniff_dot15d4(channel=channel)

    def stop(self):
        """
        Stop the Wireless Hart connector.
        """
        success = self.disable_tsch()
        return super().stop()