"""
Host/Controller interface lazy layer.
"""
# Whad
from whad.exceptions import WhadDeviceNotFound

# Whad hub
from ..device import DeviceLoader
from .hciconfig import HCIConfig

class HciLoader(DeviceLoader):
    """Host/controller interface virtual device implementation.
    """

    INTERFACE_NAME = "hci"

    @staticmethod
    def create(interface: str):
        from .impl import Hci
        return Hci.create_inst(interface)
