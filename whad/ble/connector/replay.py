"""BLE packet replay connector.

This connector can be used either in standalone to replay packets or combined
with whadreplay.
"""
from dataclasses import dataclass
from scapy.packet import Packet
from whad.device import WhadDevice
from whad.exceptions import UnsupportedCapability
from whad.ble.connector import Central
from whad.ble.exceptions import PeripheralNotFound
from whad.scapy.layers import NordicBLE, BTLE_DATA
from whad.common.replay import ReplayRole, ReplayInterface

@dataclass
class ReplayConfiguration:
    """
    Configuration for the Bluetooth Low Energy replay tool.

    :param target: specify the target BD address (t)
    :param random: target is using a random address (r)
    """
    target : str = None
    random : bool = True


class Replay(Central, ReplayInterface):
    """Replay BLE PDUs using a central device.
    """

    def __init__(self, device : WhadDevice, pcapfile:str, role : int):
        Central.__init__(self, device)
        ReplayInterface.__init__(self, role)
        self.__target = None

        # Make sure our device supports central mode
        if not self.can_be_central():
            raise UnsupportedCapability("Central")


    def prepare(self, config) -> bool:
        """Prepare this replay interface.
        """
        # Connect to our target device
        try:
            self.start()
            self.__target = self.connect(config.target, config.random)
            
            # Success !
            return True
        except PeripheralNotFound as err:
            # We were not able to initialize our replay instance
            return False

    def send_packet(self, packet : Packet):
        """Send packet callback.

        Based on the current replay role, packet must be sent or not.
        """
        # First, we make sure this packet has a valid TAP
        if packet.haslayer(NordicBLE):
            nordic_layer = packet[NordicBLE]
            if nordic_layer.haslayer(BTLE_DATA):
                pdu = nordic_layer[BTLE_DATA]

                # Only allow replay of packets sent by master (central device)
                if (nordic_layer.flags & 2) and self.is_emitter():
                    self.send_data_pdu(pdu, conn_handle=self.__target.conn_handle)

                    # Packet sent, return True
                    return True
        
        # Packet cannot be sent, return False
        return False
        