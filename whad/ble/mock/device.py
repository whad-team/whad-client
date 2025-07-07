"""Bluetooth Low Energy emulated device.
"""
import logging
from queue import Queue, Empty
from typing import List, Optional

from scapy.packet import Packet
from scapy.layers.bluetooth4LE import BTLE_DATA

from whad.hub.ble import BDAddress, AddressType
from whad.hub.ble.pdu import AdvType

logger = logging.getLogger(__name__)

class EmulatedDevice:
    """Properties holder for a BLE device emulated by the BleScanMock.
    """

    STATE_ADVERTISING = 0
    STATE_CONNECTED = 1

    def __init__(self, address: BDAddress, adv_data: bytes = b'', scan_data: Optional[bytes] = None):
        """Create an emulated device and its associated state.

        :param address: Device BD address
        :type address: BDAddress
        :param addr_type: Address type
        :type addr_type: AddressType
        :param adv_data: Advertising data
        :type adv_data: bytes
        :param scan_data: Scan response data
        :type scan_data: bytes
        """
        # Save device address info
        self.__address = address

        # Set advertising data and state
        if len(adv_data) > 31:
            raise ValueError()
        self.__adv_data = adv_data
        if scan_data is not None and len(scan_data) > 31:
            raise ValueError()
        self.__scan_data = scan_data
        self.__next_adv_type = "adv"

        # Set connection state
        self.__handle = None
        self.__tx_pdus = Queue()

        # Set default state as advertising
        self.__state = EmulatedDevice.STATE_ADVERTISING

    ##
    # Device address getters
    ##

    @property
    def address(self) -> BDAddress:
        """Device BD address"""
        return self.__address

    @property
    def addr_type(self) -> AddressType:
        """Device address type"""
        return AddressType.PUBLIC if self.__address.is_public() else AddressType.RANDOM

    ##
    # Mode switching
    ##

    def set_connected(self, conn_handle: int):
        """Switch to connected mode.
        """
        self.__handle = conn_handle
        self.__state = EmulatedDevice.STATE_CONNECTED

    def set_disconnected(self):
        """Switch back to advertising mode.
        """
        self.__handle = None
        self.__state = EmulatedDevice.STATE_ADVERTISING

    def set_advertising(self):
        """Switch to advertising mode.
        """
        self.set_disconnected()

    ##
    # Advertising mode
    ##

    @property
    def adv_data(self) -> bytes:
        """Advertising data"""
        return self.__adv_data

    @property
    def scan_data(self) -> bytes:
        """Scan response data"""
        return self.__scan_data

    def get_adv_data(self) -> Optional[tuple[int, bytes]]:
        """Return the next advertising data type and bytes.
        """
        if self.__next_adv_type == "adv":
            self.__next_adv_type = "scan"
            return (AdvType.ADV_IND, self.__adv_data)
        elif self.__next_adv_type == "scan":
            self.__next_adv_type = "adv"
            return (AdvType.ADV_SCAN_RSP, self.__scan_data)

    ##
    # Connected mode
    ##

    def on_pdu(self, pdu: bytes):
        """Process incoming PDU.
        """
        # Convert bytes back to packet
        print("[central_mock] received PDU %s" % pdu.hex())
        packet = BTLE_DATA(pdu)
        packet.show()

        # Forward packet to device stack

    def get_pending_pdus(self) -> List[bytes]:
        """Pending PDUs
        """
        try:
            pdu = self.__tx_pdus.get(timeout=0.5)
            if pdu is not None:
                return [pdu]
            else:
                return []
        except Empty:
            return []
