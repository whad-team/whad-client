"""Bluetooth Low Energy Peripheral mocks.
"""

import logging
from typing import Optional, Union

from whad.hub import ProtocolHub
from whad.hub.message import HubMessage
from whad.device.mock import MockDevice

from whad.hub.ble.address import SetBdAddress
from whad.hub.ble.mode import PeriphMode, BleStart, BleStop
from whad.hub.ble.connect import Connected
from whad.hub.ble import AddressType, BDAddress, Commands, Direction
from whad.hub.ble.pdu import SetAdvData, SendBlePdu
from whad.hub.generic.cmdresult import Success, Error, WrongMode
from whad.hub.discovery import Capability, Domain, DeviceType

# Create logger for this module.
logger = logging.getLogger(__name__)

class PeripheralMock(MockDevice):
    """BLE peripheral mock device.

    This class implements the intended behavior of a BLE-compatible
    hardware interface.
    """
    STATE_STOPPED = 0
    STATE_STARTED = 1
    STATE_CONNECTED = 2

    def __init__(self, bd_address: str = "aa:bb:cc:dd:ee:ff"):
        """Initialization."""

        # Set state
        self.__state = PeripheralMock.STATE_STOPPED

        # Advertiser address (default: aa:bb:cc:dd:ee:ff)
        self.__bdaddr = BDAddress(bd_address)

        # Advertising data
        self.__adv_data = None
        self.__scan_data = None

        """Initialization."""
        super().__init__(
            author="Whad Team",
            url="https://whad.io",
            proto_minver=ProtocolHub.LAST_VERSION,
            version="1.0.0",
            dev_type=DeviceType.VirtualDevice,
            dev_id=b"PeripheralMock",
            max_speed=115200,
            capabilities=self.__build_capabilities()
        )

    def __build_capabilities(self) -> dict:
        """Dynamically build the device's capabilities based on its config."""
        # Default commands
        commands = [
            Commands.PeripheralMode,
            Commands.Start, Commands.Stop,
            Commands.SetAdvData,
            Commands.SetBdAddress,
            Commands.SendPDU,
        ]
        capabilities = Capability.NoRawData | Capability.SimulateRole

        return {
            Domain.BtLE : (
                # We can only scan and sniff with no raw data support
                capabilities,
                commands
            )
        }

    def get_adv_data(self) -> Optional[bytes]:
        """Advertising data"""
        return self.__adv_data

    def get_scan_resp(self) -> Optional[bytes]:
        """Scan response data."""
        return self.__scan_data

    def is_started(self) -> bool:
        """Check if peripheral is started."""
        return self.__state == PeripheralMock.STATE_STARTED

    def is_stopped(self) -> bool:
        """Check if peripheral mode is stopped."""
        return self.__state == PeripheralMock.STATE_STOPPED

    def make_connection(self, initiator: BDAddress) -> bool:
        """Initiate a connection from an emulated central device.

        Peripheral must be started and advertising, the mocked interface
        will generate a Connected message and send it to the connector.
        """
        if self.__state == PeripheralMock.STATE_STARTED:
            # Add a Connected message to the connector received message queue
            msg = Connected(
                initiator=initiator.value,
                advertiser=self.__bdaddr.value,
                access_address=0,
                adv_addr_type=self.__bdaddr.type,
                init_addr_type=initiator.type
            )
            self.put_message(msg)

            # Success
            return True
        else:
            # Nope
            return False

    @MockDevice.route(PeriphMode)
    def on_periph_mode(self, message: PeriphMode):
        """BLE Peripheral node handler.

        If a mode is already selected and running, return a WrongMode
        error. If in stopped state, return success.
        """
        if self.__state == PeripheralMock.STATE_STARTED:
            return WrongMode()

        # Save advertising parameters
        self.__adv_data = message.get_adv_data()
        self.__scan_data = message.get_scan_data()

        # Success
        return  Success()

    @MockDevice.route(BleStart)
    def on_start(self, _: BleStart):
        """Start selected mode."""
        self.__state = PeripheralMock.STATE_STARTED
        return Success()

    @MockDevice.route(BleStop)
    def on_stop(self, _: BleStop):
        """Stop selected mode."""
        if self.__state == PeripheralMock.STATE_STARTED:
            self.__state = PeripheralMock.STATE_STOPPED
            return Success()
        else:
            return Error()

    @MockDevice.route(SetAdvData)
    def on_set_adv_data(self, adv_data: SetAdvData):
        """Handle SetAdvData message."""
        return Success()

    @MockDevice.route(SetBdAddress)
    def on_set_bd_address(self, set_bd_address: SetBdAddress):
        """Handle SetBdAddress."""
        return Success()

    @MockDevice.route(SendBlePdu)
    def on_send_pdu(self, send_pdu: SendBlePdu) -> Union[HubMessage, list[HubMessage]]:
        """Handle SendPdu command from connector.

        This callback forwards the given PDU to our emulated central.
        """
        return Success()

