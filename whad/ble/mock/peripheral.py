"""Bluetooth Low Energy Peripheral mocks.
"""

import logging
from typing import Optional, Union, List
from random import randint
from time import sleep

from scapy.packet import Packet

from whad.hub import ProtocolHub
from whad.hub.message import HubMessage
from whad.device.mock import MockDevice
from whad.exceptions import WhadDeviceDisconnected, WhadDeviceNotReady

from whad.hub.ble.address import SetBdAddress
from whad.hub.ble.mode import PeriphMode, BleStart, BleStop
from whad.hub.ble.connect import Connected
from whad.hub.ble import BDAddress, Commands, Direction
from whad.hub.ble.pdu import BlePduReceived, SetAdvData, SendBlePdu, BlePduReceived
from whad.hub.generic.cmdresult import Success, Error, WrongMode
from whad.hub.discovery import Capability, Domain, DeviceType
from whad.ble.profile.attribute import UUID
from whad.ble.profile.characteristic import Characteristic

from .stack.l2cap import LlcapClient

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

        # L2CAP
        self.__l2cap = None
        self.__conn_handle = None

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
            # Set state as Connected and set a connection handle
            self.__state = PeripheralMock.STATE_CONNECTED
            self.__conn_handle = randint(1, 100)

            # Add a Connected message to the connector received message queue
            msg = Connected(
                initiator=initiator.value,
                advertiser=self.__bdaddr.value,
                access_address=0,
                adv_addr_type=self.__bdaddr.type,
                init_addr_type=initiator.type,
                conn_handle = self.__conn_handle,
            )
            self.put_message(msg)

            # Initialize an emulated L2CAP connection
            self.__l2cap = LlcapClient(self.__conn_handle)
            self.__client = self.__l2cap.get_gatt()

            # Success
            return True
        else:
            # Nope
            return False

    def to_messages(self, pdus: List[Packet]) -> List[HubMessage]:
        """Convert L2CAP PDUs to a list of BlePduReceived messages."""
        messages = []
        for pdu in pdus:
            messages.append(BlePduReceived(
                conn_handle=self.__conn_handle,
                direction=Direction.MASTER_TO_SLAVE,
                pdu=bytes(pdu),
                processed=False,
                decrypted=False
            ))
        return messages

    def wait_procedure(self, timeout: float = 1.0):
        """Retrieve waiting PDUs from L2CAP layer and convert them to messages and send them to the
        attached connector, then wait for the current procedure to complete."""
        if self.__l2cap is None:
            logger.warning("[PeripheralMock] wait_procedure(): L2CAP layer has not been instantiated.")
            return None
        elif self.__client is None:
            logger.warning("[PeripheralMock] wait_procedure(): GATT client object not instantiated.")
        else:
            messages = self.to_messages(self.__l2cap.get_pdus())
            for msg in messages:
                self.put_message(msg)

            # Wait for the client procedure to terminate
            return self.__client.wait_procedure(timeout=timeout)

    def read_by_group_type(self, group_uuid: UUID, start_handle: int, end_handle: int):
        """Emulate a ReadGroupByType procedure initiated by a remote central.

        This method must be called by the application thread to avoid blocking one
        of the mock device's message thread.
        """
        # Start a ReadGroupByType procedure from an emulated central device."""
        self.__client.read_by_group_type(group_uuid, start_handle, end_handle)
        return self.wait_procedure()

    def read_by_type(self, start_handle: int, end_handle: int, type_uuid: UUID):
        """Emulate a ReadByType procedure initiated by a remote central."""
        # Start a ReadByType procedure from an emulated central device.
        self.__client.read_by_type(start_handle, end_handle, type_uuid)
        return self.wait_procedure()

    def read_attr(self, handle: int):
        """Emulate a Read procedure initiated by a remote central."""
        # Start a Read procedure from an emulated central device.
        self.__client.read(handle)
        return self.wait_procedure()

    def read_blob(self, handle: int, offset: int):
        """Emulate a ReadBlob procedure initiated by a remote central."""
        # Start a ReadBlob procedure from an emulated central device.
        self.__client.read_blob(handle, offset)
        return self.wait_procedure()

    def write_attr(self, handle: int, value: bytes):
        """Emulate a Write procedure initiated by a remote central."""
        # Start a Write procedure from an emulated central device.
        self.__client.write(handle, value)
        return self.wait_procedure()

    def write_cmd(self, handle: int, value: bytes):
        """Emulate a WriteCommand procedure initiated by a remote central."""
        # Start a Write procedure from an emulated central device.
        self.__client.write_cmd(handle, value)
        return self.wait_procedure()

    def sub_notif(self, handle: int, charac: Characteristic):
        """Subscribe for notification by writing into the specified attribute (descriptor)."""
        # Start a NotificationCheck procedure
        self.__client.sub_notif(handle)

        if self.__l2cap is None:
            logger.warning("[PeripheralMock] wait_procedure(): L2CAP layer has not been instantiated.")
            return None
        elif self.__client is None:
            logger.warning("[PeripheralMock] wait_procedure(): GATT client object not instantiated.")
        else:
            messages = self.to_messages(self.__l2cap.get_pdus())
            for msg in messages:
                self.put_message(msg)

        sleep(1)
        charac.value = b"FOOBAR"

        # Wait for the client procedure to terminate
        return self.__client.wait_procedure(timeout=2.0)

    def sub_ind(self, handle: int, charac: Characteristic):
        """Subscribe for notification by writing into the specified attribute (descriptor)."""
        # Start a NotificationCheck procedure
        self.__client.sub_ind(handle)

        if self.__l2cap is None:
            logger.warning("[PeripheralMock] wait_procedure(): L2CAP layer has not been instantiated.")
            return None
        elif self.__client is None:
            logger.warning("[PeripheralMock] wait_procedure(): GATT client object not instantiated.")
        else:
            messages = self.to_messages(self.__l2cap.get_pdus())
            for msg in messages:
                self.put_message(msg)

        sleep(1)
        charac.value = b"FOOBAR"

        # Wait for the client procedure to terminate
        return self.__client.wait_procedure(timeout=2.0)

    def find_information(self, start_handle: int, end_handle: int):
        """Emulate a FindInformation procedure initiated by a remote central.

        This method must be called by the application thread to avoid blocking
        one of the mock device's message thread.
        """
        # Start a FindInformation procedure from an emulated central device.
        self.__client.find_information(start_handle, end_handle)
        return self.wait_procedure()

    def find_by_type_value(self, start_handle: int, end_handle: int, attr_type: UUID, attr_value: bytes):
        """Emulate a FindByType procedure initiated by a remote central."""
        # Start a FindInformation procedure from an emulated central device.
        self.__client.find_by_type_value(start_handle, end_handle, attr_type, attr_value)
        return self.wait_procedure()

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
    def on_set_adv_data(self, _: SetAdvData):
        """Handle SetAdvData message."""
        return Success()

    @MockDevice.route(SetBdAddress)
    def on_set_bd_address(self, _: SetBdAddress):
        """Handle SetBdAddress."""
        return Success()

    @MockDevice.route(SendBlePdu)
    def on_send_pdu(self, send_pdu: SendBlePdu) -> Union[HubMessage, List[HubMessage]]:
        """Handle SendPdu command from connector.

        This callback forwards the given PDU to our emulated central.
        """
        if send_pdu.conn_handle == self.__conn_handle:
            try:
                # Forward to l2cap
                answers = self.__l2cap.on_pdu(send_pdu.to_packet())
                result: List[HubMessage] = [Success()]

                # Convert response PDUs into BlePduReceived messages and add them
                # to the messages sent back to the connector
                for answer in answers:
                    result.append(BlePduReceived(
                        conn_handle=send_pdu.conn_handle,
                        direction=Direction.MASTER_TO_SLAVE,
                        pdu=bytes(answer),
                        processed=False,
                        decrypted=False
                    ))

                # Send messages to connector
                return result
            except (WhadDeviceDisconnected, WhadDeviceNotReady):
                return Error()
        else:
            return Error()

