"""Bluetooth Low Energy Central mock.

This mock emulates a WHAD device that supports BLE scanning and central modes,
emulating a set of devices with associated GATT servers.
"""

import logging
from time import time
from random import randint, choice

from typing import List

from whad.hub import ProtocolHub
from whad.device.mock import MockDevice
from whad.hub.generic.cmdresult import Success, WrongMode, Error
from whad.hub.ble.mode import CentralMode, BleStart, BleStop
from whad.hub.ble.pdu import SendBlePdu
from whad.hub.ble.connect import ConnectTo, Connected
from whad.hub.ble import BDAddress, Commands
from whad.hub.discovery import Capability, Domain, DeviceType

from .device import EmulatedDevice

logger = logging.getLogger(__name__)

class CentralMock(MockDevice):
    """BLE central mock device.

    This class implements the intended behavior of a BLE-compatible
    hardware interface.
    """

    def __init__(self, devices: List[EmulatedDevice] = None, nowait: bool = False,
                 address: BDAddress = None):
        """Initialize a mock BLE hardware interface that only allow device
        scanning / advertisement sniffing.
        """
        if devices is None:
            logger.warning("No devices passed to scanner")
            self.__devices = []
        else:
            self.__devices = devices

        # Save nowait status
        self.__nowait = nowait

        # Status
        self.__central_mode_set = False
        self.__running = False
        self.__address = address or BDAddress("aa:bb:cc:dd:ee:ff", random=False)
        self.__conn_evt = None
        self.__conn_evt_ts = 0

        # Connections
        self.__handles = [1, 17, 22, 34, 56]
        self.__connections = {}

        # Initialize our mock
        super().__init__(
            author="Whad Team",
            url="https://whad.io",
            proto_minver=ProtocolHub.LAST_VERSION,
            version="1.0.0",
            dev_type=DeviceType.VirtualDevice,
            dev_id=b"BleCentralMock",
            max_speed=115200,
            capabilities=self.__build_capabilities()
        )

    def __build_capabilities(self) -> dict:
        """Dynamically build the device's capabilities based on its config.
        """
        # By design, we don't capture raw BLE PDUs


        # Default commands
        commands = [
            Commands.CentralMode,
            Commands.Start, Commands.Stop, 
            Commands.ConnectTo,
            Commands.SendPDU,
        ]
        capabilities = Capability.NoRawData

        return {
            Domain.BtLE : (
                # We can only scan and sniff with no raw data support
                capabilities,
                commands
            )
        }

    def on_interface_message_(self):
        """Handle pending connection events.
        """
        # Handle pending connection event
        if self.__conn_evt is not None and self.__conn_evt_ts < time():
            if self.__running:
                # Save connection event in connections
                self.__connections[self.__conn_evt.conn_handle] = self.__target

                # Set target device as connected
                self.__target.set_connected(self.__conn_evt.conn_handle)

                # Send notification
                self.put_message(self.__conn_evt)
                self.__conn_evt = None
                self.__conn_evt_ts = 0

        # For each connection, query the corresponding device stack to check if
        # some messages need to be sent to the connector.
        for _, device in self.__connections.items():
            pdu_messages = device.get_pending_pdus()
            for pdu in pdu_messages:
                self.put_message(pdu)

    @MockDevice.route(CentralMode)
    def on_central_mode(self, _: CentralMode):
        """BLE central mode handler"""
        if not self.__central_mode_set:
            if not self.__running:
                # Switch to scanning mode
                self.__central_mode_set = True
                return Success()
            else:
                # Return an error: another mode is running
                return WrongMode()

        if not self.__running:
            return Success()
        else:
            return Error()

    @MockDevice.route(BleStart)
    def on_start(self, _: BleStart):
        """Start selected mode"""
        if not self.__running:
            # If not running, mark as running and send a success response
            self.__running = True
            return Success()
        else:
            # If already running, return success
            return Success()

    @MockDevice.route(BleStop)
    def on_stop(self, _: BleStop):
        """Stop selected mode."""
        if self.__running:
            self.__running = False
        return Success()

    @MockDevice.route(ConnectTo)
    def on_connect(self, connect: ConnectTo):
        """Handle ConnectTo message.
        """
        # Check if the requested device belongs to our device list
        target = None
        for device in self.__devices:
            if device.address.value == connect.bd_address:
                # Device found
                target = device
                break

        # Generate a free connection handle, if possible
        if len(self.__handles) == 0:
            # No more connection handle available, return error
            return Error()
        else:
            conn_handle = choice(self.__handles)
            self.__handles.remove(conn_handle)

        # Device found ? "Connect" to this device and send a notification.
        if target is not None:
            connection_evt = Connected(
                access_addres=0,
                initiator=self.__address.value,
                advertiser=target.address.value,
                conn_handle=conn_handle,
                adv_addr_type=target.addr_type,
                init_addr_type=self.__address.type,
            )

            if self.__nowait:
                # Save connection handle
                self.__connections[conn_handle] = target

                # Set target as connected
                target.set_connected(conn_handle)

                # Return success followed by a successful connected event.
                return [Success(), connection_evt]
            else:
                # Will generate a connection event later
                self.__conn_evt = connection_evt
                self.__conn_evt_ts = time()+randint(5, 20)/10.0
                return Success()

        # Won't find.
        self.__conn_evt = None
        self.__conn_evt_ts = 0
        return Success()

    @MockDevice.route(SendBlePdu)
    def on_send_pdu(self, send_pdu: SendBlePdu):
        """Handle SendPdu command from connector.

        This callback forwards the given PDU to an existing connection.
        """
        if send_pdu.conn_handle in self.__connections:
            self.__connections[send_pdu.conn_handle].on_pdu(send_pdu.pdu)
            return Success()
        else:
            return Error()
