"""Bluetooth Low Energy Advertiser mock.
"""

import logging
from typing import Optional, List, Tuple

from scapy.packet import Packet

from whad.hub import ProtocolHub
from whad.hub.message import HubMessage
from whad.device.mock import MockDevice

from whad.hub.ble.mode import AdvMode, AdvModeV3, BleStart, BleStop
from whad.hub.ble import BDAddress, Commands, ChannelMap, AdvType
from whad.hub.ble.pdu import SetAdvData
from whad.hub.generic.cmdresult import Success, Error, WrongMode, ParameterError
from whad.hub.discovery import Capability, Domain, DeviceType


# Create logger for this module.
logger = logging.getLogger(__name__)

class AdvertiserMock(MockDevice):
    """BLE advertiser mock device.

    This class implements the intended behavior of a BLE-compatible
    hardware interface.
    """
    STATE_STOPPED = 0
    STATE_STARTED = 1

    def __init__(self, bd_address: str = "aa:bb:cc:dd:ee:ff"):
        """Initialization."""

        # Set state
        self.__state = AdvertiserMock.STATE_STOPPED

        # Advertiser address (default: aa:bb:cc:dd:ee:ff)
        self.__bdaddr = BDAddress(bd_address)

        # Advertising data
        self.__adv_data = None
        self.__scan_data = None
        self.__channel_map = None
        self.__adv_type = None
        self.__inter_min = None
        self.__inter_max = None

        """Initialization."""
        super().__init__(
            author="Whad Team",
            url="https://whad.io",
            proto_minver=3,
            version="1.0.0",
            dev_type=DeviceType.VirtualDevice,
            dev_id=b"AdvertiserMock",
            max_speed=115200,
            capabilities=self.__build_capabilities()
        )

    def __build_capabilities(self) -> dict:
        """Dynamically build the device's capabilities based on its config."""
        # Default commands
        commands = [
            Commands.AdvMode,
            Commands.Start, Commands.Stop,
            Commands.SetAdvData,
        ]
        capabilities = Capability.NoRawData | Capability.SimulateRole

        return {
            Domain.BtLE : (
                # We can only advertise and update advertising data
                capabilities,
                commands
            )
        }

    @property
    def adv_data(self) -> Optional[bytes]:
        """Advertising data"""
        return self.__adv_data

    @property
    def scan_resp(self) -> Optional[bytes]:
        """Scan response data."""
        return self.__scan_data

    @property
    def adv_type(self) -> Optional[AdvType]:
        """Advertisement type"""
        return self.__adv_type

    @property
    def channel_map(self) -> Optional[ChannelMap]:
        """Advertising channel map"""
        return self.__channel_map

    @property
    def adv_interval(self) -> Tuple[Optional[int],Optional[int]]:
        """Advertising interval"""
        return (self.__inter_min, self.__inter_max)

    def is_started(self) -> bool:
        """Check if peripheral is started."""
        return self.__state == AdvertiserMock.STATE_STARTED

    def is_stopped(self) -> bool:
        """Check if peripheral mode is stopped."""
        return self.__state == AdvertiserMock.STATE_STOPPED

    def to_messages(self, pdus: List[Packet]) -> List[HubMessage]:
        return []

    def wait_procedure(self, timeout: float = 1.0):
        """Not sure it is used"""

    @MockDevice.route(BleStart)
    def on_start(self, _: BleStart):
        """Start selected mode."""
        self.__state = AdvertiserMock.STATE_STARTED
        return Success()

    @MockDevice.route(BleStop)
    def on_stop(self, _: BleStop):
        """Stop selected mode."""
        if self.__state == AdvertiserMock.STATE_STARTED:
            self.__state = AdvertiserMock.STATE_STOPPED
            return Success()
        else:
            return Error()

    @MockDevice.route(SetAdvData)
    def on_set_adv_data(self, msg):
        """Handle SetAdvData message.

        This message shall be processed at any time.
        """
        if msg.adv_data is not None:
            self.__adv_data = msg.adv_data
        if msg.scanrsp_data is not None and isinstance(msg.scanrsp_data, bytes):
            self.__scan_data = bytes(msg.scanrsp_data)
        # Success
        return Success()

    @MockDevice.route(AdvMode, AdvModeV3)
    def on_adv_mode(self, msg: AdvMode):
        """Handle AdvMode message.

        This message shall be processed only when the device is
        not active, i.e. when not started.
        """
        # Ensure the device is not started
        if self.is_started():
            return Error()

        # Check interval values
        if msg.inter_min >= msg.inter_max or msg.inter_max <= msg.inter_min:
            return ParameterError()
        if msg.inter_min not in range(0x20, 0x4001):
            return ParameterError()
        if msg.inter_max not in range(0x20, 0x4001):
            return ParameterError()

        # Check provided channel map
        channel_map = ChannelMap.from_bytes(msg.channel_map)
        if len(channel_map) == 0:
            return ParameterError()
        for channel in channel_map.channels():
            if channel not in (37, 38, 39):
                return ParameterError()

        # Check advertisement type
        if msg.adv_type > AdvType.ADV_SCAN_RSP:
            return ParameterError()

        # Make sure we have at least adv_data set
        if msg.adv_data is None or not isinstance(msg.adv_data, bytes):
            return ParameterError()

        # Save parameters
        self.__adv_type = msg.adv_type
        self.__adv_data = msg.adv_data
        self.__scan_data = msg.scanrsp_data
        self.__channel_map = channel_map
        self.__inter_min = msg.inter_min
        self.__inter_max = msg.inter_max

        return Success()

