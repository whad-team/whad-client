"""Bluetooth Low Energy Basic mock.
"""

import logging
from typing import Optional, List, Tuple

from scapy.packet import Packet

from whad.hub.message import HubMessage
from whad.device.mock import MockDevice

from whad.hub.ble.mode import BleStart, BleStop, SetPhy, SetTxPowerLevel, SetSupportedPhys
from whad.hub.ble import BDAddress, Commands, BlePhy
from whad.hub.generic.cmdresult import Success, Error
from whad.hub.discovery import Capability, Domain, DeviceType


# Create logger for this module.
logger = logging.getLogger(__name__)

class BasicMock(MockDevice):
    """BLE basic mock device.

    This class implements the intended behavior of a BLE-compatible
    hardware interface, with no role at all. Useful to test basic
    configuration.
    """
    STATE_STOPPED = 0
    STATE_STARTED = 1

    def __init__(self, bd_address: str = "aa:bb:cc:dd:ee:ff", proto_version: int = 3):
        """Initialization."""

        # Set state
        self.__state = BasicMock.STATE_STOPPED

        # TX power level
        self.__tx_power_level = 0
        self.__tx_phy = BlePhy.LE_1M
        self.__rx_phy = BlePhy.LE_1M

        # Supported PHYs
        self.__tx_supp_phys = [BlePhy.LE_1M]
        self.__rx_supp_phys = [BlePhy.LE_1M]

        """Initialization."""
        super().__init__(
            author="Whad Team",
            url="https://whad.io",
            proto_minver=proto_version,
            version="1.0.0",
            dev_type=DeviceType.VirtualDevice,
            dev_id=b"BasicMock",
            max_speed=115200,
            capabilities=self.__build_capabilities()
        )

    def __build_capabilities(self) -> dict:
        """Dynamically build the device's capabilities based on its config."""
        # Default commands
        commands = [
            Commands.SetPhy,
            Commands.SetSupportedPhys,
            Commands.SetTxPowerLevel,
            Commands.Start, Commands.Stop,
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
    def tx_power_level(self) -> int:
        """TX power level"""
        return self.__tx_power_level

    @property
    def tx_phy(self) -> int:
        """Currently selected TX PHY."""
        return self.__tx_phy

    @property
    def rx_phy(self) -> int:
        """Currently selected RX PHY."""
        return self.__rx_phy

    @property
    def rx_supp_phys(self) -> List[int]:
        """Supported RX PHYs."""
        return self.__rx_supp_phys

    @property
    def tx_supp_phys(self) -> List[int]:
        """Supported TX PHYs."""
        return self.__tx_supp_phys

    def is_started(self) -> bool:
        """Check if peripheral is started."""
        return self.__state == BasicMock.STATE_STARTED

    def is_stopped(self) -> bool:
        """Check if peripheral mode is stopped."""
        return self.__state == BasicMock.STATE_STOPPED

    def to_messages(self, pdus: List[Packet]) -> List[HubMessage]:
        return []

    def wait_procedure(self, timeout: float = 1.0):
        """Not sure it is used"""

    @MockDevice.route(BleStart)
    def on_start(self, _: BleStart):
        """Start selected mode."""
        self.__state = BasicMock.STATE_STARTED
        return Success()

    @MockDevice.route(BleStop)
    def on_stop(self, _: BleStop):
        """Stop selected mode."""
        if self.__state == BasicMock.STATE_STARTED:
            self.__state = BasicMock.STATE_STOPPED
            return Success()
        else:
            return Error()

    @MockDevice.route(SetPhy)
    def on_set_phy(self, msg: SetPhy):
        """Handle SetPhy message."""
        # PHY can be changed at any time.
        self.__tx_phy = msg.tx_phy
        self.__rx_phy = msg.rx_phy

        return Success()

    @MockDevice.route(SetTxPowerLevel)
    def on_set_tx_power(self, msg: SetTxPowerLevel):
        self.__tx_power_level = msg.level
        return Success()

    @MockDevice.route(SetSupportedPhys)
    def on_set_supp_phys(self, msg: SetSupportedPhys):
        self.__rx_supp_phys = msg.rx_phy
        self.__tx_supp_phys = msg.tx_phy
        return Success()
