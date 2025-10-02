"""
WHAD Bluetooth Low Energy scanner mock device.

This mock emulates a WHAD-compatible hardware connected to the host
and implements the expected behavior of a BLE-oriented WHAD firmware.
"""
import logging
from time import sleep
from random import randint, choice

from typing import List
from whad.device.mock import MockDevice
from whad.hub import ProtocolHub
from whad.hub.discovery import DeviceType, Domain, Capability
from whad.hub.generic.cmdresult import Success, WrongMode, Error
from whad.hub.ble import BDAddress, Commands
from whad.hub.ble.mode import ScanMode, BleStart, BleStop
from whad.hub.ble.pdu import BleAdvPduReceived, AdvType
from whad.hub.ble.sniffing import SniffAdv

from .device import EmulatedDevice

logger = logging.getLogger(__name__)

class DeviceScan(MockDevice):
    """BLE scanning mock device

    This class implements the intended behavior of a BLE-compatible
    hardware interface.
    """

    MODE_SCAN =  0
    MODE_SNIFF = 1

    def __init__(self, devices: List[EmulatedDevice] = None, sniffing: bool = False,
                 nowait: bool = False):
        """Initialize a mock BLE hardware interface that only allow device
        scanning / advertisement sniffing.
        """
        if devices is None:
            logger.warning("No devices passed to scanner")

        # Save sniffing mode status
        self.__sniffing = sniffing
        self.__nowait = nowait

        # By default, no mode enabled and not running
        self.__current_mode = None
        self.__active_scan = False
        self.__bd_filter = None
        self.__running = False
        self.__next_delay = 0

        # Save emulated devices list
        self.__devices = devices

        # Initialize our mock
        super().__init__(
            author="Whad Team",
            url="https://whad.io",
            proto_minver=ProtocolHub.LAST_VERSION,
            version="1.0.0",
            dev_type=DeviceType.VirtualDevice,
            dev_id=b"BleScanMock",
            max_speed=115200,
            capabilities=self.__build_capabilities()
        )

    def __build_capabilities(self) -> dict:
        """Dynamically build the device's capabilities based on its config.
        """
        # By design, we don't capture raw BLE PDUs


        # Default commands
        commands = [ Commands.Start, Commands.Stop ]
        capabilities = Capability.NoRawData

        if self.__sniffing:
            capabilities = capabilities | Capability.Sniff
            commands.append(Commands.SniffAdv)
        else:
            capabilities = capabilities | Capability.Scan
            commands.append(Commands.ScanMode)

        return {
            Domain.BtLE : (
                # We can only scan and sniff with no raw data support
                capabilities,
                commands
            )
        }

    @property
    def started(self) -> bool:
        """Check if mock device is started."""
        return self.__running

    @property
    def stopped(self) -> bool:
        """Check if mock device is stopped."""
        return not self.__running

    def accept(self, bdaddr: BDAddress) -> bool:
        """Apply BD filter if required.
        """
        if self.__bd_filter == b"\xff\xff\xff\xff\xff\xff":
            return True
        return self.__bd_filter == bdaddr.value

    def set_next_delay(self):
        """Generate a random delay between 200 and 1500ms.
        """
        if self.__nowait:
            self.__next_delay = 0
        else:
            self.__next_delay = randint(200, 800)/1000.

    @MockDevice.route(ScanMode)
    def on_scan_mode(self, message: ScanMode):
        """BLE scan mode handler"""
        if not self.__sniffing:
            # Switch to scanning mode
            self.__current_mode = self.MODE_SCAN
            self.__active_scan = message.active
            return Success()
        else:
            return Error()

    @MockDevice.route(SniffAdv)
    def on_sniff_mode(self, message: SniffAdv):
        """BLE Sniffing mode handler"""
        if self.__sniffing:
            self.__current_mode = self.MODE_SNIFF
            self.__bd_filter = message.bd_address
            return Success()
        else:
            return Error()

    @MockDevice.route(BleStart)
    def on_start(self, _: BleStart):
        """Start selected mode"""
        if not self.__running:
            # Generate a random timestamp (in ms) after which we will report
            # one of our emulated devices
            self.set_next_delay()
            # If not running, mark as running and send a success response
            self.__running = True
            return Success()
        else:
            # If already running, return a wrong mode error
            return WrongMode()

    @MockDevice.route(BleStop)
    def on_stop(self, _: BleStop):
        """Stop selected mode."""
        logger.debug("[blescan mock] on_stop()")
        if self.__running:
            self.__running = False
        return Success()

    def on_interface_message(self):
        # Wait for next delay slot
        sleep(self.__next_delay)

        if self.__running:
            report = None

            # Pick a random device from our list
            advertiser = choice(self.__devices)
            if self.__current_mode == self.MODE_SNIFF:
                if self.accept(advertiser.address):
                    # Get advertiser data
                    adv_type, adv_data = advertiser.get_adv_data()

                    # Generate notification message
                    report = BleAdvPduReceived(
                        adv_type=adv_type,
                        rssi=randint(-80, -30),
                        bd_address=advertiser.address.value,
                        adv_data=adv_data,
                        addr_type=advertiser.addr_type
                    )
            else:
                # Generate an advertising notification
                adv_type, adv_data = advertiser.get_adv_data()
                if adv_type!=AdvType.ADV_SCAN_RSP or self.__active_scan:
                    report = BleAdvPduReceived(
                        adv_type=adv_type,
                        rssi=randint(-80, -30),
                        bd_address=advertiser.address.value,
                        adv_data=adv_data,
                        addr_type=advertiser.addr_type
                    )

            if report is not None:
                self.put_message(report)

        # Compute the next delay
        self.set_next_delay()
