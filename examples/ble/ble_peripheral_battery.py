"""
Example of an emulated BLE peripheral exposing a Battery service with a
single characteristic (battery level).

Each time the battery level characteristic value is read, this level decreases
by 10%.
"""

from whad.device import WhadDevice
from whad.ble import Peripheral
from whad.ble.profile.advdata import AdvCompleteLocalName, \
                                     AdvDataFieldList, AdvFlagsField
from whad.ble.profile.services import BatteryService
from whad.ble.profile import read, GenericProfile

class BatteryDevice(GenericProfile, BatteryService):
    """Device exposing a battery service
    """

    @read(BatteryService.battery.level)
    def on_battery_level_read(self, offset, length):
        level = self.get_battery_level() - 10
        if level <= 0:
            level = 100
        self.set_battery_level(level)
        return self.battery.level.value

# Start advertising on hci0
periph = Peripheral(WhadDevice.create('hci1'), profile=BatteryDevice())
periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
    AdvCompleteLocalName(b'BatteryDevice'),
    AdvFlagsField()
))

# Wait for user to press a key
input('Press a key to stop...')
