"""
Example of an emulated BLE peripheral exposing a Battery service with a
single characteristic (battery level).

Each time the battery level characteristic value is read, this level decreases
by 10%.
"""

from whad.device import WhadDevice
from whad.ble import (
    Peripheral, AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField, Profile, read,
    BatteryService,
)

class BatteryDevice(Profile):
    """Device exposing a battery service
    """

    battery = BatteryService()

    @read(battery.level)
    def on_battery_level_read(self, offset, length):
        level = self.battery.percentage - 10
        if level <= 0:
            level = 100
        self.battery.percentage = level
        return self.battery.level.value

# Start advertising on hci0
periph = Peripheral(WhadDevice.create('hci1'), profile=BatteryDevice())
periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
    AdvCompleteLocalName(b'BatteryDevice'),
    AdvFlagsField()
))

# Wait for user to press a key
input('Press a key to stop...')
