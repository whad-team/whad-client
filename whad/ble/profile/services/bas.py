"""Bluetooth Low Energy Battery Service Profile
"""
from struct import pack, unpack
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic

class BatteryService(object):
    """Battery Service Profile

    This service implements the BLE Battery Service as described in the spec.
    """

    battery = PrimaryService(
        uuid = UUID(0x180f),
        level = Characteristic(
            uuid = UUID(0x2A19),
            permissions = ['read'],
            notify = True,
            indicate = True,
            value=pack('B', 100)
        )
    )

    def set_battery_level(self, level: int):
        """Set battery level
        """
        if level >= 0 and level<=100:
            self.battery.level.value = pack('B', level)

    def get_battery_level(self):
        """Return battery level
        """
        return unpack('B', self.battery.level.value)[0]