"""Bluetooth Low Energy Battery Service Profile
"""
from struct import pack, unpack
from whad.ble.profile.attribute import UUID
from whad.ble.profile.characteristic import Characteristic, Properties
from whad.ble.profile.service import StandardService

class BatteryService(StandardService):
    """Battery Service Profile

    This service implements the BLE Battery Service as described in the spec.
    """
    _uuid = UUID(0x180f)

    level = Characteristic(
        uuid = UUID(0x2A19),
        properties = Properties.READ | Properties.NOTIFY,
        required = True,
        value=pack('B', 100),
    )

    def __init__(self, handle: int = 0, end_handle: int = 0):
        super().__init__(
            handle,
            end_handle
        )

    @property
    def percentage(self) -> int:
        """Battery level as percentage."""
        return unpack('B', self.level.value)[0]

    @percentage.setter
    def percentage(self, level: int):
        """Set battery level."""
        if 0 <= level <=100:
            # level property is dynamically created by the GATT
            # profile where this class is used.
            #
            # pylint: disable-next=E1101
            self.level.value = pack('B', level)

