"""Bluetooth Low Energy Human Interface Device Service Profile

Still a work in progress, but looks cool :D
"""

from whad.ble.utils.att import UUID
from whad.ble.profile import PrimaryService, Characteristic, CharacteristicDescriptor
from whad.ble.profile.services import BatteryService, DeviceInformationService

class ReportReferenceDescriptor(CharacteristicDescriptor):

    def __init__(self, characteristic, handle=None, notify=False, indicate=False):
        """Instanciate a Client Characteristic Configuration Descriptor

        :param bool notify: Set to True to get the corresponding characteristic notified on change
        :param bool indicate: Set to True to get the corresponding characteristic indicated on change
        """
        super().__init__(
            characteristic,
            uuid=UUID(0x2908),
            handle=handle,
            value=b''
        )

class HidMouseService(BatteryService, DeviceInformationService):
    """Bluetooth Low Energy HID Mouse Service
    """

    hid = PrimaryService(
        uuid=UUID(0x1812),

        # Mandatory characteristics
        info=Characteristic(
            uuid=UUID(0x2A4A),
            permissions=['read'],
        ),
        control_point=Characteristic(
            uuid=UUID(0x2A4C),
            permissions=['write_without_response']
        ),
        report_map=Characteristic(
            uuid=UUID(0x2A4B),
            permissions=['read']
        ),

        # Mouse-specific characteristics

    )