"""Generic Access Profile service

TODO: Add appearance interpretation.
"""

from whad.ble.profile.attribute import UUID
from whad.ble.profile.service import StandardService
from whad.ble.profile.characteristic import Characteristic

class GapService(StandardService):

    _uuid = UUID(0x1800)

    device_name = Characteristic(
        UUID(0x2a00),
        properties=Characteristic.READ,
        required=True,
        value=b''
    )

    appearance = Characteristic(
       UUID(0x2a01),
        properties=Characteristic.READ,
        required=True,
        value=b'\x00\x00' # Unknown by default
    )

    preferred_conn_params = Characteristic(
        UUID(0x2a04),
        properties=Characteristic.READ,
        value=b'\x06\x00\xa0\x00\x06\x00\xe8\x03'
    )

    @property
    def devicename(self) -> str:
        return self.device_name.value.decode('utf-8')
