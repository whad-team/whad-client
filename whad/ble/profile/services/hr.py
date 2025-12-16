"""GAP Heart Rate Service
"""
from whad.ble.profile.attribute import UUID
from whad.ble.profile.service import StandardService
from whad.ble.profile.characteristic import Characteristic

class HeartRateService(StandardService):
    """Heart Rate service version 1.0 as defined in
    [specification](https://www.bluetooth.com/specifications/specs/html/?src=HRS_v1.0/out/en/index-en.html).
    """

    _uuid = UUID(0x180d)

    measurement = Characteristic(
        UUID(0x2a37),
        properties=Characteristic.NOTIFY,
        required=True
    )

    body_sensor_location = Characteristic(
        UUID(0x2a38),
        properties=Characteristic.READ
    )

    control_point = Characteristic(
        UUID(0x2a39),
        properties=Characteristic.WRITE
    )

