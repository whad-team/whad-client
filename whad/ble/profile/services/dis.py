"""Bluetooth Low Energy Device Information Service Profile
"""
from whad.ble.profile.attribute import UUID
from whad.ble.profile.service import StandardService
from whad.ble.profile.characteristic import Characteristic

class DeviceInformationService(StandardService):
    """Device Information Service version 1.2 as defined in
    `specification <https://www.bluetooth.com/specifications/specs/html/?src=DIS_v1.2/out/en/index-en.html>`_.
    """
    _uuid = UUID(0x180a)

    manufacturer= Characteristic(
        UUID(0x2A29),
        permissions=['read'],
    )
    model_number=Characteristic(
        UUID(0x2A24),
        permissions=['read']
    )
    serial_number=Characteristic(
        UUID(0x2A25),
        permissions=['read']
    )
    hw_revision=Characteristic(
        UUID(0x2A27),
        permissions=['read']
    )
    fw_revision=Characteristic(
        UUID(0x2A26),
        permissions=['read']
    )
    sw_revision=Characteristic(
        UUID(0x2A28),
        permissions=['read']
    )
    system_id=Characteristic(
        UUID(0x2A23),
        permissions=['read']
    )
    ieee_rcdl=Characteristic(
        UUID(0x2A2A),
        permissions=['read']
    )
    pnp_id=Characteristic(
        UUID(0x2A50),
        permissions=['read']
    )
    udi=Characteristic(
        UUID(0x2BFF),
        permissions = ['read'],
    )

