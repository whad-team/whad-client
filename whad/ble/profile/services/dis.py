"""Bluetooth Low Energy Device Information Service Profile
"""
from whad.ble.profile.attribute import UUID
from whad.ble.profile.service import PrimaryService
from whad.ble.profile.characteristic import Characteristic

class DeviceInformationService(PrimaryService):
    """Define Device Information Service
    """
    _uuid = UUID(0x180a)

    manufacturer= Characteristic(
        uuid=UUID(0x2A29),
        permissions=['read'],
    )
    model_number=Characteristic(
        uuid=UUID(0x2A24),
        permissions=['read']
    )
    serial_number=Characteristic(
        uuid=UUID(0x2A25),
        permissions=['read']
    )
    hw_revision=Characteristic(
        uuid=UUID(0x2A27),
        permissions=['read']
    )
    fw_revision=Characteristic(
        uuid=UUID(0x2A26),
        permissions=['read']
    )
    sw_revision=Characteristic(
        uuid=UUID(0x2A28),
        permissions=['read']
    )
    system_id=Characteristic(
        uuid=UUID(0x2A23),
        permissions=['read']
    )
    ieee_rcdl=Characteristic(
        uuid=UUID(0x2A2A),
        permissions=['read']
    )
    pnp_id=Characteristic(
        uuid=UUID(0x2A50),
        permissions=['read']
    )

