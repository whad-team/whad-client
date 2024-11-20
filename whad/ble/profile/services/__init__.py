"""Default GATT profile services.
"""
from whad.ble.profile.services.bas import BatteryService
from whad.ble.profile.services.dis import DeviceInformationService

__all__ = [
    "BatteryService",
    "DeviceInformationService"
]
