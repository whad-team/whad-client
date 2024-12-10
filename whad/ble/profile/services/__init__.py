"""WHAD BLE GATT default services

This module provides different default GATT services as defined in
* https://www.bluetooth.com/specifications/specs/battery-service/
* https://www.bluetooth.com/specifications/specs/device-information-service/
"""
from whad.ble.profile.services.bas import BatteryService
from whad.ble.profile.services.dis import DeviceInformationService

__all__ = [
    "BatteryService",
    "DeviceInformationService"
]