"""
Bluetooth Low Energy
"""
import re

from whad.ble.stack.gatt import GattClient, GattServer
from whad.common.triggers import ManualTrigger, ConnectionEventTrigger, ReceptionTrigger
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.profile import GenericProfile
from whad.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvDataField, AdvCompleteLocalName, \
    AdvManufacturerSpecificData, AdvShortenedLocalName, AdvTxPowerLevel, AdvDataFieldListOverflow, AdvDataError
from whad.ble.connector.base import BLE
from whad.ble.connector import Central, Peripheral, Sniffer, Hijacker, Injector, Scanner, PeripheralClient, Advertiser
from whad.ble.utils.phy import PHYS

def is_bdaddr_valid(bd_addr):
    return re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$',bd_addr)

__all__ = [
    'BLE',
    'GattClient',
    'GattServer',
    'BDAddress',
    'GenericProfile',
    'AdvDataFieldList',
    'AdvFlagsField',
    'AdvDataField',
    'AdvCompleteLocalName',
    'AdvManufacturerSpecificData',
    'AdvShortenedLocalName',
    'AdvTxPowerLevel',
    'AdvDataFieldListOverflow',
    'AdvDataError',
    'Central',
    'Peripheral',
    'PeripheralClient',
    'Sniffer',
    'Hijacker',
    'Injector',
    'Scanner',
    'PHYS',
    'ConnectionEventTrigger',
    'ManualTrigger',
    'ReceptionTrigger',
    'Advertiser'
]
