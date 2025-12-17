"""
Bluetooth Low Energy
"""
import re

from whad.ble.stack.gatt import GattClient, GattServer
from whad.common.triggers import ManualTrigger, ConnectionEventTrigger, ReceptionTrigger
from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble.chanmap import ChannelMap

from whad.ble.profile.attribute import UUID
from whad.ble.profile import (
    GenericProfile, Profile, Characteristic, Descriptor, ClientCharacteristicConfig,
    ReportReference, UserDescription, Service, PrimaryService, SecondaryService,
    IncludeService, read, write, written, subscribed, unsubscribed,

    CharacteristicDescriptor, CharacteristicUserDescriptionDescriptor, ReportReferenceDescriptor
)
from whad.ble.profile.advdata import (
    AdvDataFieldList, AdvFlagsField, AdvDataField, AdvCompleteLocalName,
    AdvManufacturerSpecificData, AdvShortenedLocalName, AdvTxPowerLevel,
    AdvDataFieldListOverflow, AdvURI, AdvLeRole, AdvAppearance, AdvUuid128List,
    AdvUuid16List, AdvDataError
)
from whad.ble.profile.services import BatteryService, DeviceInformationService, GapService, HeartRateService
from whad.ble.connector.base import BLE
from whad.ble.connector import (
    Central, Peripheral, Sniffer, Hijacker, Injector, Scanner, PeripheralClient, Scanner
)
from whad.ble.utils.phy import PHYS

def is_bdaddr_valid(bd_addr):
    return re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$',bd_addr)

__all__ = [
    # Basic types for BLE
    'BLE',
    'ChannelMap',
    'GattClient',
    'GattServer',
    'BDAddress',
    'UUID',
    'Profile',
    'read',
    'write',
    'written',
    'subscribed',
    'unsubscribed',
    'BatteryService',
    'GapService',
    'HeartRateService',
    'DeviceInformationService',
    'Characteristic',
    'Descriptor',
    'ClientCharacteristicConfig',
    'ReportReference',
    'UserDescription',
    'Service',
    'PrimaryService',
    'SecondaryService',
    'IncludeService',

    # Advertising data classes
    'AdvDataFieldList',
    'AdvFlagsField',
    'AdvDataField',
    'AdvCompleteLocalName',
    'AdvManufacturerSpecificData',
    'AdvShortenedLocalName',
    'AdvTxPowerLevel',
    'AdvDataFieldListOverflow',
    'AdvURI',
    'AdvLeRole',
    'AdvAppearance',
    'AdvUuid128List',
    'AdvUuid16List',
    'AdvDataError',

    # Connectors
    'Central',
    'Peripheral',
    'PeripheralClient',
    'Sniffer',
    'Hijacker',
    'Injector',
    'Scanner',

    # Misc.
    'PHYS',
    'ConnectionEventTrigger',
    'ManualTrigger',
    'ReceptionTrigger',

    # Old classes to remove later
    'GenericProfile',
    'CharacteristicDescriptor',
    'CharacteristicUserDescriptionDescriptor',
    'ReportReferenceDescriptor',
]
