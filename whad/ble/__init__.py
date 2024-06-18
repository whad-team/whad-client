"""
Bluetooth Low Energy
"""
import re
from time import time
from whad.ble.stack.gatt import GattClient, GattServer
from whad.helpers import message_filter
from whad.common.triggers import ManualTrigger, ConnectionEventTrigger, ReceptionTrigger
from whad.exceptions import UnsupportedDomain, UnsupportedCapability

from whad.protocol.ble.ble_pb2 import BleDirection, BleAdvType, Connected
from whad.ble.stack import BleStack
from scapy.layers.bluetooth4LE import BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP,\
    BTLE_ADV
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.profile.device import PeripheralDevice
from whad.ble.profile import GenericProfile
from whad.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvDataField, AdvCompleteLocalName, \
    AdvManufacturerSpecificData, AdvShortenedLocalName, AdvTxPowerLevel, AdvDataFieldListOverflow, AdvDataError
from whad.ble.connector import BLE, Central, Peripheral, Sniffer, Hijacker, Injector, Scanner, PeripheralClient
from whad.ble.utils.phy import PHYS
from whad.scapy.layers.bt_mesh import BTMesh_Unprovisioned_Device_Beacon, EIR_BTMesh_Beacon

def is_bdaddr_valid(bd_addr):
    return re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$',bd_addr)

__all__ = [
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
    'ReceptionTrigger'
]
