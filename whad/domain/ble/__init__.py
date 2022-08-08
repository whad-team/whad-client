"""
Bluetooth Low Energy
"""
from time import time
from whad.domain.ble.stack.gatt import GattClient, GattServer
from whad.helpers import message_filter
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import BleDirection, BleAdvType, Connected
from whad.domain.ble.stack import BleStack
from scapy.layers.bluetooth4LE import BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP
from whad.domain.ble.bdaddr import BDAddress
from whad.domain.ble.profile.device import PeripheralDevice
from whad.domain.ble.profile import GenericProfile
from whad.domain.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvDataField, AdvCompleteLocalName, \
    AdvManufacturerSpecificData, AdvShortenedLocalName, AdvTxPowerLevel, AdvDataFieldListOverflow
from whad.domain.ble.sniffing import SynchronizedConnection, SnifferConfiguration
from whad.domain.ble.connector import BLE, Central, Peripheral, Sniffer, Hijacker, Injector