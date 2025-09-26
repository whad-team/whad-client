"""WHAD Protocol BLE mode messages abstraction layer.
"""
from typing import Optional, Tuple

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import CentralModeCmd, StartCmd as BleStartCmd, StopCmd as BleStopCmd
from whad.hub.message import pb_bind, PbFieldBytes, PbMessageWrapper, PbFieldBool, PbFieldInt
from whad.hub.ble import BleDomain, BleAdvType, ChannelMap

@pb_bind(BleDomain, 'scan_mode', 1)
class ScanMode(PbMessageWrapper):
    """BLE scan mode message class
    """
    active = PbFieldBool('ble.scan_mode.active_scan')

@pb_bind(BleDomain, 'adv_mode', 1)
class AdvMode(PbMessageWrapper):
    """BLE advertising mode message class
    """
    adv_data = PbFieldBytes('ble.adv_mode.adv_data')
    scanrsp_data = PbFieldBytes('ble.adv_mode.scanrsp_data')

    # Protocol version 2 use 0x20 for both min and max values, we reflect this here.
    adv_type = BleAdvType.ADV_IND
    channel_map = ChannelMap([37, 38, 39]).value
    inter_min = 0x20
    inter_max = 0x20

@pb_bind(BleDomain, 'adv_mode', version=3)
class AdvModeV3(PbMessageWrapper):
    """
    Ble advertising mode message class with more control over
    advertising parameters:
      - advertising type
      - channel map
      - minimal and maximal advertising interval values

    Important note:
      - `scan_data` field has been renamed to `adv_data`

    """
    adv_data = PbFieldBytes('ble.adv_mode.adv_data')
    scanrsp_data = PbFieldBytes('ble.adv_mode.scanrsp_data')
    adv_type = PbFieldInt('ble.adv_mode.adv_type')
    channel_map = PbFieldBytes('ble.adv_mode.channel_map')
    inter_min = PbFieldInt('ble.adv_mode.inter_min')
    inter_max = PbFieldInt('ble.adv_mode.inter_max')

@pb_bind(BleDomain, 'central_mode', 1)
class CentralMode(PbMessageWrapper):
    """BLE advertising mode message class
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.ble.central_mode.CopyFrom(CentralModeCmd())

@pb_bind(BleDomain, 'periph_mode', 1)
class PeriphMode(PbMessageWrapper):
    """BLE advertising mode message class
    """
    adv_data = PbFieldBytes('ble.periph_mode.adv_data')
    scanrsp_data = PbFieldBytes('ble.periph_mode.scanrsp_data')

    # Default fields required by inherited classes (versions greater than 1)
    adv_type = BleAdvType.ADV_IND
    inter_min = 0x20
    inter_max = 0x20
    channel_map = ChannelMap([37, 38, 39]).value

    def get_adv_data(self) -> Optional[bytes]:
        """Retrieve advertising data."""
        return self.get_field_value(PeriphMode.adv_data)

    def get_scan_data(self) -> Optional[bytes]:
        """Retrieve scan response data, if set."""
        return self.get_field_value(PeriphMode.scanrsp_data)

@pb_bind(BleDomain, 'periph_mode', version=3)
class PeriphModeV3(PeriphMode):
    """BLE advertising mode message class, improved starting from version 3
    """
    adv_data = PbFieldBytes('ble.periph_mode.adv_data')
    scanrsp_data = PbFieldBytes('ble.periph_mode.scanrsp_data')
    adv_type = PbFieldInt('ble.periph_mode.adv_type')
    channel_map = PbFieldBytes('ble.periph_mode.channel_map')
    inter_min = PbFieldInt('ble.periph_mode.inter_min')
    inter_max = PbFieldInt('ble.periph_mode.inter_max')

    def get_adv_data(self) -> Optional[bytes]:
        """Retrieve advertising data."""
        return self.get_field_value(PeriphModeV3.adv_data)

    def get_scan_data(self) -> Optional[bytes]:
        """Retrieve scan response data, if set."""
        return self.get_field_value(PeriphModeV3.scanrsp_data)

    def get_adv_type(self) -> Optional[BleAdvType]:
        """Retrieve the advertisement type."""
        return self.get_field_value(PeriphModeV3.adv_type)

    def get_channel_map(self) -> Optional[ChannelMap]:
        """Retrieve channel map."""
        # Read value from message
        value = self.get_field_value(PeriphModeV3.channel_map)
        if value is not None and isinstance(value, bytes):
            return ChannelMap.from_bytes(value)
        return None

    def get_interval(self) -> Optional[Tuple[int, int]]:
        """Retrieve advertising interval min/max values."""
        inter_min = self.get_field_value(PeriphModeV3.inter_min)
        inter_max = self.get_field_value(PeriphModeV3.inter_max)
        if inter_min is not None and inter_max is not None:
            if inter_min in range(0x20, 0x4001) and inter_max in range(0x20, 0x4001):
                return (inter_min, inter_max)
        return None

@pb_bind(BleDomain, 'start', 1)
class BleStart(PbMessageWrapper):
    """BLE start mode message class
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.ble.start.CopyFrom(BleStartCmd())

@pb_bind(BleDomain, 'stop', 1)
class BleStop(PbMessageWrapper):
    """BLE stop mode message class
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.ble.stop.CopyFrom(BleStopCmd())

@pb_bind(BleDomain, 'encryption', 1)
class SetEncryption(PbMessageWrapper):
    """BLE SetEncryption message class
    """
    conn_handle = PbFieldInt('ble.encryption.conn_handle')
    enabled = PbFieldBool('ble.encryption.enabled')
    ll_key = PbFieldBytes('ble.encryption.ll_key')
    ll_iv = PbFieldBytes('ble.encryption.ll_iv')
    key = PbFieldBytes('ble.encryption.key')
    rand = PbFieldBytes('ble.encryption.rand')
    ediv = PbFieldBytes('ble.encryption.ediv')
