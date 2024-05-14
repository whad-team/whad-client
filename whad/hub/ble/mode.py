"""WHAD Protocol BLE mode messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import CentralModeCmd, StartCmd as BleStartCmd, StopCmd as BleStopCmd
from whad.hub.message import pb_bind, PbFieldBytes, PbMessageWrapper, PbFieldBool, PbFieldInt
from whad.hub.ble import BleDomain

@pb_bind(BleDomain, 'scan_mode', 1)
class ScanMode(PbMessageWrapper):
    """BLE scan mode message class
    """
    active = PbFieldBool('ble.scan_mode.active_scan')

@pb_bind(BleDomain, 'adv_mode', 1)
class AdvMode(PbMessageWrapper):
    """BLE advertising mode message class
    """
    scan_data = PbFieldBytes('ble.adv_mode.scan_data')
    scanrsp_data = PbFieldBytes('ble.adv_mode.scanrsp_data')

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
    scan_data = PbFieldBytes('ble.periph_mode.scan_data')
    scanrsp_data = PbFieldBytes('ble.periph_mode.scanrsp_data')


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
