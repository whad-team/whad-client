"""WHAD Protocol BLE pdu messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import CentralModeCmd
from whad.protocol.hub import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool
from whad.protocol.hub.ble import BleDomain

@pb_bind(BleDomain, "set_adv_data", 1)
class SetAdvData(PbMessageWrapper):
    """BLE set advertising data message class
    """
    scan_data = PbFieldBytes("ble.set_adv_data.scan_data")
    scanrsp_data = PbFieldBytes("ble.set_adv_data.scanrsp_data")

@pb_bind(BleDomain, "send_raw_pdu", 1)
class SendRawPdu(PbMessageWrapper):
    """BLE send raw PDU message class
    """
    direction = PbFieldInt("ble.send_raw_pdu.direction")
    conn_handle = PbFieldInt("ble.send_raw_pdu.conn_handle")
    access_address = PbFieldInt("ble.send_raw_pdu.access_address")
    pdu = PbFieldBytes("ble.send_raw_pdu.pdu")
    crc = PbFieldInt("ble.send_raw_pdu.crc")
    encrypt = PbFieldBool("ble.send_raw_pdu.encrypt")

@pb_bind(BleDomain, "send_pdu", 1)
class SendPdu(PbMessageWrapper):
    """BLE send PDU message class
    """
    direction = PbFieldInt("ble.send_pdu.direction")
    conn_handle = PbFieldInt("ble.send_pdu.conn_handle")
    pdu = PbFieldBytes("ble.send_pdu.pdu")
    encrypt = PbFieldBool("ble.send_pdu.encrypt")

@pb_bind(BleDomain, "adv_pdu", 1)
class AdvPduReceived(PbMessageWrapper):
    """BLE advertising PDU received message class
    """
    adv_type = PbFieldInt("ble.adv_pdu.adv_type")
    rssi = PbFieldInt("ble.adv_pdu.rssi")
    bd_address = PbFieldBytes("ble.adv_pdu.bd_address")
    adv_data = PbFieldBytes("ble.adv_pdu.adv_data")
    addr_type = PbFieldInt("ble.adv_pdu.addr_type")


@pb_bind(BleDomain, "pdu", 1)
class PduReceived(PbMessageWrapper):
    """BLE PDU received message class
    """
    direction = PbFieldInt("ble.pdu.direction")
    pdu = PbFieldBytes("ble.pdu.pdu")
    conn_handle = PbFieldInt("ble.pdu.conn_handle")
    processed = PbFieldBool("ble.pdu.processed")
    decrypted = PbFieldBool("ble.pdu.decrypted")

@pb_bind(BleDomain, "raw_pdu", 1)
class RawPduReceived(PbMessageWrapper):
    """BLE raw PDU received message class
    """
    direction = PbFieldInt("ble.raw_pdu.direction")
    channel = PbFieldInt("ble.raw_pdu.channel")
    rssi = PbFieldInt("ble.raw_pdu.rssi")
    timestamp = PbFieldInt("ble.raw_pdu.timestamp")
    relative_timestamp = PbFieldInt("ble.raw_pdu.relative_timestamp")
    crc_validity = PbFieldBool("ble.raw_pdu.crc_validity")
    access_address = PbFieldInt("ble.raw_pdu.access_address")
    pdu = PbFieldBytes("ble.raw_pdu.pdu")
    crc = PbFieldInt("ble.raw_pdu.crc")
    conn_handle = PbFieldInt("ble.raw_pdu.conn_handle")
    processed = PbFieldBool("ble.raw_pdu.processed")
    decrypted = PbFieldBool("ble.raw_pdu.decrypted")

@pb_bind(BleDomain, "injected", 1)
class Injected(PbMessageWrapper):
    """BLE PDU injected notification message class
    """
    success = PbFieldBool("ble.injected.success")
    access_address = PbFieldInt("ble.injected.access_address")
    injection_attempts = PbFieldInt("ble.injected.injection_attempts")
