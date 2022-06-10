"""
Bluetooth Low Energy
"""

from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.device.uart import UartDevice
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import StartCmd, StopCmd, ScanMode, Start, Stop, BleAdvType

from scapy.layers.bluetooth4LE import *


class BLE(WhadDeviceConnector):
    """
    BLE protocol connector.

    This connector drives a BLE-capable device with BLE-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    # correlation table
    SCAPY_CORR_ADV = {
        BleAdvType.ADV_IND: BTLE_ADV_IND,
        BleAdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
        BleAdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
        BleAdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
        BleAdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
    }

    def __init__(self, device=None):
        super().__init__(device)

        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Check device supports BLE
        if not self.device.has_domain(WhadDomain.BtLE):
            raise UnsupportedDomain()

    def can_scan(self):
        """
        Determine if the device implements a scanner mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << ScanMode))>0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def enable_scan_mode(self, active=False):
        msg = Message()
        msg.ble.scan_mode.active_scan = active
        resp = self.send_message(msg, message_filter('generic', 'cmd_result'))

    def start(self):
        # Enable scanner
        msg = Message()
        msg.ble.start.CopyFrom(StartCmd())
        resp = self.send_message(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def stop(self):
        # Disable scanner
        msg = Message()
        msg.ble.stop.CopyFrom(StopCmd())
        resp = self.send_message(msg, message_filter('generic', 'cmd_result'))

    def on_generic_msg(self, message):
        pass

    def on_discovery_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        if domain == 'ble':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'adv_pdu':
                if message.adv_pdu.adv_type in BLE.SCAPY_CORR_ADV:
                    self.on_adv_pdu(
                        BLE.SCAPY_CORR_ADV[message.adv_pdu.adv_type](
                            bytes(message.adv_pdu.bd_address) + bytes(message.adv_pdu.adv_data)
                        )
                    )

    def on_adv_pdu(self, packet):
        pass
    

class Scanner(BLE):
    """
    BLE Observer interface for compatible WHAD device.
    """

    def __init__(self, device):
        super().__init__(device)

        # Check device accept scanning mode
        if not self.can_scan():
            raise UnsupportedCapability('Scan')
        else:
            self.stop()
            self.enable_scan_mode(True)

    def discover_devices(self):
        """
        Listen incoming messages and yield advertisements.
        """
        # correlation table
        scapy_corr_adv = {
            BleAdvType.ADV_IND: BTLE_ADV_IND,
            BleAdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
            BleAdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
            BleAdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
            BleAdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
        }

        while True:
            messages = self.process(keep=message_filter('ble', 'adv_pdu'))
            for message in messages:
                # Convert message from rebuilt PDU
                if message.ble.adv_pdu.adv_type in scapy_corr_adv:
                    yield scapy_corr_adv[message.ble.adv_pdu.adv_type](
                        bytes(message.ble.adv_pdu.bd_address) + bytes(message.ble.adv_pdu.adv_data)
                    )

