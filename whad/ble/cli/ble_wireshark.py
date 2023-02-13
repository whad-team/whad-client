"""Bluetooth Low Energy wireshark monitoring tool

This utility must be chained between two command-line tools to
monitor BLE packets going back and forth.
"""
import logging
import struct
from time import sleep
from threading import Thread
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL

from whad.protocol.ble.ble_pb2 import BleDirection, CentralMode, SetEncryptionCmd, StartCmd, StopCmd, \
    ScanMode, Start, Stop, BleAdvType, ConnectTo, CentralModeCmd, PeripheralMode, \
    PeripheralModeCmd, SetBdAddress, SendPDU, SniffAdv, SniffConnReq, HijackMaster, \
    HijackSlave, HijackBoth, SendRawPDU, AdvModeCmd, BleAdvType, SniffAccessAddress, \
    SniffAccessAddressCmd, SniffActiveConn, SniffActiveConnCmd, BleAddrType, ReactiveJam, \
    JamAdvOnChannel, PrepareSequence, PrepareSequenceCmd, TriggerSequence, DeleteSequence
from whad.cli.app import CommandLineApp
from whad.ble.connector import Central
from whad.common.monitors import WiresharkMonitor
from whad.device.unix import UnixSocketProxy, UnixSocketConnector
from whad.ble.metadata import generate_ble_metadata, BLEMetadata

logger = logging.getLogger(__name__)


class BleUnixSocketConnector(UnixSocketConnector):
    """
    Specific connector for BLE protocol over UnixSocket.
    """

    # correlation table
    SCAPY_CORR_ADV = {
        BleAdvType.ADV_IND: BTLE_ADV_IND,
        BleAdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
        BleAdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
        BleAdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
        BleAdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
    }

    def __init__(self, device, path=None):
        """Initialize our Unix Socket connector
        """
        super().__init__(device, path)

    def on_msg_sent(self, message):
        if message.WhichOneof('msg') == 'discovery':
            return
        elif message.WhichOneof('msg') == 'generic':
            return
        else:
            domain = message.WhichOneof('msg')
            if domain is not None:
                logger.info('message concerns domain `%s`, forward to domain-specific handler' % domain)
                if domain == 'ble':
                    message = getattr(message,domain)
                    msg_type = message.WhichOneof('msg')
                    if msg_type == 'send_pdu':
                        packet = self._build_scapy_packet_from_sent_message(message, msg_type)

                    elif msg_type == 'send_raw_pdu':
                        packet = self._build_scapy_packet_from_sent_message(message, msg_type)

    def on_domain_msg(self, domain, message):
        if domain == 'ble':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'adv_pdu':
                packet = self._build_scapy_packet_from_recvd_message(message, msg_type)
                #self.on_adv_pdu(packet)

            elif msg_type == 'pdu':
                packet = self._build_scapy_packet_from_recvd_message(message, msg_type)

            elif msg_type == 'raw_pdu':
                packet = self._build_scapy_packet_from_recvd_message(message, msg_type)

            
    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        formatted_packet = packet
        if BTLE not in packet:
            if BTLE_ADV in packet:
                formatted_packet = BTLE(access_addr=0x8e89bed6)/packet
            elif BTLE_DATA in packet:
                # We are forced to use a pseudo access address for connections in this case.
                formatted_packet = BTLE(access_addr=0x11223344) / packet

        timestamp = None
        if hasattr(packet, "metadata"):
            header, timestamp = packet.metadata.convert_to_header()
            formatted_packet = header / formatted_packet
        else:
            header = BTLE_RF()
            formatted_packet = header / formatted_packet

        return formatted_packet, timestamp

    def _build_scapy_packet_from_sent_message(self, message, msg_type):
        try:
            if msg_type == 'send_raw_pdu':
                packet = BTLE(bytes(struct.pack("I", message.send_raw_pdu.access_address)) + bytes(message.raw_pdu.pdu) + bytes(struct.pack(">I", message.send_raw_pdu.crc)[1:]))
                packet.metadata = generate_ble_metadata(message, msg_type)

                self._signal_packet_reception(packet)
                return packet

            elif msg_type == 'send_pdu':
                packet = BTLE_DATA(message.send_pdu.pdu)
                packet.metadata = generate_ble_metadata(message, msg_type)

                self._signal_packet_reception(packet)
                return packet

        except AttributeError as err:
            print(err)
            return None

    def _build_scapy_packet_from_recvd_message(self, message, msg_type):
        try:
            if msg_type == 'adv_pdu':
                if message.adv_pdu.adv_type in BleUnixSocketConnector.SCAPY_CORR_ADV:
                    data = bytes(message.adv_pdu.adv_data)

                    packet = BTLE_ADV()/BleUnixSocketConnector.SCAPY_CORR_ADV[message.adv_pdu.adv_type](
                            bytes(message.adv_pdu.bd_address) + data
                        )
                    packet.metadata = generate_ble_metadata(message, msg_type)
                    self._signal_packet_reception(packet)

                    return packet

            elif msg_type == 'raw_pdu':
                packet = BTLE(bytes(struct.pack("I", message.raw_pdu.access_address)) + bytes(message.raw_pdu.pdu) + bytes(struct.pack(">I", message.raw_pdu.crc)[1:]))
                packet.metadata = generate_ble_metadata(message, msg_type)

                self._signal_packet_reception(packet)
                return packet

            elif msg_type == 'pdu':
                packet = BTLE_DATA(message.pdu.pdu)
                packet.metadata = generate_ble_metadata(message, msg_type)

                self._signal_packet_reception(packet)
                return packet

        except AttributeError as err:
            print(err)
            return None


class BleWiresharkApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy wireshark monitoring',
            interface=True,
            commands=False
        )


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        self.pre_run()

        # We need to have an interface specified
        if self.interface is not None:
            # Make sure we are placed between two piped tools
            if self.is_stdout_piped() and self.is_stdin_piped():
                # Start wireshark monitoring
                self.monitor()
            else:
                self.error('Tool must be piped to another WHAD tool.')
        else:
            self.error('<i>ble-wireshark</i> must be placed between two WHAD CLI tools to monitor traffic.')

        # Launch post-run tasks
        self.post_run()

    def monitor(self):
        """Start a new Unix socket server and forward all messages
        """
        # Create our proxy
        proxy = UnixSocketProxy(self.interface, self.args.__dict__, BleUnixSocketConnector)

        # Attach a wireshark monitor to our proxy
        monitor = WiresharkMonitor()
        monitor.attach(proxy.connector)
        monitor.start()
        sleep(2)
        proxy.start()
        proxy.join()
        

def ble_wireshark_main():
    app = BleWiresharkApp()
    app.run()
