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
from whad.cli.app import CommandLineDevicePipe, ApplicationError
from whad.ble.connector import Central
from whad.common.monitors import WiresharkMonitor
from whad.device.unix import UnixSocketProxy, UnixSocketConnector
from whad.ble.metadata import generate_ble_metadata, BLEMetadata
from whad.hub.ble import SendBlePdu, SendBleRawPdu, BleAdvPduReceived, BlePduReceived, \
    BleRawPduReceived

from whad.ble.connector.translator import BleMessageTranslator


logger = logging.getLogger(__name__)


class BleUnixSocketConnector(UnixSocketConnector):
    """
    Specific connector for BLE protocol over UnixSocket.
    """

    domain = 'ble'

    def __init__(self, device, path=None):
        """Initialize our Unix Socket connector
        """
        super().__init__(device, path)

    def on_msg_sent(self, message):
        """Incoming message processing.

        We only process BLE-related messages and especially PDU and raw PDU sending
        messages. If such a message is sent, we extract the encapsulated PDU and
        convert it to a raw packet that can be monitored in Wireshark.
        """
        if message.message_type == 'ble':
            # Convert message to packet
            if isinstance(message, SendBlePdu) or isinstance(message, SendBleRawPdu):
                #packet = self.__translator.from_message(message)
                packet = message.to_packet()
                if packet is not None:
                    self.monitor_packet_tx(packet)

    def on_domain_msg(self, domain, message):
        """Received a domain message, process only BLE messages.
        """
        packet = None
        if domain == 'ble':
            if isinstance(message, BleAdvPduReceived) or \
                isinstance(message, BlePduReceived) or \
                isinstance(message, BleRawPduReceived):
                #packet = self.__translator.from_message(message)
                packet = message.to_packet()

            if packet is not None:
                self.monitor_packet_rx(packet)


    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        return self.hub.ble.format(packet)

    def on_event(self, event):
        pass


class BleWiresharkApp(CommandLineDevicePipe):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy wireshark monitoring',
            interface=True,
            commands=False
        )
        self.proxy = None


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.input_interface is not None:
                # Make sure we are placed between two piped tools
                if self.is_stdout_piped() and self.is_stdin_piped():
                    # Start wireshark monitoring
                    self.monitor()
                else:
                    self.error('Tool must be piped to another WHAD tool.')
            else:
                self.error('<i>ble-wireshark</i> must be placed between two WHAD CLI tools to monitor traffic.')

        except KeyboardInterrupt:
            self.warning('ble-wireshark stopped (CTL-C)')
            if self.proxy is not None:
                self.proxy.stop()

        # Launch post-run tasks
        self.post_run()

    def monitor(self):
        """Start a new Unix socket server and forward all messages
        """
        # Create our proxy
        self.proxy = UnixSocketProxy(self.input_interface, self.args.__dict__, BleUnixSocketConnector)

        # Attach a wireshark monitor to our proxy
        monitor = WiresharkMonitor()
        monitor.attach(self.proxy.connector)
        monitor.start()
        self.proxy.start()
        self.proxy.join()
        

def ble_wireshark_main():
    try:
        app = BleWiresharkApp()
        app.run()
    except ApplicationError as err:
        err.show()

