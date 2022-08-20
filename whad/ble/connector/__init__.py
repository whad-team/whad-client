import struct
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP
from scapy.compat import raw

from whad.device import WhadDeviceConnector
from whad.protocol.ble.ble_pb2 import BleDirection, CentralMode, StartCmd, StopCmd, \
    ScanMode, Start, Stop, BleAdvType, ConnectTo, CentralModeCmd, PeripheralMode, \
    PeripheralModeCmd, SetBdAddress, SendPDU, SniffAdv, SniffConnReq, HijackMaster, \
    HijackSlave, HijackBoth, SendRawPDU, AdvModeCmd, BleAdvType, SniffAccessAddress, \
    SniffAccessAddressCmd
from whad.protocol.whad_pb2 import Message
from whad.protocol.generic_pb2 import ResultCode
from whad import WhadDomain, WhadCapability
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.ble.metadata import generate_ble_metadata, BLEMetadata
from whad.helpers import message_filter, bd_addr_to_bytes
from whad.ble.profile.advdata import AdvDataFieldList

# Logging
import logging
logger = logging.getLogger(__name__)

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
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        self.__ready = False
        super().__init__(device)

        # Capability cache
        self.__can_send = None
        self.__can_send_raw = None

        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Check device supports BLE
        if not self.device.has_domain(WhadDomain.BtLE):
            raise UnsupportedDomain()
        else:
            self.__ready = True

    def close(self):
        self.device.close()

    def _build_scapy_packet_from_message(self, message, msg_type):
        try:
            if msg_type == 'adv_pdu':
                if message.adv_pdu.adv_type in BLE.SCAPY_CORR_ADV:
                    packet = BLE.SCAPY_CORR_ADV[message.adv_pdu.adv_type](
                            bytes(message.adv_pdu.bd_address) + bytes(message.adv_pdu.adv_data)
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

    def _build_message_from_scapy_packet(self, packet):
        msg = Message()
        direction = packet.metadata.direction
        connection_handle = packet.metadata.connection_handle

        self._signal_packet_transmission(packet)

        if BTLE in packet:
            msg.ble.send_raw_pdu.direction = direction
            msg.ble.send_raw_pdu.conn_handle = connection_handle
            msg.ble.send_raw_pdu.crc = BTLE(raw(packet)).crc # force the CRC to be generated if not provided
            msg.ble.send_raw_pdu.access_address = BTLE(raw(packet)).access_addr

            if BTLE_DATA in packet:
                msg.ble.send_raw_pdu.pdu = raw(packet[BTLE_DATA:])
            elif BTLE_ADV in packet:
                msg.ble.send_raw_pdu.pdu = raw(packet[BTLE_ADV:])
            else:
                return None

        else:
            msg.ble.send_pdu.direction = direction
            msg.ble.send_pdu.conn_handle = connection_handle

            if BTLE_DATA in packet:
                msg.ble.send_pdu.pdu = raw(packet[BTLE_DATA:])
            elif BTLE_ADV in packet:
                msg.ble.send_pdu.pdu = raw(packet[BTLE_ADV:])
            else:
                return None

        return msg

    def support_raw_pdu(self):
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(WhadDomain.BtLE)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw

    def can_send(self):
        """
        Determine if the device is able to send PDU
        """
        if self.__can_send is None:
            # Retrieve supported commands
            commands = self.device.get_domain_commands(WhadDomain.BtLE)
            self.__can_send = ((commands & (1 << SendPDU))>0 or (commands & (1 << SendRawPDU)))
        return self.__can_send

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

    def can_connect(self):
        """
        Determine if the device can establish a connection as central.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << ConnectTo))>0

    def can_be_central(self):
        """
        Determine if the device implements a central mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << CentralMode))>0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_be_peripheral(self):
        """
        Determine if the device implements a peripheral mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << PeripheralMode))>0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_discover_access_addresses(self):
        """
        Determine if the device implements an access addresses discovery mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << SniffAccessAddress)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )


    def can_sniff_advertisements(self):
        """
        Determine if the device implements an advertisements sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << SniffAdv)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )


    def can_sniff_new_connection(self):
        """
        Determine if the device implements a new connection sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << SniffConnReq)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_inject(self):
        """
        Determine if the device implements an injection mode.
        """
        capabilities = self.device.get_domain_capability(WhadDomain.BtLE)
        return self.can_send() and (capabilities & (1 << WhadCapability.Inject) > 0)


    def can_hijack_master(self):
        """
        Determine if the device implements a master hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << HijackMaster)) > 0

    def can_hijack_slave(self):
        """
        Determine if the device implements a slave hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << HijackSlave)) > 0

    def can_hijack_both(self):
        """
        Determine if the device implements a slave and master hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << HijackBoth)) > 0

    def hijack_master(self, access_address):
        """
        Hijack the master role.
        """
        if not self.can_hijack_master():
            raise UnsupportedCapability("Hijack")

        msg = Message()
        msg.ble.hijack_master.access_address = access_address
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def discover_access_addresses(self):
        """
        Discover access addresses.
        """
        if not self.can_discover_access_addresses():
            raise UnsupportedCapability("AccessAddressesDiscovery")

        msg = Message()
        msg.ble.sniff_aa.CopyFrom(SniffAccessAddressCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)



    def hijack_slave(self, access_address):
        """
        Hijack the slave role.
        """
        if not self.can_hijack_slave():
            raise UnsupportedCapability("Hijack")

        msg = Message()
        msg.ble.hijack_slave.access_address = access_address
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def hijack_both(self, access_address):
        """
        Hijack both roles.
        """
        if not self.can_hijack_both():
            raise UnsupportedCapability("Hijack")

        msg = Message()
        msg.ble.hijack_both.access_address = access_address
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def sniff_advertisements(self, channel=37, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy advertisements (on a single channel).
        """
        if not self.can_sniff_advertisements():
            raise UnsupportedCapability("Sniff")

        msg = Message()
        msg.ble.sniff_adv.channel = channel
        msg.ble.sniff_adv.bd_address = bd_addr_to_bytes(bd_address)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def sniff_new_connection(self, channel=37, show_advertisements=True, show_empty_packets=False, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy connection (from initiation).
        """
        if not self.can_sniff_new_connection():
            raise UnsupportedCapability("Sniff")

        msg = Message()
        msg.ble.sniff_connreq.show_advertisements = show_advertisements
        msg.ble.sniff_connreq.show_empty_packets = show_empty_packets
        msg.ble.sniff_connreq.channel = channel
        msg.ble.sniff_connreq.bd_address = bd_addr_to_bytes(bd_address)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def set_bd_address(self, bd_address):
        """
        Set Bluetooth Low Energy BD address.
        """
        # Ensure we can spoof BD address
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        if (commands & (1 << SetBdAddress))>0:
            msg = Message()
            msg.ble.set_bd_addr.bd_address = bd_addr_to_bytes(bd_address)
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return True
        else:
            return False

    def enable_scan_mode(self, active=False):
        """
        Enable Bluetooth Low Energy scanning mode.
        """
        msg = Message()
        msg.ble.scan_mode.active_scan = active
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def enable_central_mode(self):
        """
        Enable Bluetooth Low Energy central mode (acts as master).
        """
        msg = Message()
        msg.ble.central_mode.CopyFrom(CentralModeCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def enable_adv_mode(self, adv_data=None, scan_data=None):
        """
        Enable BLE advertising mode (acts as a broadcaster)
        """
        msg = Message()
        if adv_data is not None and isinstance(adv_data, bytes):
            msg.ble.adv_mode.scan_data = adv_data
        if scan_data is not None and isinstance(scan_data, bytes):
            msg.ble.adv_mode.scanrsp_data = scan_data
        if adv_data is None and scan_data is None:
            msg.ble.adv_mode.CopyFrom(AdvModeCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def enable_peripheral_mode(self, adv_data=None, scan_data=None):
        """
        Enable Bluetooth Low Energy peripheral mode (acts as slave).
        """
        # Build advertising data if required
        if isinstance(adv_data, AdvDataFieldList):
            adv_data = adv_data.to_bytes()
        if isinstance(scan_data, AdvDataFieldList):
            scan_data = scan_data.to_bytes()

        msg = Message()
        if adv_data is not None and isinstance(adv_data, bytes):
            msg.ble.periph_mode.scan_data = adv_data
        if scan_data is not None and isinstance(scan_data, bytes):
            msg.ble.periph_mode.scanrsp_data = scan_data
        if adv_data is None and scan_data is None:
            msg.ble.periph_mode.CopyFrom(PeripheralModeCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def connect_to(self, bd_addr):
        """
        Initiate a Bluetooth Low Energy connection.
        """
        msg = Message()
        msg.ble.connect.bd_address = bd_addr_to_bytes(bd_addr)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def start(self):
        """
        Start currently enabled mode.
        """
        msg = Message()
        msg.ble.start.CopyFrom(StartCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def disconnect(self, conn_handle):
        """Terminate a specific connection.

        :param int conn_handle: Connection handle of the connection to terminate.
        """
        msg = Message()
        msg.ble.disconnect.conn_handle = conn_handle
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        msg = Message()
        msg.ble.stop.CopyFrom(StopCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def process_messages(self):
        self.device.process_messages()

    def on_generic_msg(self, message):
        logger.info('generic message: %s' % message)
        pass

    def on_discovery_msg(self, message):
        logger.info('discovery message: %s' % message)
        pass


    def on_domain_msg(self, domain, message):
        if not self.__ready:
            return

        if domain == 'ble':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'adv_pdu':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_adv_pdu(packet)

            elif msg_type == 'pdu':
                if message.pdu.processed:
                    logger.info('[ble PDU log-only]')
                else:
                    packet = self._build_scapy_packet_from_message(message, msg_type)
                    self.on_pdu(packet)

            elif msg_type == 'raw_pdu':
                if message.raw_pdu.processed:
                    logger.info('[ble PDU log-only]')
                else:
                    # Extract scapy packet
                    packet = self._build_scapy_packet_from_message(message, msg_type)
                    self.on_raw_pdu(packet)

            elif msg_type == 'synchronized':
                self.on_synchronized(
                    access_address = message.synchronized.access_address,
                    crc_init = message.synchronized.crc_init,
                    hop_interval = message.synchronized.hop_interval,
                    hop_increment = message.synchronized.hop_increment,
                    channel_map = message.synchronized.channel_map
                )

            elif msg_type == 'desynchronized':
                self.on_desynchronized(access_address=message.desynchronized.access_address)

            elif msg_type == 'connected':
                self.on_connected(message.connected)

            elif msg_type == 'disconnected':
                self.on_disconnected(message.disconnected)


    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None, hop_interval=None, channel_map=None):
        pass

    def on_desynchronized(self, access_address=None):
        pass

    def on_adv_pdu(self, packet):
        logger.info('received an advertisement PDU')

    def on_connected(self, connection_data):
        logger.info('a connection has been established')
        logger.debug(
            'connection handle: %d' % connection_data.handle if connection_data.handle is not None else 0
        )

    def on_disconnected(self, disconnection_data):
        logger.info('a connection has been terminated')

    def on_raw_pdu(self, packet):

        if BTLE_ADV in packet:
            adv_pdu = packet[BTLE_ADV:]
            adv_pdu.metadata = packet.metadata
            self.on_adv_pdu(adv_pdu)

        elif BTLE_DATA in packet:
            conn_pdu = packet[BTLE_DATA:]
            conn_pdu.metadata = packet.metadata
            self.on_pdu(conn_pdu)

    def on_pdu(self, packet):

        if packet.LLID == 3:
            self.on_ctl_pdu(packet)
        elif packet.LLID in (1,2):
            self.on_data_pdu(packet)
        else:
            self.on_error_pdu(packet)

    def on_data_pdu(self, pdu):
        logger.info('received a data PDU')
        pass

    def on_ctl_pdu(self, pdu):
        logger.info('received a control PDU')
        pass

    def on_error_pdu(self, pdu):
        pass

    def send_ctrl_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6):
        """
        Send CTRL PDU
        """
        logger.info('send control PDU to connection (handle:%d)' % conn_handle)
        return self.send_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address)

    def send_data_pdu(self, data, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6):
        """
        Send data (L2CAP) PDU.
        """
        logger.info('send data PDU to connection (handle:%d)' % conn_handle)
        return self.send_pdu(data, conn_handle=conn_handle, direction=direction, access_address=access_address)

    def send_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6):
        """
        Send generic PDU.
        """
        if self.can_send():
            if self.support_raw_pdu():
                packet = BTLE(access_addr=access_address)/pdu
            else:
                packet = pdu
            packet.metadata = BLEMetadata()
            packet.metadata.direction = direction
            packet.metadata.connection_handle = conn_handle

            msg = self._build_message_from_scapy_packet(packet)

            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return (resp.generic.cmd_result.result == ResultCode.SUCCESS)
        else:
            return False

from whad.ble.connector.peripheral import Peripheral
from whad.ble.connector.central import Central
from whad.ble.connector.injector import Injector
from whad.ble.connector.hijacker import Hijacker
from whad.ble.connector.sniffer import Sniffer
from whad.ble.connector.scanner import Scanner
