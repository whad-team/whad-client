"""
Bluetooth Low Energy
"""
import re, struct
from time import sleep, time
from binascii import hexlify, unhexlify
from whad import WhadDomain, WhadCapability
from whad.metadata import generate_metadata, BLEMetadata
from whad.device import WhadDeviceConnector
from whad.domain.ble.stack.gatt import GattClient
from whad.helpers import message_filter, is_message_type, bd_addr_to_bytes
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import BleDirection, CentralMode, SendRawPDUCmd, StartCmd, StopCmd, \
    ScanMode, Start, Stop, BleAdvType, ConnectToCmd, ConnectTo, CentralModeCmd, PeripheralMode, \
    PeripheralModeCmd, SendPDUCmd, SetBdAddress, SendPDU, SniffAdv, SniffConnReq, HijackMaster, \
    HijackSlave, HijackBoth, SendRawPDU
from whad.domain.ble.stack import BleStack
from scapy.layers.bluetooth4LE import BTLE_CTRL, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP
from whad.domain.ble.device import PeripheralDevice
from whad.domain.ble.exceptions import InvalidBDAddressException


class BDAddress(object):

    def __init__(self, address):
        """Initialize BD address
        """
        if isinstance(address, str):
            if re.match('^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$', address) is not None:
                self.__value = unhexlify(address.replace(':',''))[::-1]
            elif re.match('[0-9a-fA-F]{12}$', address) is not None:
                self.__value = unhexlify(address)[::-1]
            else:
                raise InvalidBDAddressException
        else:
            raise InvalidBDAddressException

    def __str__(self):
        return ':'.join(['%02x' % b for b in self.__value[::-1]])

    def __repr__(self):
        return 'BDAddress(%s)' % str(self)

    @property
    def value(self):
        return self.__value

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

    def _build_scapy_packet_from_message(self, message, msg_type):
        try:
            if msg_type == 'adv_pdu':
                if message.adv_pdu.adv_type in BLE.SCAPY_CORR_ADV:
                    packet = BLE.SCAPY_CORR_ADV[message.adv_pdu.adv_type](
                            bytes(message.adv_pdu.bd_address) + bytes(message.adv_pdu.adv_data)
                        )
                    packet.metadata = generate_metadata(message)
                    return packet

            elif msg_type == 'raw_pdu':
                packet = BTLE(bytes(struct.pack("I", message.raw_pdu.access_address)) + bytes(message.raw_pdu.pdu) + bytes(struct.pack(">I", message.raw_pdu.crc)[1:]))
                packet.metadata = generate_metadata(message)
                return packet

            elif msg_type == 'pdu':
                packet = BTLE_DATA(message.pdu.pdu)
                packet.metadata = generate_metadata(message)
                return packet

        except AttributeError:
            return None

    def _build_message_from_scapy_packet(self, packet):
        msg = Message()
        direction = packet.metadata.direction
        connection_handle = packet.metadata.connection_handle

        if BTLE in packet:
            msg.ble.send_raw_pdu.direction = direction
            msg.ble.send_raw_pdu.conn_handle = connection_handle
            msg.ble.send_raw_pdu.crc = BTLE(raw(bytes_packet)).crc # force the CRC to be generated if not provided
            msg.ble.send_raw_pdu.access_address = BTLE(raw(bytes_packet)).access_addr

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
        capabilities = self.device.get_domain_capability(WhadDomain.BtLE)
        return not (capabilities & (1 << WhadCapability.NoRawData) > 0)

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


    def can_sniff_connection(self):
        """
        Determine if the device implements a connection sniffer mode.
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
        if not self.can_sniff_connection():
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

    def enable_peripheral_mode(self):
        """
        Enable Bluetooth Low Energy peripheral mode (acts as slave).
        """
        msg = Message()
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

    def stop(self):
        """
        Stop currently enabled mode.
        """
        msg = Message()
        msg.ble.stop.CopyFrom(StopCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def process_messages(self):
        self.device.process_messages()

    def on_generic_msg(self, message):
        print('generic: %s' % message)
        pass

    def on_discovery_msg(self, message):
        pass


    def on_domain_msg(self, domain, message):
        if domain == 'ble':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'adv_pdu':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_adv_pdu(packet)

            elif msg_type == 'pdu':
                if pdu.processed:
                    print('[ble PDU log-only]')
                else:
                    packet = self._build_scapy_packet_from_message(message, msg_type)
                    self.on_pdu(packet)

            elif msg_type == 'raw_pdu':
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


    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None, hop_interval=None, channel_map=None):
        pass

    def on_desynchronized(self, access_address=None):
        pass

    def on_adv_pdu(self, packet):
        pass

    def on_connected(self, connection_data):
        self.on_connected(connection_data)

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
        pass

    def on_ctl_pdu(self, pdu):
        pass

    def on_error_pdu(self, pdu):
        pass

    def send_ctrl_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6):
        """
        Send CTRL PDU
        """
        return self.send_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address)

    def send_data_pdu(self, data, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6):
        """
        Send data (L2CAP) PDU.
        """
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
            message = self.wait_for_message(filter=message_filter('ble', 'adv_pdu'))
            # Convert message from rebuilt PDU
            if message.ble.adv_pdu.adv_type in scapy_corr_adv:
                yield (
                    message.ble.adv_pdu.rssi,
                    scapy_corr_adv[message.ble.adv_pdu.adv_type](
                        bytes(message.ble.adv_pdu.bd_address) + bytes(message.ble.adv_pdu.adv_data)
                    )
                )
            else:
                print('nope')


class Central(BLE):

    def __init__(self, device):
        super().__init__(device)

        self.use_stack(BleStack)
        self.__connected = False
        self.__peripheral = None

        # Check device accept central mode
        if not self.can_be_central():
            raise UnsupportedCapability('Central')
        else:
            self.stop()
            self.enable_central_mode()

    def connect(self, bd_address, timeout=30):
        """Connect to a target device
        """
        self.connect_to(bd_address)
        self.start()
        start_time=time()
        while not self.__connected:
            if time()-start_time >= timeout:
                return None
        return self.__peripheral

    def peripheral(self):
        return self.__peripheral

    def use_stack(self, clazz=BleStack):
        """Specify a stack class to use for BLE. By default, our own stack (BleStack) is used.
        """
        self.__stack = clazz(self)


    ##############################
    # Incoming events
    ##############################

    def on_connected(self, connection_data):
        self.__stack.on_connection(connection_data)

    def on_disconnected(self, connection_data):
        self.__stack.on_disconnected(connection_data.conn_handle)

    def on_ctl_pdu(self, conn_handle, direction, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as a master, so we only forward slave to master
        messages to the stack.
        """
        if direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_ctl_pdu(conn_handle, pdu)

    def on_data_pdu(self, conn_handle, direction, pdu):
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.
        """
        if direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_data_pdu(conn_handle, pdu)


    def on_new_connection(self, connection):
        """On new connection, discover primary services
        """
        print('>> on connection')

        # Use GATT client
        self.connection = connection
        connection.use_gatt_class(GattClient)
        self.__peripheral = PeripheralDevice(connection.gatt)
        self.__connected = True
