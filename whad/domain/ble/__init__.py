"""
Bluetooth Low Energy
"""
from time import sleep, time
from binascii import hexlify
from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.domain.ble.stack.gatt import GattClient
from whad.helpers import message_filter, is_message_type, bd_addr_to_bytes
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import BleDirection, CentralMode, StartCmd, StopCmd, \
    ScanMode, Start, Stop, BleAdvType, ConnectToCmd, ConnectTo, CentralModeCmd, \
    SendPDUCmd
from whad.domain.ble.stack import BleStack
from scapy.layers.bluetooth4LE import BTLE_CTRL, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP
from whad.domain.ble.device import PeripheralDevice


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

    def can_be_central(self):
        """
        Determine if the device implements a central mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << CentralMode))>0 and
            (commands & (1 << ConnectTo))>0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )


    def enable_scan_mode(self, active=False):
        msg = Message()
        msg.ble.scan_mode.active_scan = active
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def enable_central_mode(self):
        msg = Message()
        msg.ble.central_mode.CopyFrom(CentralModeCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def connect_to(self, bd_addr):
        msg = Message()
        msg.ble.connect.bd_address = bd_addr_to_bytes(bd_addr)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def start(self):
        # Enable scanner
        msg = Message()
        msg.ble.start.CopyFrom(StartCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def stop(self):
        # Disable scanner
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
                if message.adv_pdu.adv_type in BLE.SCAPY_CORR_ADV:
                    self.on_adv_pdu(
                        message.adv_pdu.rssi,
                        BLE.SCAPY_CORR_ADV[message.adv_pdu.adv_type](
                            bytes(message.adv_pdu.bd_address) + bytes(message.adv_pdu.adv_data)
                        )
                    )
            elif msg_type == 'pdu':
                self.on_pdu(message.pdu)
            elif msg_type == 'connected':
                self.on_connected(message.connected)

    def on_adv_pdu(self, rssi, packet):
        pass

    def on_connected(self, connection_data):
        self.on_connected(connection_data)

    def on_pdu(self, pdu):
        #print(hexlify(pdu.pdu))
        if pdu.processed:
            print('[ble PDU log-only]')
        else:
            if pdu.pdu[0] & 0x3 == 0x03:
                self.on_ctl_pdu(
                    pdu.conn_handle,
                    pdu.direction,
                    BTLE_DATA(pdu.pdu)
                )
            elif (pdu.pdu[0] & 0x3) in [0x01, 0x02]:
                self.on_data_pdu(
                    pdu.conn_handle,
                    pdu.direction,
                    BTLE_DATA(pdu.pdu)
                )
            else:
                self.on_error_pdu(pdu.conn_handle, pdu.direction, pdu.pdu)
    
    def on_data_pdu(self, conn_handle, direction, pdu):
        pass

    def on_ctl_pdu(self, conn_handle, direction, pdu):
        pass

    def on_error_pdu(self, conn_handle, direction, pdu):
        pass

    def send_ctrl_pdu(self, pdu):
        """
        Send CTRL PDU
        """
        final_pdu = bytes([0x03, len(pdu)] + pdu)
        msg = Message()
        msg.ble.send_pdu.direction = BleDirection.MASTER_TO_SLAVE
        msg.ble.send_pdu.pdu = final_pdu
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def send_data_pdu(self, conn_handle, data):
        """
        Send data (L2CAP) PDU.
        """
        final_pdu = bytes(data)
        #print('sending: %s' % hexlify(final_pdu))
        msg = Message()
        msg.ble.send_pdu.direction = BleDirection.MASTER_TO_SLAVE
        msg.ble.send_pdu.pdu = final_pdu
        msg.ble.send_pdu.conn_handle = conn_handle
        #self.send_message(msg, message_filter('generic', 'cmd_result'))
        #resp = self.wait_for_message(filter=lambda x: False)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        #print('resp:%s' % resp)
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


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