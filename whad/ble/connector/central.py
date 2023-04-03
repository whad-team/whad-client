"""
Bluetooth Low Energy Central connector
======================================
"""

from time import time, sleep

from whad.ble.connector import BLE
from whad.ble.bdaddr import BDAddress
from whad.ble.stack import BleStack, BtVersion
from whad.ble.stack.constants import BT_MANUFACTURERS, BT_VERSIONS
from whad.ble.stack.gatt import GattClient
from whad.ble.profile.device import PeripheralDevice
from whad.protocol.ble.ble_pb2 import BleDirection
from whad.exceptions import UnsupportedCapability

from binascii import hexlify

import logging
logger = logging.getLogger(__name__)

class Central(BLE):
    """This connector provides a BLE Central role.

    To initiate a connection to a device, just call :meth:`Central.connect` with the target
    BD address and it should return an instance of :class:`whad.ble.profile.device.PeripheralDevice` in return.

    """

    def __init__(self, device, existing_connection = None, from_json=None):
        super().__init__(device)

        self.__gatt_client = GattClient()
        self.__stack = BleStack(self, self.__gatt_client)
        self.__connected = False
        self.__peripheral = None
        self.__random_addr = False
        self.__profile_json = from_json
        self.__target = None
        self.__local = None

        # If no connection, check if 
        if not self.can_be_central():
            raise UnsupportedCapability('Central')

        # If a connection already exists, just feed the stack with the parameters
        if existing_connection is not None:
            self.on_connected(existing_connection)
        else:
            # self.stop() # ButteRFly doesn't support calling stop when spawning central
            self.enable_central_mode()


    @property
    def local_peer(self) -> BDAddress:
        """Local peer BD address.
        """
        return self.__local

    @property
    def target_peer(self) -> BDAddress:
        """Remote peer BD address.
        """
        return self.__target

    def connect(self, bd_address, random=False, timeout=30, access_address=None, channel_map=None, crc_init=None, hop_interval=None, hop_increment=None) -> PeripheralDevice:
        """Connect to a target device

        :param  bd_address:     Bluetooth device address (in format 'xx:xx:xx:xx:xx:xx')
        :type   bd_address:     str
        :param  timeout:        Connection timeout
        :type   timeout:        float
        :param  access_address: Access address to use (optional)
        :type   access_address: int
        :param  channel_map:    Channel map to use (optional)
        :type   channel_map:    int
        :param  crc_init:       CRC Initialization value to use (optional)
        :type   crc_init:       int
        :param  hop_interval:   Hop interval to use (optional)
        :type   hop_interval:   int
        :param  hop_increment:  Hop increment to use (optional)
        :type   hop_increment:  int
        
        :return: An instance of `PeripheralDevice` on success, `None` on failure.
        :rtype: :class:`whad.ble.profile.device.PeripheralDevice`
        """
        if self.can_connect():
            self.connect_to(
                bd_address,
                random=random,
                access_address=access_address,
                channel_map=channel_map,
                crc_init=crc_init,
                hop_interval=hop_interval,
                hop_increment=hop_increment
            )

            self.start()
            start_time=time()
            while not self.is_connected():
                if time()-start_time >= timeout:
                    return None
            self.__random_addr = random
            return self.peripheral()
        else:
            return None

    def peripheral(self) -> PeripheralDevice:
        """Connected BLE peripheral.
        """
        return self.__peripheral


    def send_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None) -> bool:
        """Send a PDU to the connected peripheral device or to the central device.

        :param  pdu:            BLE PDU to send.
        :type   pdu:            :class:`scapy.layers.bluetooth4LE.BTLE`
        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        :param  direction:      Direction (central to peripheral, peripheral to central)
        :type   direction:      :class:`whad.protocol.ble.ble_pb2.BleDirection`
        :param  access_address: Access address to use while sending PDU.
        :type   access_address: int
        :param  encrypt:        Enable PDU encryption if set to ``True``.
        :type   encrypt:        bool

        :return:                PDU transmission result.
        :rtype:                 bool
        """
        return super().send_pdu(pdu, conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    ##############################
    # Incoming events
    ##############################

    def is_connected(self) -> bool:
        """Determine if the central device is connected to a peripheral.

        :return:    ``True`` if central is connected to a peripheral device, `False` otherwise.
        :rtype:     bool
        """
        return self.__connected

    def on_connected(self, connection_data):
        """Callback method to handle connection event.

        :param  connection_data: Connection data
        :type   connection_data: dict
        """
        # Save local and target peer info
        self.__local = BDAddress.from_bytes(
            connection_data.initiator,
            addr_type=connection_data.init_addr_type
        )

        self.__target = BDAddress.from_bytes(
            connection_data.advertiser,
            connection_data.adv_addr_type
        )

        self.__stack.on_connection(
            connection_data.conn_handle,
            BDAddress.from_bytes(
                connection_data.initiator,
                addr_type=connection_data.init_addr_type
            ),
            BDAddress.from_bytes(
                connection_data.advertiser,
                connection_data.adv_addr_type
            )
        )

    def on_disconnected(self, disconnection_data):
        """Callback method to handle disconnection event.

        :param  disconnection_data: Disconnection data
        :type   disconnection_data: :class:`whad.protocol.ble_pb2.Disconnected`
        """
        self.__stack.on_disconnection(
            disconnection_data.conn_handle,
            disconnection_data.reason
        )

        self.__connected = False
        self.__local = None
        self.__target = None

        # Notify peripheral device about this disconnection
        if self.__peripheral is not None:
            self.__peripheral.on_disconnect(disconnection_data.conn_handle)


    def on_ctl_pdu(self, pdu):
        """This callback method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as master, so we only forward slave to master
        messages to the stack.

        :param  pdu: BLE Control PDU
        :type   pdu: :class:`scapy.layers.bluetooth4LE.BTLE`
        """
        logger.info('received control PDU')
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        """This callback methid is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as master, so we only forward slave to master
        messages to the stack.

        :param  pdu: BLE Data PDU
        :type   pdu: :class:`scapy.layers.bluetooth4LE.BTLE_DATA`
        """
        logger.info('received data PDU')
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_data_pdu(pdu.metadata.connection_handle, pdu)


    def on_new_connection(self, connection):
        """On new connection, discover primary services.

        :param  connection: New connection Protobuf message
        :type   connection: :class:`whad.protocol.ble_pb2.Connected`
        """
        logger.info('new connection established')

        # Use GATT client
        self.connection = connection
        self.__peripheral = PeripheralDevice(
            self,
            connection.gatt,
            connection.conn_handle,
            from_json=self.__profile_json
        )
        self.__gatt_client.set_model(self.__peripheral)
        self.__connected = True

        # Notify peripheral about this connection
        self.__peripheral.on_connect(self.connection.conn_handle)


    def version(self, synchronous=True):
        """Query BLE version of remote peer.
        """
        if self.connection is not None:
            # Send an LL_VERSION_IND PDU
            self.connection.send_version()

            # Wait for an answer (mandatory)
            if synchronous:
                while not self.connection.remote_version:
                    sleep(0.01)
                result = self.connection.remote_version

                # Identify BT version
                if result.version in BT_VERSIONS:
                    version = BT_VERSIONS[result.version]
                else:
                    version = result.version

                # Identify BT company
                if result.company in BT_MANUFACTURERS:
                    company = BT_MANUFACTURERS[result.company]
                else:
                    company = result.company

                # Return information
                return (version, result.subversion, company)
            else:
                return None

    def export_profile(self):
        """Export GATT profile of the existing connection.

        :returns: Profile as a JSON string
        :rtype: str
        """
        return self.connection.gatt.model.export_json()
