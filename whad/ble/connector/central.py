from time import time

from whad.ble.connector import BLE
from whad.ble.bdaddr import BDAddress
from whad.ble.stack import BleStack
from whad.ble.stack.gatt import GattClient
from whad.ble.profile.device import PeripheralDevice
from whad.protocol.ble.ble_pb2 import BleDirection
from whad.exceptions import UnsupportedCapability

from binascii import hexlify

import logging
logger = logging.getLogger(__name__)

class Central(BLE):
    """This connector provides a BLE Central role.

    To initiate a connection to a device, just call `connect` with the target
    BD address and it should return an instance of `PeripheralDevice` in return.

    """

    def __init__(self, device, existing_connection = None, from_json=None):
        super().__init__(device)

        #self.use_stack(BleStack)
        self.__gatt_client = GattClient()
        self.__stack = BleStack(self, self.__gatt_client)
        self.__connected = False
        self.__peripheral = None
        self.__random_addr = False
        self.__profile_json = from_json

        # Check device accept central mode
        if not self.can_be_central():
            raise UnsupportedCapability('Central')
        else:
            # self.stop() # ButteRFly doesn't support calling stop when spawning central
            self.enable_central_mode()
            # If an existing connection is hijacked, simulate a connection
            if existing_connection is not None:
                self.on_connected(existing_connection)

    def connect(self, bd_address, random=False, timeout=30):
        """Connect to a target device

        :param string bd_address: Bluetooth device address (in format 'xx:xx:xx:xx:xx:xx')
        :param int timeout: Connection timeout
        :returns: An instance of `PeripheralDevice` on success, `None` on failure.
        """
        if self.can_connect():
            self.connect_to(bd_address, random=random)
            self.start()
            start_time=time()
            while not self.is_connected():
                if time()-start_time >= timeout:
                    return None
            self.__random_addr = random
            return self.peripheral()
        else:
            return None

    def peripheral(self):
        return self.__peripheral


    def send_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None):
        return super().send_pdu(pdu, conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    ##############################
    # Incoming events
    ##############################

    def is_connected(self):
        """Determine if the central device is connected to a peripheral.

        :returns: `True` if central is connected to a peripheral device, `False` otherwise.
        """
        return self.__connected

    def on_connected(self, connection_data):
        """Callback method to handle connection event.
        """
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
        """
        self.__stack.on_disconnection(
            disconnection_data.conn_handle,
            disconnection_data.reason
        )

        self.__connected = False
        
        # Notify peripheral device about this disconnection
        if self.__peripheral is not None:
            self.__peripheral.on_disconnect(disconnection_data.conn_handle)

    def on_ctl_pdu(self, pdu):
        """This callback method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as master, so we only forward slave to master
        messages to the stack.
        
        :param pdu: BLE Control PDU
        """
        logger.info('received control PDU')
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        """This callback methid is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as master, so we only forward slave to master
        messages to the stack.
        
        :param pdu: BLE Control PDU
        """
        logger.info('received data PDU')
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.
        """
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_data_pdu(pdu.metadata.connection_handle, pdu)


    def on_new_connection(self, connection):
        """On new connection, discover primary services.
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

    def export_profile(self):
        """Export GATT profile of the existing connection.

        :rtype: string
        :returns: Profile as a JSON string
        """
        return self.connection.gatt.model.export_json()