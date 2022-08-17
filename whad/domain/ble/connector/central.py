from time import time

from whad.domain.ble.connector import BLE
from whad.domain.ble.stack import BleStack
from whad.domain.ble.stack.gatt import GattClient
from whad.domain.ble.profile.device import PeripheralDevice
from whad.protocol.ble.ble_pb2 import BleDirection
from whad.exceptions import UnsupportedCapability

import logging
logger = logging.getLogger(__name__)

class Central(BLE):

    def __init__(self, device, existing_connection = None):
        super().__init__(device)

        #self.use_stack(BleStack)
        self.__stack = BleStack(self, GattClient())
        self.__connected = False
        self.__peripheral = None

        # Check device accept central mode
        if not self.can_be_central():
            raise UnsupportedCapability('Central')
        else:
            # self.stop() # ButteRFly doesn't support calling stop when spawning central
            self.enable_central_mode()
            # If an existing connection is hijacked, simulate a connection
            if existing_connection is not None:
                self.on_connected(existing_connection)

    def connect(self, bd_address, timeout=30):
        """Connect to a target device
        """
        if self.can_connect():
            self.connect_to(bd_address)
            self.start()
            start_time=time()
            while not self.is_connected():
                if time()-start_time >= timeout:
                    return None
            return self.peripheral()
        else:
            return None

    def peripheral(self):
        return self.__peripheral


    def send_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6):
        return super().send_pdu(pdu, conn_handle, direction=direction, access_address=access_address)

    ##############################
    # Incoming events
    ##############################

    def is_connected(self):
        return self.__connected

    def on_connected(self, connection_data):
        self.__stack.on_connection(connection_data)

    def on_disconnected(self, connection_data):
        self.__stack.on_disconnected(connection_data.conn_handle)

    def on_ctl_pdu(self, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as master, so we only forward slave to master
        messages to the stack.
        """
        logger.info('received control PDU')
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        logger.info('received data PDU')
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.
        """
        if pdu.metadata.direction == BleDirection.SLAVE_TO_MASTER:
            self.__stack.on_data_pdu(pdu.metadata.connection_handle, pdu)


    def on_new_connection(self, connection):
        """On new connection, discover primary services
        """
        logger.info('new connection established')

        # Use GATT client
        self.connection = connection
        self.__peripheral = PeripheralDevice(connection.gatt)
        self.__connected = True

    def export_profile(self):
        """Export remote device profile
        """
        return self.connection.gatt.model.export_json()