
from whad.domain.ble.connector import BLE
from whad.domain.ble.stack import BleStack
from whad.domain.ble.stack.gatt import GattServer
from whad.domain.ble.profile import GenericProfile
from whad.protocol.ble.ble_pb2 import BleDirection
from whad.exceptions import UnsupportedCapability

class Peripheral(BLE):

    def __init__(self, device, existing_connection = None, profile=None):
        super().__init__(device)

        # Initialize stack
        #self.use_stack(BleStack)
        self.__stack = BleStack(self, GattServer(profile))
        self.__connected = False

        # Initialize profile
        if profile is None:
            self.__profile = GenericProfile()
        else:
            self.__profile = profile

        # Check if device accepts peripheral mode
        if not self.can_be_peripheral():
            raise UnsupportedCapability("Peripheral")
        else:
            self.enable_peripheral_mode()

            # If an existing connection is hijacked, simulate a connection
            if existing_connection is not None:
                self.on_connected(existing_connection)

    
    def send_pdu(self, pdu, conn_handle=1, direction=BleDirection.SLAVE_TO_MASTER, access_address=0x8e89bed6):
        super().send_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address)
    

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

    def on_ctl_pdu(self, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Peripheral devices act as a slave, so we only forward master to slave
        messages to the stack.
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            self.__stack.on_data_pdu(pdu.metadata.connection_handle, pdu)


    def on_new_connection(self, connection):
        """On new connection, discover primary services
        """
        print('>> on connection')

        # Use GATT server
        self.connection = connection
        self.__connected = True