
from whad.ble.connector import BLE
from whad.ble.bdaddr import BDAddress
from whad.ble.stack import BleStack
from whad.ble.stack.gatt import GattServer
from whad.ble.profile import GenericProfile
from whad.protocol.ble.ble_pb2 import BleDirection
from whad.exceptions import UnsupportedCapability

from binascii import hexlify

# Logging
import logging
logger = logging.getLogger(__name__)

class Peripheral(BLE):
    """This BLE connector provides a way to create a peripheral device.

    A peripheral device exposes some services and characteristics that may
    be accessed by a central device. These services and characteristics are
    defined by a specific profile.
    """

    def __init__(self, device, existing_connection = None, profile=None, adv_data=None, scan_data=None, bd_address=None):
        """Create a peripheral device.

        :param WhadDevice device: WHAD device to use as a peripheral
        :param GattProfile profile: Device profile to use
        :param AdvDataFieldList adv_data: Advertisement data
        """
        super().__init__(device)

        # Initialize stack
        #self.use_stack(BleStack)
        self.__stack = BleStack(self, GattServer(profile))
        self.__connected = False

        # Initialize profile
        if profile is None:
            logger.info('No profile provided to this Peripheral instance, use a default one.')
            self.__profile = GenericProfile()
        else:
            logger.info('Peripheral will use the provided profile.')
            self.__profile = profile

        # Check if device accepts peripheral mode
        if not self.can_be_peripheral():
            logger.info('Capability MasterRole not supported by this WHAD device')
            raise UnsupportedCapability("Peripheral")
        else:
            # Set bd address if provided
            if bd_address is not None:
                logger.info('Set BD address to %s' % bd_address)
                self.set_bd_address(bd_address)

            # Enable peripheral mode
            logger.info('Enable peripheral mode with advertising data: %s' % adv_data)
            self.enable_peripheral_mode(adv_data, scan_data)

            # If an existing connection is hijacked, simulate a connection
            if existing_connection is not None:
                self.on_connected(existing_connection)


    def send_data_pdu(self, pdu, conn_handle=1, direction=BleDirection.SLAVE_TO_MASTER, access_address=0x8e89bed6, encrypt=None):
        """Send a PDU to the central device this peripheral device is connected to.

        Sending direction is set to ̀ BleDirection.SLAVE_TO_MASTER` as we need to send PDUs to a central device.

        :param bytes pdu: PDU to send
        :param int conn_handle: Connection handle
        :param int direction: Sending direction (to master or slave)
        :param access_address: Target access address
        :type access_address: int, optional
        """
        super().send_data_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    def send_ctrl_pdu(self, pdu, conn_handle=1, direction=BleDirection.SLAVE_TO_MASTER, access_address=0x8e89bed6, encrypt=None):
        """Send a PDU to the central device this peripheral device is connected to.

        Sending direction is set to ̀ BleDirection.SLAVE_TO_MASTER` as we need to send PDUs to a central device.

        :param bytes pdu: PDU to send
        :param int conn_handle: Connection handle
        :param int direction: Sending direction (to master or slave)
        :param access_address: Target access address
        :type access_address: int, optional
        """
        super().send_ctrl_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    def use_stack(self, clazz=BleStack):
        """Specify a stack class to use for BLE. By default, our own stack (BleStack) is used.
        """
        self.__stack = clazz(self)


    ##############################
    # Incoming events
    ##############################

    def on_connected(self, connection_data):
        """A device has just connected to this peripheral.
        """
        logger.info('a device is now connected (connection handle: %d)' % connection_data.conn_handle)
        self.__stack.on_connection(
            connection_data.conn_handle,
            BDAddress.from_bytes(
                connection_data.advertiser,
                connection_data.adv_addr_type
            ),
            BDAddress.from_bytes(
                connection_data.initiator,
                connection_data.init_addr_type
            )
        )

    def on_disconnected(self, disconnection_data):
        """A device has just disconnected from this peripheral.
        """
        logger.info('a device has just connected (connection handle: %d)' % disconnection_data.conn_handle)
        self.__stack.on_disconnection(
            disconnection_data.conn_handle,
            disconnection_data.reason
        )

        # Notify peripheral device about this disconnection
        if self.__profile is not None:
            self.__profile.on_disconnect(disconnection_data.conn_handle)

    def on_ctl_pdu(self, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Peripheral devices act as a slave, so we only forward master to slave
        messages to the stack.
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            logger.info('Control PDU comes from master, forward to peripheral')
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            logger.info('Data PDU comes from master, forward to peripheral')
            self.__stack.on_data_pdu(pdu.metadata.connection_handle, pdu)

    def on_new_connection(self, connection):
        """On new connection, discover primary services
        """
        # Use GATT server
        self.connection = connection
        self.__connected = True

        # Notify our profile about this connection
        self.__profile.on_connect(self.connection.conn_handle)
