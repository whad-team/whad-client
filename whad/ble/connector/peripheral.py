"""
Bluetooth Low Energy Peripheral connector
=========================================

WHAD provides a specific connector to create a BLE device, :class:`Peripheral`.
This connector implements a GATT server and hosts a GATT profile, allowing remote
BLE devices to connect to it and query its services, characteristics, and descriptors.

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

from time import sleep

from whad.ble.connector import BLE
from whad.ble.bdaddr import BDAddress
from whad.ble.stack import BleStack
from whad.ble.stack.gatt import GattServer, GattClientServer
from whad.ble.stack.att import ATTLayer
from whad.ble.profile import GenericProfile
from whad.ble.profile.device import PeripheralDevice
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

    def __init__(self, device, existing_connection = None, profile=None, adv_data=None, scan_data=None, bd_address=None, public=True, stack=BleStack):
        """Create a peripheral device.

        :param  device:     WHAD device to use as a peripheral
        :type   device:     :class:`whad.device.WhadDevice`
        :param  profile:    Device profile to use
        :type   profile:    :class:`whad.ble.profile.GenericProfile`
        :param  adv_data:   Advertisement data
        :type   adv_data:   :class:`whad.ble.profile.advdata.AdvDataFieldList`
        :param  scan_data:  Advertisement data sent in Scan Response
        :type   scan_data:  :class:`whad.ble.profile.advdata.AdvDataFieldList`
        :param  bd_address: Bluetooth Device address to use
        :type   bd_address: str
        :param  public:     Set to True to use a public Bluetooth Device address, False to use a random one
        :type   public:     bool
        :param  stack:      Bluetooth Low Energy stack to use, :class:`whad.ble.stack.BleStack` by default
        """
        super().__init__(device)

        # Attach a GATT server to our stack ATT layer
        ATTLayer.add(GattServer)

        # Initialize stack
        self.__stack = stack(self)
        self.__conn_handle = None
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
                self.set_bd_address(bd_address, public=public)

            # Enable peripheral mode
            logger.info('Enable peripheral mode with advertising data: %s' % adv_data)
            self.enable_peripheral_mode(adv_data, scan_data)

            # If an existing connection is hijacked, simulate a connection
            if existing_connection is not None:
                self.on_connected(existing_connection)


    def send_data_pdu(self, pdu, conn_handle=1, direction=BleDirection.SLAVE_TO_MASTER, access_address=0x8e89bed6, encrypt=None) -> bool:
        """Send a PDU to the central device this peripheral device is connected to.

        Sending direction is set to ̀ BleDirection.SLAVE_TO_MASTER` as we need to send PDUs to a central device.

        :param  pdu:            PDU to send
        :type   pdu:            :class:`scapy.layers.bluetooth4LE.BTLE`
        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        :param  direction:      Sending direction (to master or slave)
        :type   direction:      :class:`whad.protocol.ble_pb2.BleDirection`, optional
        :param  access_address: Target access address
        :type   access_address: int, optional
        :return:                PDU transmission result.
        :rtype: bool
        """
        return super().send_data_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)


    def send_ctrl_pdu(self, pdu, conn_handle=1, direction=BleDirection.SLAVE_TO_MASTER, access_address=0x8e89bed6, encrypt=None) -> bool:
        """Send a PDU to the central device this peripheral device is connected to.

        Sending direction is set to ̀ BleDirection.SLAVE_TO_MASTER` as we need to send PDUs to a central device.

        :param  pdu:            PDU to send
        :type   pdu:            :class:`scapy.layers.bluetooth4LE.BTLE`
        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        :param  direction:      Sending direction (to master or slave)
        :type   direction:      :class:`whad.protocol.ble_pb2.BleDirection`, optional
        :param  access_address: Target access address
        :type   access_address: int, optional
        :return:                PDU transmission result.
        :rtype: bool
        """
        return super().send_ctrl_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)


    def use_stack(self, clazz=BleStack):
        """Specify a stack class to use for BLE. By default, our own stack (BleStack) is used.

        :param  clazz:  BLE stack to use.
        :type   clazz:  :class:`whad.ble.stack.BleStack`
        """
        self.__stack = clazz(self)

    @property
    def gatt(self):
        return self.__gatt_server

    ##############################
    # Incoming events
    ##############################

    def on_connected(self, connection_data):
        """A device has just connected to this peripheral.

        :param  connection_data:    Connection data
        :type   connection_data:    :class:`whad.protocol.ble_pb2.Connected`
        """
        # Retrieve the GATT server instance and set its profile
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
        self.__conn_handle = connection_data.conn_handle

    def on_disconnected(self, disconnection_data):
        """A device has just disconnected from this peripheral.

        :param  connection_data:    Connection data
        :type   connection_data:    :class:`whad.protocol.ble_pb2.Disconnected`
        """
        logger.info('a device has just connected (connection handle: %d)' % disconnection_data.conn_handle)
        self.__stack.on_disconnection(
            disconnection_data.conn_handle,
            disconnection_data.reason
        )

        # Notify peripheral device about this disconnection
        if self.__profile is not None:
            self.__profile.on_disconnect(disconnection_data.conn_handle)

        # We are now disconnected
        self.__connected = False


    def on_ctl_pdu(self, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Peripheral devices act as a slave, so we only forward master to slave
        messages to the stack.

        :param  pdu:    BLE PDU
        :type   pdu:    :class:`scapy.layers.bluetooth4LE.BTLE`
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            logger.info('Control PDU comes from master, forward to peripheral')
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        :param  pdu:    BLE PDU
        :type   pdu:    :class:`scapy.layers.bluetooth4LE.BTLE_DATA`
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            logger.info('Data PDU comes from master, forward to peripheral')
            self.__stack.on_data_pdu(pdu.metadata.connection_handle, pdu)

    def on_new_connection(self, connection):
        """On new connection, discover primary services

        :param  connection:    Connection data
        :type   connection:    :class:`whad.protocol.ble_pb2.Connected`
        """
        # Use GATT server
        self.connection = connection
        self.__connected = True

        # Retrieve GATT server
        self.__gatt_server = connection.gatt
        self.__gatt_server.set_server_model(self.__profile)
        self.__connected = True

        # Notify our profile about this connection
        self.__profile.on_connect(self.connection.conn_handle)

    def is_connected(self):
        """Determine if this peripheral is connected to a central.

        :return:    True if connected, False otherwise.
        """
        return self.__connected

    def wait_connection(self):
        """Wait for a connection.
        """
        while not self.is_connected():
            sleep(.5)

    def terminate(self):
        """Terminate the current connection
        """
        if self.__conn_handle is not None:
            self.disconnect(self.__conn_handle)


class PeripheralClient(Peripheral):
    '''This BLE connector provides a way to create a peripheral device with
    both GATT server and client roles.
    '''

    def __init__(self, device, existing_connection = None, profile=None, adv_data=None, scan_data=None, bd_address=None, public=True, stack=BleStack):
        super().__init__(
            device,
            existing_connection=existing_connection,
            profile=profile,
            adv_data=adv_data,
            scan_data=scan_data,
            bd_address=bd_address,
            public=public,
            stack=stack
        )

        # Change ATTLayer to use GattClientServer and reinstantiate our stack
        ATTLayer.add(GattClientServer)
        self.use_stack(BleStack)


    def on_new_connection(self, connection):
        super().on_new_connection(connection)
        
        # Create a new peripheral device to represent the central device
        # that has just connected
        self.__peripheral = PeripheralDevice(
            self,
            connection.gatt,
            connection.conn_handle
        )

        # Retrieve GATT client
        self.__central = connection.gatt
        self.__central.set_client_model(self.__peripheral)
        #self.__connected = True

    @property
    def central_device(self):
        return self.__peripheral