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
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.stack import BleStack
from whad.ble.stack.gatt import GattServer, GattClientServer
from whad.ble.stack.att import ATTLayer
from whad.ble.stack.smp import CryptographicDatabase, Pairing
from whad.ble.profile import GenericProfile
from whad.ble.profile.device import PeripheralDevice
from whad.protocol.ble.ble_pb2 import BleDirection
from whad.exceptions import UnsupportedCapability
from time import sleep

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

    def __init__(self, device, existing_connection = None, profile=None, adv_data=None, scan_data=None, bd_address=None, public=True, stack=BleStack, gatt=GattServer, pairing=Pairing(), security_database=None):
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
        :param  gatt:       Bluetooth Low Energy GATT
        """
        super().__init__(device)

        # Attach a GATT server to our stack ATT layer
        att_layer = stack.find('att')
        if att_layer is not None:
            att_layer.add(gatt)

        # Initialize local peer and remote per info
        self.__local_peer = None
        self.__remote_peer = None

        # Initialize stack
        self.__stack = stack(self)
        self.connection = None
        self.__connected = False
        self.__conn_handle = None

        # Initialize profile
        if profile is None:
            logger.info('No profile provided to this Peripheral instance, use a default one.')
            self.__profile = GenericProfile()
        else:
            logger.info('Peripheral will use the provided profile.')
            self.__profile = profile

        # Initialize security database
        if security_database is None:
            logger.info('No security database provided to this Peripheral instance, use a default one.')
            self.__security_database = CryptographicDatabase()
        else:
            logger.info('Peripheral will use the provided security database.')
            self.__security_database = security_database

        # Initiate pairing parameters
        self.__pairing_parameters = pairing

        # Check if device accepts peripheral mode
        if not self.can_be_peripheral():
            logger.info('Capability MasterRole not supported by this WHAD device')
            raise UnsupportedCapability("Peripheral")
        else:
            # Set bd address if provided
            if bd_address is not None:
                logger.info('Set BD address to %s' % bd_address)
                self.set_bd_address(bd_address, public=public)

            # If an existing connection is hijacked, simulate a connection
            if existing_connection is not None:
                self.on_connected(existing_connection)
            else:    
                # Enable peripheral mode
                logger.info('Enable peripheral mode with advertising data: %s' % adv_data)
                self.enable_peripheral_mode(adv_data, scan_data)

    @property
    def local_peer(self):
        return self.__local_peer

    @property
    def remote_peer(self):
        return self.__remote_peer

    @property
    def conn_handle(self):
        return self.__conn_handle

    def get_pairing_parameters(self):
        """Returns the provided pairing parameters, if any.
        """
        return self.__pairing_parameters

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
    def smp(self):
        if self.connection is not None:
            return self.connection.smp
        return None

    def pairing(self, pairing=None):
        if self.smp is None:
            return False
        if pairing is not None:
            self.__pairing_parameters = pairing

        if not self.smp.request_pairing(self.__pairing_parameters):
            return False

        while not self.smp.is_pairing_done():
            sleep(0.1)
            if self.smp.is_pairing_failed():
                return False

        self.smp.reset_state()
        return True

    @property
    def gatt(self):
        if self.connection is not None:
            return self.connection.gatt
        return None

    @property
    def security_database(self):
        return self.__security_database

    def is_connected(self) -> bool:
        """Determine if the peripheral has an active connection from a
        GATT client.
        """
        return self.__connected

    def wait_connection(self):
        """Wait for a GATT client to connect to the peripheral. If a connection
        is already active, returns immediately.
        """
        while not self.is_connected():
            sleep(.5)


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
        self.__local_peer = BDAddress.from_bytes(
            connection_data.advertiser,
            connection_data.adv_addr_type
        )
        self.__remote_peer = BDAddress.from_bytes(
            connection_data.initiator,
            connection_data.init_addr_type
        )
        self.__stack.on_connection(
            connection_data.conn_handle,
            self.__local_peer,
            self.__remote_peer
        )

        # GATT server is now connected
        self.__connected = True
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

        # Configure SMP layer
        # we set the security database
        self.connection.smp.set_security_database(self.__security_database)
        self.connection.smp.pairing_parameters = self.__pairing_parameters

        # Check if we got a matching LTK
        crypto_material = self.security_database.get(address=self.__local_peer)

        if crypto_material is not None and crypto_material.has_ltk():
            conn_handle = connection.conn_handle
            self.__stack.get_layer('ll').state.register_encryption_key(
                conn_handle,
                crypto_material.ltk.value
            )
            if crypto_material.is_authenticated():
                #print("Marked as authenticated")
                self.__stack.get_layer('ll').state.mark_as_authenticated(connection.conn_handle)
            else:
                pass#print("Marked as unauthenticated")


        # we indicate that we are a responder
        self.connection.smp.set_responder_role()

        # Notify our profile about this connection
        self.__profile.on_connect(self.connection.conn_handle)
    '''
    def start_encryption(self):
        # Check if we got a matching LTK
        crypto_material = self.security_database.get(address=self.__target)

        if crypto_material is not None and crypto_material.has_ltk():
            conn_handle = self.connection.smp.get_layer('l2cap').state.conn_handle
            if crypto_material is not None and crypto_material.has_ltk():
                self.connection.smp.get_layer('ll').start_encryption(
                    conn_handle,
                    unpack('>Q', crypto_material.ltk.rand)[0],
                    crypto_material.ltk.ediv
                )
    '''
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

    @property
    def central_device(self):
        return self.__peripheral
