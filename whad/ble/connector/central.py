"""
Bluetooth Low Energy Central connector
======================================

The :py:class:`whad.ble.connector.central.Central` class provides its own
asynchronous event notification mechanism (different from the one used in
the :py:class:`whad.ble.connector.peripheral.Peripheral` class for some
weird reasons).

"""
import logging
from time import sleep
from threading import Event
from typing import Optional

from whad.device.connector import Event as CentralEvent
from whad.common.stack import Layer
from whad.exceptions import UnsupportedCapability
from whad.hub.ble import Direction
from whad.hub.ble.bdaddr import BDAddress

from .base import BLE
from ..exceptions import ConnectionLostException, PeripheralNotFound
from ..profile.device import PeripheralDevice
from ..stack import BleStack
from ..stack.constants import BT_MANUFACTURERS, BT_VERSIONS
from ..stack.gatt import GattClient
from ..stack.att import ATTLayer
from ..stack.smp import CryptographicDatabase

logger = logging.getLogger(__name__)

class CentralConnected(CentralEvent):
    """Central connection event
    """

    def __init__(self, handle: int, local: BDAddress, remote: BDAddress):
        self.__handle = handle
        self.__local = local
        self.__remote = remote

    @property
    def handle(self) -> int:
        """Connection handle
        """
        return self.__handle

    @property
    def local_peer(self) -> BDAddress:
        """Central BD address
        """
        return self.__local

    @property
    def remote_peer(self) -> BDAddress:
        """Remote device BD address
        """
        return self.__remote

    def __repr__(self) -> str:
        return f"<CentralConnected handle={self.__handle} local={self.__local} remote={self.__remote}/>"

class CentralDisconnected(CentralEvent):
    """Client has disconnected from central
    """
    def __init__(self, handle: int):
        self.__handle = handle

    @property
    def handle(self) -> int:
        """Connection handle"""
        return self.__handle

class Central(BLE):
    """This connector provides a BLE Central role.

    To initiate a connection to a device, just call :meth:`Central.connect` with the target
    BD address and it should return an instance of 
    :class:`whad.ble.profile.device.PeripheralDevice` in return.
    """

    def __init__(self, device, existing_connection = None, from_json=None, stack=BleStack,
                 client=GattClient, security_database=None):
        """Attach a GATT client if specified in parameter

        If `client` is set to None, the default GATT layer is used, which does
        not provide any client feature at all.
        """
        super().__init__(device)

        # Reconfigure stack layers
        self.__configure_stack(stack, client)

        self.__gatt_client = None
        self.__connected = False
        self.__peripheral = None
        self.__profile_json = from_json
        self.__target = None
        self.__local = None
        self.__conn_handle = None
        self.connection = None

        # Internal events
        self.__connected_evt = Event()

        # If no connection, check if
        if not self.can_be_central():
            raise UnsupportedCapability('Central')

        # Initialize security database
        if security_database is None:
            logger.info((
                "No security database provided to this Peripheral instance, "
                "use a default one."))
            self.__security_database = CryptographicDatabase()
        else:
            logger.info('Peripheral will use the provided security database.')
            self.__security_database = security_database

        # Create our event handler
        self.add_event_handler(self.on_central_event)

        # If a connection already exists, just feed the stack with the parameters
        if existing_connection is not None:
            self.on_connected(existing_connection)
        else:
            # self.stop() # ButteRFly doesn't support calling stop when spawning central
            self.enable_central_mode()


    def __configure_stack(self, phy_layer=None, gatt_layer=None):
        """
        """
        # Save GATT and PHY layers
        if gatt_layer is not None:
            self.__gatt_layer = gatt_layer
        if phy_layer is not None:
            self.__phy_layer = phy_layer

            # Configure BLE stack to use our PHY class
            self.__stack = phy_layer(self)

        # Configure ATT layer to use our GATT class
        if self.__gatt_layer is not None:
            if issubclass(self.__gatt_layer, Layer) and self.__gatt_layer.alias == 'gatt':
                ATTLayer.add(self.__gatt_layer)

    @property
    def security_database(self):
        """Central role security database.
        """
        return self.__security_database

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

    @property
    def conn_handle(self) -> int:
        """Connection handle.
        """
        return self.__conn_handle

    @property
    def stack(self):
        '''Return the current stack instance
        '''
        return self.__stack

    def set_profile_json(self, profile):
        """Set Central profile as json
        """
        self.__profile_json = profile

    def stop(self):
        """Stopping Central connector.
        """
        super().stop()

    def add_event_handler(self, handler, event_type = None):
        """Add an event handler for a specific event.
        """
        self.add_listener(handler, event_type)

    def remove_event_handler(self, handler):
        """Remove an event handler.
        """
        self.remove_listener(handler)

    def clear_event_handlers(self):
        """Remove all event handlers
        """
        self.clear_listeners()

    def on_central_event(self, event: CentralEvent):
        """Central event handler

        :param  event: Central event to handle
        :type   event: CentralEvent
        """

    def notify(self, event: CentralEvent):
        """Send event to handlers.

        This method is called from methods associated with incoming events
        and is called from the Central's connector IoThread

        :param  event: Central event to notify
        :type   event: CentralEvent
        """
        super().notify(event)

    def connect(self, bd_address, random=False, timeout=30, access_address=None,channel_map=None,
                crc_init=None, hop_interval=None, hop_increment=None) -> PeripheralDevice:
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
        # Clear connection event
        self.__connected_evt.clear()

        # Make sure our BLE stack is correctly configured
        self.__configure_stack()

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

            # Wait for connection to be established
            self.__connected_evt.wait(timeout=timeout)
            if self.__peripheral is None:
                raise PeripheralNotFound()

            # Return peripheral
            return self.peripheral()

        # Raise error
        raise PeripheralNotFound()

    def peripheral(self) -> Optional[PeripheralDevice]:
        """Connected BLE peripheral.
        """
        return self.__peripheral


    def send_pdu(self, pdu, conn_handle=0, direction=Direction.MASTER_TO_SLAVE,
                 access_address=0x8e89bed6, encrypt=None) -> bool:
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
        if self.__connected:
            return super().send_pdu(pdu, conn_handle, direction=direction,
                                    access_address=access_address, encrypt=encrypt)

        # Connection lost
        raise ConnectionLostException(None)

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
            self.__local,
            self.__target
        )
        self.__conn_handle = connection_data.conn_handle
        # Notify event handlers
        self.notify(CentralConnected(
            connection_data.conn_handle, self.__local,self.__target)
        )


    def on_disconnected(self, disconnection_data):
        """Callback method to handle disconnection event.

        :param  disconnection_data: Disconnection data
        :type   disconnection_data: :class:`whad.protocol.ble_pb2.Disconnected`
        """
        logger.debug("[central] Device disconnected, forward to stack")
        self.__stack.on_disconnection(
            disconnection_data.conn_handle,
            disconnection_data.reason
        )

        self.__connected = False
        self.__local = None
        self.__target = None

        # Notify peripheral device about this disconnection
        logger.debug("[central] Notify peripheral object that a disconnection occurred")
        if self.__peripheral is not None:
            self.__peripheral.on_disconnect(disconnection_data.conn_handle)

        # Notify event handlers
        self.notify(CentralDisconnected(self.conn_handle))


    def on_ctl_pdu(self, pdu):
        """This callback method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as master, so we only forward slave to master
        messages to the stack.

        :param  pdu: BLE Control PDU
        :type   pdu: :class:`scapy.layers.bluetooth4LE.BTLE`
        """
        logger.info('received control PDU')
        if pdu.metadata.direction == Direction.SLAVE_TO_MASTER:
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        """This callback method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Central devices act as master, so we only forward slave to master
        messages to the stack.

        :param  pdu: BLE Data PDU
        :type   pdu: :class:`scapy.layers.bluetooth4LE.BTLE_DATA`
        """
        if pdu.metadata.direction == Direction.SLAVE_TO_MASTER:
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

        # Retrieve GATT client
        self.__gatt_client = connection.gatt
        self.__gatt_client.set_client_model(self.__peripheral)
        self.__connected = True
        self.__connected_evt.set()

        # Configure SMP layer
        # we set the security database
        self.connection.smp.set_security_database(self.__security_database)

        # Check if we got a matching LTK
        crypto_material = self.security_database.get(address=self.__target)

        if crypto_material is not None and crypto_material.has_ltk():
            self.__stack.get_layer('ll').state.register_encryption_key(
                connection.conn_handle,
                crypto_material.ltk.value
            )
            if crypto_material.is_authenticated():
                #print("Marked as authenticated")
                self.__stack.get_layer('ll').state.mark_as_authenticated(connection.conn_handle)
            else:
                pass#print("Marked as unauthenticated")

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

        # Error
        return None

    def export_profile(self):
        """Export GATT profile of the existing connection.

        :return: Profile as a JSON string
        :rtype: str
        """
        return self.connection.gatt.model.export_json()

    def on_mtu_changed(self, conn_handle: int, mtu: int):
        """Notify MTU change to peripheral.
        """
        logger.info("on_mtu_changed")
        if self.__peripheral is not None:
            logger.debug("[Central::on_mtu_changed] MTU changed to %d, notify peripheral", mtu)
            self.__peripheral.on_mtu_changed(mtu)

    def set_mtu(self, mtu: int):
        """Set connection MTU.
        """
        if self.__gatt_client is not None:
            # Start a MTU exchange procedure
            self.__gatt_client.set_mtu(mtu)

    def get_mtu(self) -> Optional[int]:
        """Retrieve the connection MTU.
        """
        if self.connection is not None:
            return self.connection.att.get_server_mtu()
