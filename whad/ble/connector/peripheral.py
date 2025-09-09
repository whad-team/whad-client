"""
Bluetooth Low Energy Peripheral connector
=========================================

WHAD provides a specific connector to create a BLE device, :class:`Peripheral`.
This connector implements a GATT server and hosts a GATT profile, allowing remote
BLE devices to connect to it and query its services, characteristics, and descriptors.
"""
import logging
from time import sleep
from queue import Queue, Empty
from threading import Thread, Event
from typing import Optional

from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble import Direction as BleDirection
from whad.exceptions import UnsupportedCapability

from .base import BLE
from ..stack import BleStack, Layer
from ..stack.gatt import GattServer, GattClientServer
from ..stack.att import ATTLayer
from ..stack.smp import CryptographicDatabase, Pairing
from ..profile import GenericProfile
from ..profile.device import PeripheralDevice
from ..profile.advdata import AdvDataFieldList, AdvFlagsField

# Logging
logger = logging.getLogger(__name__)

class PeripheralEventDisconnected:
    """Peripheral disconnected event.
    """
    def __init__(self, conn_handle: int):
        """Initialize this event

        :param conn_handle: Connection handle
        :type conn_handle: int
        """
        self.__conn_handle = conn_handle

    @property
    def conn_handle(self) -> int:
        """Connection handle

        :rtype: int
        """
        return self.__conn_handle


class PeripheralEventConnected:
    """Connected event
    """
    def __init__(self, conn_handle: int, local: BDAddress, remote: BDAddress):
        """Initialize event

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param local: Peripheral BD address
        :type local: :py:class:`whad.ble.BDAddress`
        :param remote: Central BD address
        :type remote: :py:class:`whad.ble.BDAddress`
        """
        self.__conn_handle = conn_handle
        self.__local = local
        self.__remote = remote

    @property
    def conn_handle(self) -> int:
        """Connection handle

        :rtype: int
        """
        return self.__conn_handle

    @property
    def local(self) -> BDAddress:
        """Peripheral BD address

        :rtype: :py:class:`whad.ble.BDAddress`
        """
        return self.__local

    @property
    def remote(self) -> BDAddress:
        """Central BD address

        :rtype: :py:class:`whad.ble.BDAddress`
        """
        return self.__remote

class PeripheralEventListener(Thread):
    """Peripheral event listener.
    """

    def __init__(self, callback=None):
        """Initialize event listener
        """
        super().__init__()
        self.__queue = Queue()
        self.__running = True
        self.__callback = callback

        # This thread is a daemon (must be terminated when main thread ends).
        self.daemon = True

    @property
    def queue(self):
        return self.__queue

    def notify(self, event):
        """Add event to notify
        """
        self.__queue.put(event)

    def stop(self):
        """Stop listener
        """
        self.__running = False

    def run(self):
        while self.__running:
            try:
                event = self.__queue.get(block=True, timeout=1.0)
                if event is not None:
                    if self.__callback is not None:
                        self.__callback(event)
            except Empty:
                pass

class Peripheral(BLE):
    """This BLE connector provides a way to create a peripheral device.

    A peripheral device exposes some services and characteristics that may
    be accessed by a central device. These services and characteristics are
    defined by a specific profile.
    """

    def __init__(self, device, existing_connection = None, profile=None, adv_data=None,
                 scan_data=None, bd_address=None, public=True, stack=BleStack, gatt=GattServer,
                 pairing=Pairing(), security_database=None):
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
        :param  public:     Set to True to use a public Bluetooth Device address,
                            False to use a random one
        :type   public:     bool
        :param  stack:      Bluetooth Low Energy stack to use,
                            :class:`whad.ble.stack.BleStack` by default
        :param  gatt:       Bluetooth Low Energy GATT
        """
        super().__init__(device)

        # Initialize local peer and remote per info
        self.__local_peer = None
        self.__remote_peer = None
        self.__gatt_server = None
        self.__peripheral = None
        self.__central = None

        # Initialize stack
        self.__configure_stack(stack, gatt)

        self.connection = None
        self.__connected = Event()
        self.__disconnected = Event()
        self.__disconnected.set()
        self.__conn_handle = None
        self.__access_address = None

        # Initialize event listener
        self.__evt_listener = None

        # Initialize profile
        if profile is None:
            logger.info("No profile provided to this Peripheral instance, use a default one.")
            self.__profile = GenericProfile()
        else:
            logger.info("Peripheral will use the provided profile.")
            self.__profile = profile

        # Initialize security database
        if security_database is None:
            logger.info((
                "No security database provided to this Peripheral instance, "
                "use a default one."))
            self.__security_database = CryptographicDatabase()
        else:
            logger.info("Peripheral will use the provided security database.")
            self.__security_database = security_database

        # Initiate pairing parameters
        self.__pairing_parameters = pairing

        # Check if device accepts peripheral mode
        if not self.can_be_peripheral():
            logger.info("Capability MasterRole not supported by this WHAD device")
            raise UnsupportedCapability("Peripheral")

        # Set bd address if provided
        if bd_address is not None:
            logger.info("Set BD address to %s", bd_address)
            self.set_bd_address(bd_address, public=public)

        # If an existing connection is hijacked, simulate a connection
        if existing_connection is not None:
            self.on_connected(existing_connection)
        else:
            # If no advertising data has been set, initialize this peripheral
            # with default flags.
            if adv_data is None:
                adv_data = AdvDataFieldList(AdvFlagsField())

            # Enable peripheral mode
            logger.info("Enable peripheral mode with advertising data: %s", adv_data)
            self.enable_peripheral_mode(adv_data, scan_data)

    @property
    def listener(self):
        """Attached event listener
        """
        return self.__evt_listener

    @property
    def local_peer(self):
        """Local peer object
        """
        return self.__local_peer

    @property
    def remote_peer(self):
        """Remote peer object
        """
        return self.__remote_peer

    @property
    def conn_handle(self) -> int:
        """Connection handle
        """
        return self.__conn_handle

    @property
    def profile(self) -> Optional[GenericProfile]:
        """GATT Profile"""
        return self.__profile

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

    def attach_event_listener(self, listener: PeripheralEventListener):
        """Attach an event queue to receive asynchronous notifications.

        :param  listener: Event listener
        :type   listener: PeripheralEventListener
        """
        # Save event queue
        self.__evt_listener = listener

    def notify_event(self, event):
        """Notify event
        """
        if self.__evt_listener is not None:
            self.__evt_listener.notify(event)

    def get_pairing_parameters(self):
        """Returns the provided pairing parameters, if any.
        """
        return self.__pairing_parameters

    def send_data_pdu(self, data, conn_handle=1, direction=BleDirection.SLAVE_TO_MASTER,
                      access_address=0x8e89bed6, encrypt=None) -> bool:
        """Send a PDU to the central device this peripheral device is connected to.

        Sending direction is set to ̀ BleDirection.SLAVE_TO_MASTER` as we need
        to send PDUs to a central device.

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
        # TODO: access address is not really required in parameters, only conn_handle
        # We patch access address if it was set in the connection event
        if self.__access_address is not None:
            access_address = self.__access_address
        return super().send_data_pdu(data, conn_handle=conn_handle, direction=direction,
                                     access_address=access_address, encrypt=encrypt)


    def send_ctrl_pdu(self, pdu, conn_handle=1, direction=BleDirection.SLAVE_TO_MASTER,
                      access_address=0x8e89bed6, encrypt=None) -> bool:
        """Send a PDU to the central device this peripheral device is connected to.

        Sending direction is set to ̀ BleDirection.SLAVE_TO_MASTER` as we need 
        to send PDUs to a central device.

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
        # TODO: access address is not really required in parameters, only conn_handle
        # We patch access address if it was set in the connection event
        if self.__access_address is not None:
            access_address = self.__access_address
        return super().send_ctrl_pdu(pdu, conn_handle=conn_handle, direction=direction,
                                     access_address=access_address, encrypt=encrypt)

    def set_profile(self, profile: GenericProfile):
        """Set peripheral profile.
        """
        self.__profile = profile

    def use_stack(self, clazz=BleStack):
        """Specify a stack class to use for BLE. By default, our own stack
        (BleStack) is used.

        :param  clazz:  BLE stack to use.
        :type   clazz:  :class:`whad.ble.stack.BleStack`
        """
        self.__stack = clazz(self)

    @property
    def smp(self):
        """Security Manager Protocol
        """
        if self.connection is not None:
            return self.connection.smp
        return None

    def pairing(self, pairing=None):
        """Trigger a pairing request with the provided parameters, if any.
        """
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
        """Generic Attribute layer
        """
        if self.connection is not None:
            return self.connection.gatt
        return None

    @property
    def security_database(self):
        """Security Database
        """
        return self.__security_database

    def is_connected(self) -> bool:
        """Determine if the peripheral has an active connection from a
        GATT client.
        """
        return self.__connected.is_set()

    def wait_connection(self, timeout: float = None) -> bool:
        """Wait for a GATT client to connect to the peripheral. If a connection
        is already active, returns immediately.
        """
        return self.__connected.wait(timeout=timeout)

    def wait_disconnection(self, timeout: float = None) -> bool:
        """Wait for a GATT client to disconnect from the peripheral. If no connection
        is active, returns immediately.
        """
        return self.__disconnected.wait(timeout=timeout)

    ##############################
    # Incoming events
    ##############################

    def on_connected(self, connection_data):
        """A device has just connected to this peripheral.

        :param  connection_data:    Connection data
        :type   connection_data:    :class:`whad.protocol.ble_pb2.Connected`
        """
        # Make sure stack is correctly configured
        self.__configure_stack()

        # Retrieve the GATT server instance and set its profile
        logger.info("a device is now connected (connection handle: %d)",
                    connection_data.conn_handle)
        self.__local_peer = BDAddress.from_bytes(
            connection_data.advertiser,
            connection_data.adv_addr_type
        )
        self.__remote_peer = BDAddress.from_bytes(
            connection_data.initiator,
            connection_data.init_addr_type
        )

        # GATT server is now connected
        self.__connected.set()
        self.__disconnected.clear()
        self.__conn_handle = connection_data.conn_handle

        # Save access address if specified
        if connection_data.access_address != 0:
            self.__access_address = connection_data.access_address
        else:
            self.__access_address = None

        # Notify our stack that a connection has been created
        self.__stack.on_connection(
            connection_data.conn_handle,
            self.__local_peer,
            self.__remote_peer
        )

        # Notify event listener, if any
        self.notify_event(PeripheralEventConnected(
                connection_data.conn_handle,
                self.__local_peer,
                self.__remote_peer
            ))


    def on_disconnected(self, disconnection_data):
        """A device has just disconnected from this peripheral.

        :param  connection_data:    Connection data
        :type   connection_data:    :class:`whad.protocol.ble_pb2.Disconnected`
        """

        logger.info("a device has just disconnected (connection handle: %d)",
                    disconnection_data.conn_handle)
        self.__stack.on_disconnection(
            disconnection_data.conn_handle,
            disconnection_data.reason
        )

        # Notify peripheral device about this disconnection
        if self.__profile is not None:
            self.__profile.on_disconnect(disconnection_data.conn_handle)

        # We are now disconnected
        self.__connected.clear()
        self.__disconnected.set()

        # Notify event listener, if any
        self.notify_event(PeripheralEventDisconnected(
            disconnection_data.conn_handle
        ))

    def on_ctl_pdu(self, pdu):
        """This method is called whenever a control PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        Peripheral devices act as a slave, so we only forward master to slave
        messages to the stack.

        :param  pdu:    BLE PDU
        :type   pdu:    :class:`scapy.layers.bluetooth4LE.BTLE`
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            logger.info("Control PDU comes from master, forward to peripheral")
            self.__stack.on_ctl_pdu(pdu.metadata.connection_handle, pdu)

    def on_data_pdu(self, pdu):
        """This method is called whenever a data PDU is received.
        This PDU is then forwarded to the BLE stack to handle it.

        :param  pdu:    BLE PDU
        :type   pdu:    :class:`scapy.layers.bluetooth4LE.BTLE_DATA`
        """
        if pdu.metadata.direction == BleDirection.MASTER_TO_SLAVE:
            logger.info("Data PDU comes from master, forward to peripheral")
            self.__stack.on_data_pdu(pdu.metadata.connection_handle, pdu)

    def on_new_connection(self, connection):
        """On new connection, discover primary services

        :param  connection:    Connection data
        :type   connection:    :class:`whad.protocol.ble_pb2.Connected`
        """

        # Use GATT server
        self.connection = connection

        # Retrieve GATT server
        self.__gatt_server = connection.gatt
        self.__gatt_server.set_server_model(self.__profile)
        self.__connected.set()
        self.__disconnected.clear()

        # Configure SMP layer
        # we set the security database
        self.connection.smp.set_security_database(self.__security_database)
        self.connection.smp.pairing_parameters = self.__pairing_parameters

        # Check if we got a matching LTK
        crypto_material = self.security_database.get(address=self.__local_peer)

        if crypto_material is not None and crypto_material.has_ltk():
            conn_handle = connection.conn_handle
            self.__stack.get_layer("ll").state.register_encryption_key(
                conn_handle,
                crypto_material.ltk.value
            )
            if crypto_material.is_authenticated():
                #print("Marked as authenticated")
                self.__stack.get_layer("ll").state.mark_as_authenticated(connection.conn_handle)
            else:
                pass#print("Marked as unauthenticated")


        # we indicate that we are a responder
        self.connection.smp.set_responder_role()

        # Notify our profile about this connection
        self.__profile.on_connect(self.connection.conn_handle)

    def set_mtu(self, mtu: int):
        """Set connection MTU.
        """
        if self.connection is not None:
            # Start a MTU exchange procedure
            self.connection.gatt.set_mtu(mtu)

    def get_mtu(self) -> int:
        """Retrieve the connection MTU.
        """
        if self.connection is not None:
            return self.connection.l2cap.get_local_mtu()

class PeripheralClient(Peripheral):
    '''This BLE connector provides a way to create a peripheral device with
    both GATT server and client roles.
    '''

    def __init__(self, device, existing_connection = None, profile=None, adv_data=None,
                 scan_data=None, bd_address=None, public=True, stack=BleStack):
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
        """Central device
        """
        return self.__peripheral
