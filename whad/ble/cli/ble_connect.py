"""Bluetooth Low Energy connect tool

This utility will configure a compatible whad device to connect to a given
BLE device, and chain this with another tool.
"""
# Logging
import logging

from time import sleep

# WHAD device classes
from whad.device.unix import UnixConnector, UnixSocketServerDevice
from whad.device import Bridge

# WHAD BLE interfaces
from whad.ble import BLE, Central
from whad.ble.exceptions import PeripheralNotFound

# WHAD BLE messages
from whad.hub.ble import BlePduReceived, BleRawPduReceived, Connected, Disconnected
from whad.hub.ble.bdaddr import BDAddress

# WHAD CLI helper
from whad.cli.app import CommandLineDevicePipe, run_app

logger = logging.getLogger(__name__)

class BleConnectOutputPipe(Bridge):
    """wble-connect output pipe

    When wble-connect is used with its output piped to another WHAD tool,
    it creates a connection to a BLE device and then gives access to the
    WHAD adapter in its entirety. The piped tool can send commands and will
    receive notifications from the adapter.

    There is not specific process to be applied, we are just bridging a
    unix socket server device to the central connector and that's it.
    """

class BleConnectInputPipe(Bridge):
    """wble-connect input pipe

    When wble-connect has its standard input piped to another WHAD tool
    standard output, then it will consider that the previous tool configure
    another WHAD hardware adapter to get a connection and will process incoming
    connection/disconnection events as well as PDUs. These PDUs will be
    forwarded to the device wble-connect is connected to, and every PDU coming
    from our target device will be forwarded to the chained WHAD tool upstream.

    Inbound messages (sent by the device we are connected to) are monitored and
    only PDU-related messages will be forwarded  to the chained tool while
    outbound messages (coming from the chained tool) are analyzed to detect when
    a connection occurs and forward every PDU to our target device.
    """

    def __init__(self, input_connector, output_connector):
        """Initialize our wble-connect input pipe.
        """
        logger.debug('[wble-connect][output-pipe] Initialization')
        super().__init__(input_connector, output_connector)

        logger.debug('[wble-connect][output-pipe] Initialize properties')
        self.__connected = False
        self.__in_conn_handle = None
        self.__out_conn_handle = None

    def set_in_conn_handle(self, conn_handle: int):
        """Saves the input connector connection handle.
        """
        self.__in_conn_handle = conn_handle

    def set_out_conn_handle(self, conn_handle: int):
        """Saves output connection handle.
        """
        logger.debug("[wble-connect][output-pipe] set output connection handle to %d", conn_handle)
        self.__out_conn_handle = conn_handle

    def convert_packet_message(self, message, conn_handle, incoming=True):
        """Convert a BleRawPduReceived/BlePduReceived notification into the
        corresponding SendBleRawPdu/SendBlePdu command, using the provided
        connection handle.
        """
        if incoming:
            connector = self.input
        else:
            connector = self.output

        # Do we received a packet notification ?
        logger.debug("[wble-connect][output-pipe] convert message %s into a command", message)
        if isinstance(message, BleRawPduReceived):
            # Does our input connector support raw packets ?
            if connector.support_raw_pdu():
                logger.debug('[wble-connect][output-pipe] connector supports raw pdu')
                # Create a SendBleRawPdu command
                command = connector.hub.ble.create_send_raw_pdu(
                    message.direction,
                    message.pdu,
                    message.crc,
                    encrypt=False,
                    access_address=message.access_address,
                    conn_handle=conn_handle, # overwrite the connection handle
                )
                logger.debug("[wble-connect][output-pipe] created command %s", command)
            else:
                logger.debug('[wble-connect][output-pipe] connector does not support raw pdu')
                # Create a SendBlePdu command
                command = connector.hub.ble.create_send_pdu(
                    message.direction,
                    message.pdu,
                    conn_handle, # overwrite the connection handle
                    encrypt=False
                )
                logger.debug("[wble-connect][output-pipe] created command %s", command)
        elif isinstance(message, BlePduReceived):
            # Does our input connector support raw packets ?
            if connector.support_raw_pdu():
                logger.debug('[wble-connect][output-pipe] connector supports raw pdu')
                # Create a SendBleRawPdu command
                command = connector.hub.ble.create_send_raw_pdu(
                    message.direction,
                    message.pdu,
                    None,
                    encrypt=False,
                    access_address=0x11223344, # We use the default access address
                    conn_handle=conn_handle, # overwrite the connection handle
                )
                logger.debug("[wble-connect][output-pipe] created command %s", command)
            else:
                logger.debug('[wble-connect][output-pipe] connector does not support raw pdu')
                # Create a SendBlePdu command
                command = self.input.hub.ble.create_send_pdu(
                    message.direction,
                    message.pdu,
                    conn_handle, # overwrite the connection handle
                    encrypt=False
                )
                logger.debug("[wble-connect][output-pipe] created command %s", command)
        else:
            # Not a BLE packet notification
            command = None

        # Return generated command
        return command

    def on_inbound(self, message):
        """Process inbound messages.

        Inbound messages are coming from our output connector, i.e. the
        peripheral device we are connected to, we  only process any PDU-related
        message and discard other events/notifications such as connection or
        disconnection events.

        Normally, since we get packets from a central device we are supposed to
        be connected and know the connection handle corresponding to this
        connection.
        """
        if isinstance(message, BleRawPduReceived) or isinstance(message, BlePduReceived):
            if not self.__connected:
                logger.debug(
                    "[wble-connect][output-pipe] add pending inbound PDU message %s to queue",
                    message
                )
            else:
                logger.debug(
                    "[wble-connect][output-pipe] received an inbound PDU message %s",
                    message
                )
                command = self.convert_packet_message(message, self.__in_conn_handle, True)
                self.input.send_command(command)
        elif isinstance(message, Disconnected):
            # Central device has disconnected, we don't care but we don't send this
            # notification to our chained tool.
            logger.debug("[wble-connect][output-pipe] received a disconnection notification, todo")
            return
        elif isinstance(message, Connected):
            logger.debug("[wble-connect][output-pipe] received a connection notification, discard")
            return
        else:
            logger.debug("[wble-connect][output-pipe] forward default inbound message %s", message)
            # Forward other messages
            super().on_inbound(message)

    def on_outbound(self, message):
        """Process outbund messages.

        We monitor these messages to catch the connection handle used by our chained
        tool (upstream) in order to send valid commands.
        """
        if isinstance(message, BleRawPduReceived) or isinstance(message, BlePduReceived):
            if self.__out_conn_handle is not None:
                logger.debug("[wble-connect][output-pipe] received an outbound PDU message %s", message)
                command = self.convert_packet_message(message, self.__out_conn_handle, False)
                self.output.send_command(command)
        elif isinstance(message, Connected):
            # Don't forward this message.
            self.set_in_conn_handle(message.conn_handle)
            self.__connected = True
            return
        elif isinstance(message, Disconnected):
            # Chained tool has lost connection, we must handle it
            logger.debug("[wble-connect][output-pipe] received a disconnection notification, discard")
            return
        else:
            logger.debug("[wble-connect][output-pipe] forward default outbound message %s", message)
            # Forward other messages
            super().on_outbound(message)

class BleConnectApp(CommandLineDevicePipe):
    """Bluetooth Low-energy connection tool

    This command-line tool has one job: initiate a BLE connection to a specific
    device and then let another tool use it for whatever purpose it has.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy connection tool',
            interface=True,
            commands=False
        )

        self.add_argument('bdaddr', metavar='BDADDR', help='Target device BD address')
        self.add_argument(
            '--spoof-public',
            metavar='PUB_BD_ADDR',
            dest='bdaddr_pub_src',
            default=None,
            help='Spoof a public BD address'
        )

        self.add_argument(
            '--spoof-random',
            metavar='RAND_BD_ADDR',
            dest='bdaddr_rand_src',
            default=None,
            help='Spoof a random BD address'
        )

        # Add an optional random type argument
        self.add_argument(
            '-r',
            '--random',
            dest='random',
            action='store_true',
            default=False,
            help='Use a random connection type'
        )


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:
                # Make sure we are piped to another tool
                if self.is_stdout_piped() and not self.is_stdin_piped():
                    # Connect to the target device
                    self.connect_target(self.args.bdaddr, self.args.random)
                elif self.is_stdin_piped() and not self.is_stdout_piped():
                    # Connect to the target device once the previous tool
                    # gives us a unix socket.
                    self.connect_target_and_proxify(self.args.bdaddr, self.args.random)
                else:
                    self.error('Tool must be piped to another WHAD tool.')
            else:
                self.error('You need to specify an interface with option --interface.')

        except KeyboardInterrupt:
            self.warning("wble-connect stopped (CTL-C)")

        # Launch post-run tasks
        self.post_run()

    def set_bd_address(self, central: Central, bdaddr: str, public=True):
        """Set central BLE address
        """
        # Make sure it is a valid BD address
        if BDAddress.check(bdaddr):
            # Set the BD address
            if not central.set_bd_address(bdaddr, public=public):
                self.warning("Cannot spoof BD address, please make sure your WHAD interface supports this feature.")
        else:
            self.error(f"Invalid spoofed BD address: {bdaddr}")


    def connect_target_and_proxify(self, bdaddr, random_connection_type=False):
        """Connect to our target device and relay packets between input interface
        and our target.
        """
        # Make sure the bd address is valid
        if BDAddress.check(bdaddr):
            central = Central(self.interface)

            # Spoof source BD address if required
            if self.args.bdaddr_pub_src is not None:
                self.set_bd_address(central, self.args.bdaddr_pub_src, public=True)
            elif self.args.bdaddr_rand_src is not None:
                self.set_bd_address(central, self.args.bdaddr_rand_src, public=False)

            # Connect to our target device
            try:
                central.connect(bdaddr, random_connection_type)
                output_pipe = BleConnectInputPipe(BLE(self.input_interface), central)
                output_pipe.set_out_conn_handle(central.conn_handle)

                while self.input_interface.opened:
                    sleep(1)

            except PeripheralNotFound:
                # Could not connect
                self.error(f"Cannot connect to {bdaddr}")

    def connect_target(self, bdaddr, random_connection_type=False):
        """Connect to our target device
        """
        # Make sure the bd address is valid
        if BDAddress.check(bdaddr):
            # Configure our interface
            central = Central(self.interface)

            # Spoof source BD address if required
            if self.args.bdaddr_pub_src is not None:
                self.set_bd_address(central, self.args.bdaddr_pub_src, public=True)
            elif self.args.bdaddr_rand_src is not None:
                self.set_bd_address(central, self.args.bdaddr_rand_src, public=False)

            # Connect to our target device
            try:
                periph = central.connect(bdaddr, random_connection_type)

                # Get peers
                logger.info("local_peer: %s", central.local_peer)

                # Insanciate our output pipe
                proxy = UnixConnector(UnixSocketServerDevice(parameters={
                    'domain':'ble',
                    'conn_handle':periph.conn_handle,
                    'initiator_bdaddr':str(central.local_peer),
                    'initiator_addrtype':str(central.local_peer.type),
                    'target_bdaddr':str(central.target_peer),
                    'target_addrtype': str(central.target_peer.type)
                }))
                BleConnectOutputPipe(central, proxy)

                # Wait for device to disconnect (or user CTL-C)
                proxy.device.wait()

            except PeripheralNotFound:
                # Could not connect
                self.error(f"Cannot connect to {bdaddr}")
            finally:
                central.stop()
        else:
            self.error(f"Invalid BD address: {bdaddr}")


def ble_connect_main():
    """Main application wrapper.
    """
    app = BleConnectApp()
    run_app(app)
