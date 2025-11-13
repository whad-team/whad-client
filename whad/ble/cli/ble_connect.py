"""Bluetooth Low Energy connect tool

This utility will configure a compatible whad device to connect to a given
BLE device, and chain this with another tool.
"""
import sys
import logging
from time import sleep

# WHAD device classes
from whad.device.unix import UnixConnector, UnixSocketServer
from whad.device import Bridge

# WHAD BLE interfaces
from whad.ble import Central
from whad.device.connector import LockedConnector
from whad.ble.exceptions import PeripheralNotFound

# WHAD BLE messages
from whad.hub.ble import BlePduReceived, BleRawPduReceived, Connected, \
    Disconnected, SendBlePdu, SendBleRawPdu
from whad.hub.ble.bdaddr import BDAddress

# WHAD CLI helper
from whad.cli.app import CommandLineDevicePipe, run_app

logger = logging.getLogger(__name__)

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

    def __init__(self, input_connector, output_connector, out_handle, target_bdaddr):
        """Initialize our wble-connect input pipe.
        """
        logger.debug('[wble-connect][output-pipe] Initialization')

        # Do we get raw PDUs ?
        if output_connector.support_raw_pdu():
            self.support_raw_pdu = True
        else:
            self.support_raw_pdu = False

        # Save output handle
        self.__out_handle = out_handle
        self.__target_bdaddr = target_bdaddr

        # Initialize bridge
        super().__init__(input_connector, output_connector)

        # Unlock connectors
        output_connector.unlock(dispatch_callback=self.dispatch_pending_output_pdu)
        input_connector.unlock(dispatch_callback=self.dispatch_pending_input_pdu)

    def dispatch_pending_input_pdu(self, message):
        """Dispatch pending PDU.
        """
        logger.info("Dispatching input pdu %s", message)

        # Send message to our chained tool
        command = self.convert_packet_message(message, self.__out_handle)
        self.output.send_command(command)

    def dispatch_pending_output_pdu(self, message):
        """Dispatch pending out PDUs (received)
        """
        logger.info("Dispatching output pdu %s", message)
        self.input.send_message(message)

    def convert_packet_message(self, message, conn_handle: int):
        """Convert a BleRawPduReceived/BlePduReceived notification into the
        corresponding SendBleRawPdu/SendBlePdu command, using the provided
        connection handle.
        """
        # Do we received a packet notification ?
        logger.debug("[wble-connect][output-pipe] convert message %s into a command", message)
        if isinstance(message, BleRawPduReceived):
            # Does our input connector support raw packets ?
            if self.output.support_raw_pdu():
                logger.debug('[wble-connect][output-pipe] connector supports raw pdu')
                # Create a SendBleRawPdu command
                command = self.output.hub.ble.create_send_raw_pdu(
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
                command = self.output.hub.ble.create_send_pdu(
                    message.direction,
                    message.pdu,
                    conn_handle, # overwrite the connection handle
                    encrypt=False
                )
                logger.debug("[wble-connect][output-pipe] created command %s", command)
        elif isinstance(message, BlePduReceived):
            # Does our input connector support raw packets ?
            if self.output.support_raw_pdu():
                logger.debug('[wble-connect][output-pipe] connector supports raw pdu')
                # Create a SendBleRawPdu command
                command = self.output.hub.ble.create_send_raw_pdu(
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
                command = self.output.hub.ble.create_send_pdu(
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
        if isinstance(message, (BleRawPduReceived, BlePduReceived)):
            logger.debug(
                "[wble-connect][output-pipe] received an inbound PDU message %s",
                message
            )
            self.input.send_message(message)
        elif isinstance(message, Disconnected):
            # Peripheral disconnected, we lock the input
            logger.debug("[wble-connect][output-pipe] Peripheral disconnected, locking input")
        elif isinstance(message, Connected):
            # We are now again connected to the target device, unlock input to
            # process any incoming message and save output connection handle
            print("Connected to %s" % self.__target_bdaddr)
            logger.debug("[wble-connect][output-pipe] Peripheral connected, updating connection handle")
            self.__out_handle = message.conn_handle
            logger.debug("[wble-connect][output-pide] Unlocking input ...")
            self.input_wrapper.unlock()
            logger.debug("[wble-connect][output-pide] Input unlocked ...")
        else:
            logger.debug("[wble-connect][output-pipe] forward default inbound message %s", message)
            # Forward other messages
            super().on_inbound(message)

    def on_outbound(self, message):
        """Process outbund messages.

        We monitor these messages to catch the connection handle used by our chained
        tool (upstream) in order to send valid commands.
        """
        if isinstance(message, (BleRawPduReceived, BlePduReceived)):
            if self.__out_handle is not None:
                logger.debug(
                    "[wble-connect][output-pipe] received an outbound PDU message %s",
                    message
                )
                command = self.convert_packet_message(message, self.__out_handle)
                self.output.send_command(command)
        elif isinstance(message, Connected):
            # A client has reconnected
            logger.error("A client has reconnected, reconnect to our target ...")
            print("Connecting to %s" % self.__target_bdaddr)
            connect = self.output.hub.ble.create_connect_to(
                self.__target_bdaddr
            )
            logger.debug("Sending connect message: %s", connect)
            self.output.send_command(connect)
        elif isinstance(message, Disconnected):
            logger.error("Client has disconnected, disconnect from device")
            self.input_wrapper.lock()

            # Create a disconnection message from scratch and send it to our output.
            disconnect = self.output.hub.ble.create_disconnect(
                self.__out_handle
            )
            self.__out_handle = None
            logger.debug("[wble-connect][output-pipe] Disconnecting target device ...")
            self.output.send_command(disconnect)
        elif isinstance(message, (SendBlePdu, SendBleRawPdu)):
            # These messages are sent by unlocked connectors that translate packets
            # into corresponding send commands
            # We just need to update the connection handle and forward them.
            message.conn_handle = self.__out_handle
            self.output.send_command(message)
        else:
            logger.debug(
                "[wble-connect][output-pipe] forward default outbound message %s",
                message
            )
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

            # We need a BD address to be set
            if self.args.bdaddr is not None:
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
                self.warning((
                    "Cannot spoof BD address, please make sure your WHAD interface "
                    "supports this feature."
                ))
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
                # Lock central to avoid any PDU processing
                central.lock()

                # Connect to a device
                print("Connecting to %s" % bdaddr)
                periph = central.connect(bdaddr, random_connection_type)
                print("Connected: %d" % periph.conn_handle)

                # Create our bridge: it will drive the connection process
                BleConnectInputPipe(
                    LockedConnector(self.input_interface),
                    central,
                    periph.conn_handle,
                    BDAddress(bdaddr, random=random_connection_type)
                )

                while self.input_interface.opened:
                    sleep(.2)

            except PeripheralNotFound:
                # Could not connect
                self.error(f"Cannot connect to {bdaddr}")

    def connect_target(self, bdaddr, random_connection_type=False):
        """Connect to our target device
        """
        # Make sure the bd address is valid
        if BDAddress.check(bdaddr):
            # Configure our interface (Central with PDU queue)
            logger.debug("Using CentralProxy")
            central = Central(self.interface)
            central.lock()

            # Spoof source BD address if required
            if self.args.bdaddr_pub_src is not None:
                self.set_bd_address(central, self.args.bdaddr_pub_src, public=True)
            elif self.args.bdaddr_rand_src is not None:
                self.set_bd_address(central, self.args.bdaddr_rand_src, public=False)

            # Connect to our target device
            try:
                # Output current status on stderr
                logger.info("[wble-connect::connect_target] Connecting to %s ...", bdaddr)
                sys.stderr.write(f"Connecting to {bdaddr} ...\n")
                sys.stderr.flush()

                # Connect to target device
                periph = central.connect(bdaddr, random_connection_type)

                # We are connected
                logger.info("[wble-connect::connect_target] Connected to %s", bdaddr)
                sys.stderr.write(f"Connected to {bdaddr}\n")
                sys.stderr.flush()

                # Get peers
                logger.info("local_peer: %s", central.local_peer)

                # Insanciate our output pipe
                proxy = UnixConnector(UnixSocketServer(parameters={
                    'domain':'ble',
                    'conn_handle':periph.conn_handle,
                    'initiator_bdaddr':str(central.local_peer),
                    'initiator_addrtype':str(central.local_peer.type),
                    'target_bdaddr':str(central.target_peer),
                    'target_addrtype': str(central.target_peer.type)
                }))

                # Create our custom pipe
                bridge = Bridge(central, proxy)

                # Wait for our bridge to gracefully terminate...
                bridge.join()

            except PeripheralNotFound:
                # Could not connect
                logger.info("[wble-connect::connect_target] Cannot connect to %s", bdaddr)
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
