"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML

from whad.cli.app import CommandLineApp, run_app
from whad.device.tcp import TCPSocketConnector
from whad.common.converters.scapy import ScapyConverter
from pprint import pprint 

logger = logging.getLogger(__name__)

from whad.device import WhadDevice, WhadDeviceConnector

class WebSocketConnector(WhadDeviceConnector):
    """Web socket server connector.

    This connector will create a websocket and accept a single connection
    to this socket. It will then forward every message receveived from the
    underlying WHAD device to the connected client, and the messages received
    from the client to the device (passthrough mode).
    """

    def __init__(self, device, address="127.0.0.1", port=12345):
        """Create a WebSocketConnector
        """
        # No client connected
        self.__client = None

        # Input pipes
        self.__inpipe = bytearray()

        # Socket
        self.__socket = None

        # Shutdown require (to force exit in  ̀`serve()`)
        self.__shutdown_required = False

        # Initialize parent class (device connector)
        super().__init__(device)

        # Create our TCP socket
        self.__address = address
        self.__port = port

        logger.debug("Web socket address and port: %s (%s)", str(self.__address),
                     str(self.__port))


    def on_data_received(self, data: bytes):
        """Handle incoming data and parse it.

        :param data: Incoming data
        :type data: bytes
        """
        '''
        logger.debug("received raw data from socket: %s", hexlify(data))
        self.__inpipe.extend(data)
        while len(self.__inpipe) > 2:
            # Is the magic correct ?
            if self.__inpipe[0] == 0xAC and self.__inpipe[1] == 0xBE:
                # Have we received a complete message ?
                if len(self.__inpipe) > 4:
                    msg_size = self.__inpipe[2] | (self.__inpipe[3] << 8)
                    if len(self.__inpipe) >= (msg_size+4):
                        raw_message = self.__inpipe[4:4+msg_size]

                        # Old parsing code
                        #_msg = Message()
                        #_msg.ParseFromString(bytes(raw_message))

                        # Parse our message with our Protocol Hub
                        _msg = self.hub.parse(bytes(raw_message))

                        # Send to device
                        if _msg is not None:
                            logger.debug(("WHAD message successfully parsed, "
                                        "forward to underlying device"))
                            self.device.send_message(_msg)

                            # Notify message
                            self.on_msg_sent(_msg)

                        # Chomp
                        self.__inpipe = self.__inpipe[msg_size + 4:]
                    else:
                        break
                else:
                    break
            else:
                # Nope, that's not a header
                while len(self.__inpipe) >= 2:
                    if (self.__inpipe[0] != 0xAC) or (self.__inpipe[1] != 0xBE):
                        self.__inpipe = self.__inpipe[1:]
                    else:
                        break
        '''

    def shutdown(self):
        """Shutdown TCP connection.
        """
        self.__shutdown_required = True

    def serve(self, timeout=None):
        """Serve TCP socket

        Forward data received through our TCP socket to the underlying device.

        :param float timeout: number of seconds to wait for incoming data
        """
        '''
        logger.debug('Creating TCP socket server')
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__socket.bind((self.__address, self.__port))
        self.__socket.listen()

        logger.debug("Waiting for TCP socket connection on %s (%s)",
                     self.__address, self.__port)

        try:
            while not self.__shutdown_required:
                self.__client,_ = self.__socket.accept()
                self.device.open()
                try:
                    while not self.__shutdown_required:
                        rlist = [self.__client.fileno()]
                        readers, _, errors = select.select(rlist, [], rlist, timeout)

                        # Do we have pending data ?
                        if len(readers) > 0:
                            data = self.__client.recv(4096)
                            # Is socket closed ?
                            if len(data) == 0:
                                # Exit serve loop
                                break

                            # Process received data
                            self.on_data_received(data)
                        elif len(errors) > 0:
                            logger.debug('Error detected on server socket, exiting.')
                            break
                except ConnectionResetError:
                    # Reset the underlying device
                    self.device.reset()


                self.__client = None

        except BrokenPipeError:
            logger.error('Broken pipe.')
            self.__client = None
        except Exception:
            pass
        '''
    # Message callbacks
    def on_any_msg(self, message):
        """Callback function to process incoming discovery messages.

        This method MUST be overriden by inherited classes.

        :param message: Discovery message
        """
        try:
            logger.debug('Received a message from device, forward to client if any')
            if self.__client is not None:
                # Convert message into bytes
                raw_message = message.serialize()

                # Define header
                header = [
                    0xAC, 0xBE,
                    len(raw_message) & 0xff,
                    (len(raw_message) >> 8) & 0xff
                ]

                # Send header followed by serialized message
                self.__client.send(bytes(header))
                self.__client.send(raw_message)
                logger.debug('Message sent to client')
        except BrokenPipeError:
            logger.debug('Client socket disconnected')

    def on_packet(self, packet):
        """Incoming packet handler.
        """
        print("[PKT]", packet)
        print("[DICT]")
        pprint(ScapyConverter.get_dict_from_scapy_packet(packet))
        print("[JSON]", ScapyConverter.get_json_from_scapy_packet(packet))
        print()

    def on_event(self, event):
        """Generic event handler.
        """

    def on_msg_sent(self, message):
        """Called when a message has successfully been sent.
        """

    def on_generic_msg(self, message):
        """Callback function to process incoming generic messages.

        This method MUST be overriden by inherited classes.

        :param message: Generic message
        :type message: HubMessage
        """

    def on_discovery_msg(self, message):
        """Callback method to process incoming discovery messages.

        :param message: Discovery message
        :type message: HubMessage
        """

    def on_domain_msg(self, domain, message):
        """Callback function to process incoming domain-related messages.

        This method MUST be overriden by inherited classes.

        :param message: Domain message
        """


class WhadServerApp(CommandLineApp):
    """Main wserver CLI application class.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description="WHAD server tool",
            interface=True,
            commands=False
        )



        self.add_argument(
            '-j',
            '--json',
            action='store_true',
            dest='json',
            default=False,
            help="Save as JSON"
        )

        self.add_argument(
            "--address",
            "-a",
            dest="address",
            action="store",
            default="127.0.0.1",
            help="IP address to use"
        )

        self.add_argument(
            "--port",
            "-p",
            dest="port",
            action="store",
            default="12345",
            help="Port to use"
        )

        # Initialize properties.
        self.address = None
        self.port = None
        self.server = None

    def run(self):
        """CLI application main routine.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            # Format address and port
            self.address = self.args.address
            self.port = int(self.args.port)

            # We need to have an interface specified
            if interface is not None:
                self.serve(interface)
            else:
                self.error("You have to provide an interface to proxify.")

        except KeyboardInterrupt:
            self.warning("Server stopped (CTRL-C)")

        if self.server is not None:
            self.server.shutdown()

        # Launch post-run tasks
        self.post_run()

    def serve(self, device):
        """
        Create a TCP proxy device according to provided address and port and serve forever.
        """
        print_formatted_text(HTML(
            f"<ansicyan>[i] Device proxy running on {self.address}:{self.port} </ansicyan>"
        ))

        if self.args.json:
            self.server = WebSocketConnector(device, self.address, self.port)
            self.server.serve()
            while True:
                import time
                time.sleep(1)
        else:
            # Setup a TCP server and await connections.
            self.server = TCPSocketConnector(device, self.address, self.port)
            self.server.serve()

def wserver_main():
    """Launcher for wserver.
    """
    app = WhadServerApp()
    run_app(app)
