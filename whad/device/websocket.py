"""This module provides a WebSocketDevice class that can be used with a WhadDeviceConnector
to interact with a WebSocket connected to a Whad-enable device. This class implements
a WebSocket client that connects to a remote device through a WebSocket.

It also provides a dedicated connector to be used as a WebSocket server.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""
from whad.device import WhadDevice, WhadDeviceConnector
from whad.common.converters.scapy import ScapyConverter
from websockets.sync.server import serve
from websockets.exceptions import ConnectionClosedOK
from time import sleep
from binascii import hexlify

import threading
import logging

logger = logging.getLogger(__name__)


class WebSocketConnector(WhadDeviceConnector):
    """Web socket server connector.

    This connector will create a websocket and accept a single connection
    to this socket. It will then forward every message received from the
    underlying WHAD device to the connected client, and the messages received
    from the client to the device (passthrough mode).
    """

    def __init__(self, device, address="127.0.0.1", port=12345, json_mode=False):
        """Create a WebSocketConnector
        """

        # JSON mode
        self.__json_mode = json_mode

        # Input pipes
        self.__inpipe = bytearray()

        # Connected clients
        self.__clients = []

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

    def shutdown(self):
        """Shutdown TCP connection.
        """
        if self.__socket is not None:
            self.__socket.shutdown()


    def handler(self, websocket):
        """Handle a WebSocket client.
        
        :param websocket: websocket connection instance
        """
        logger.debug("New websocket connection on %s (%d)", websocket.remote_address[0], websocket.remote_address[1])
        self.__clients.append(websocket)
        for data in websocket:
            self.on_data_received(data)

    def serve(self, timeout=None):
        """Serve TCP socket

        Forward data received through our TCP socket to the underlying device.

        :param float timeout: number of seconds to wait for incoming data
        """
        logger.debug('Creating WebSocket server')

        self.server = serve(self.handler, self.__address, self.__port)
        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        while not self.__shutdown_required:
            logger.debug("Waiting for WebSocket connection on %s (%s)",
                     self.__address, self.__port)

            while len(self.__clients) == 0:
                sleep(0.1)

            self.device.open()

            while len(self.__clients) > 0:
                sleep(0.1)

            self.device.reset()


    # Message callbacks
    def on_any_msg(self, message):
        """Callback function to process incoming discovery messages.

        This method MUST be overriden by inherited classes.

        :param message: Discovery message
        """
        if not self.__json_mode:
            logger.debug('Received a message from device, forward to clients if any')
            
            for client in self.__clients:
                # Convert message into bytes
                raw_message = message.serialize()

                # Define header
                header = [
                    0xAC, 0xBE,
                    len(raw_message) & 0xff,
                    (len(raw_message) >> 8) & 0xff
                ]
                try:
                    # Send header followed by serialized message
                    client.send(bytes(header))
                    client.send(raw_message)
                    logger.debug('Message sent to client')
                except ConnectionClosedOK:
                    logger.debug('Connection closed, message dropped.')

    def on_packet(self, packet):
        """Incoming packet handler.
        """
        if self.__json_mode:
            # Convert received packet to JSON and forwards it to connected clients
            for client in self.__clients:
                try:
                    client.send(ScapyConverter.get_json_from_scapy_packet(packet))
                except ConnectionClosedOK:
                    logger.debug('Connection closed, message dropped.')
                    
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

"""
class TestWebSocketServer:
    def __init__(self, address, port):
        self.__client = []
        self.address = address
        self.port = port

    def helloall(self):
        for client in self.__client:
            client.send("hello all")

    def echo(self, websocket):
        address, port = websocket.remote_address
        self.__client.append(websocket)
        for message in websocket:
            websocket.send("hello " + message)
            

    def close(self):
        self.server.shutdown()

    def serve(self):
        self.server = serve(self.echo, self.address, self.port)
        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        #server_thread.join()
        #self.server.serve_forever()

s = TestWebSocketServer("localhost", 8000)
try:
    import time
    s.serve()
    while True:
        s.helloall()
        time.sleep(5)
except KeyboardInterrupt:
    s.close()
"""