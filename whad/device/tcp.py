"""This module provides a TCPSocketDevice class that can be used with a WhadDeviceConnector
to interact with a TCP socket connected to a Whad-enable device. This class implements
a TCP socket client that connects to a remote device through a TCP socket.

It also provides a dedicated connector to be used as a TCP socket server.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""
import logging
import socket
import select
import re

from ipaddress import ip_address

from whad.exceptions import WhadDeviceNotReady, WhadDeviceDisconnected, WhadDeviceNotFound
from whad.hub.message import HubMessage

from .device import Device
from .connector import Connector

logger = logging.getLogger(__name__)

def is_valid_hostname(hostname: str) -> bool:
    """Determine if a hostname is valid.

    :param hostname: Hostname to check
    :type hostname: str
    :return: `True` if hostname is valid, `False` otherwise.
    :rtype: bool
    """
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

class TcpSocket(Device):
    """
    TCP client class.
    """

    INTERFACE_NAME = "tcp"

    @classmethod
    def list(cls):
        '''
        Returns a list of available TCP socket devices.
        '''
        return None

    @classmethod
    def check_interface(cls, interface):
        '''
        This method checks dynamically if the provided interface can be instantiated.
        '''
        logger.info("Checking interface: %s", str(interface))
        if ":" in interface:
            host, port = interface.split(":")
            try:
                port = int(port)
            except ValueError:
                return False
        else:
            host = interface
            port = 12345

        try:
            ip_address(host)
        except ValueError:
            # It is not a valid IP address, is it a valid hostname ?
            if not is_valid_hostname(host):
                return False

        # We survived to previous code, let's check if we can establish a connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            return s.connect_ex((host, port)) == 0
        except:
            return False

    def __init__(self, interface):
        """
        Create device connection
        """
        super().__init__()

        # Connect to target TCP Socket device in non-blocking mode
        try:
            if isinstance(interface, tuple) and len(interface) == 2:
                self.__address = interface[0]
                self.__port = interface[1]
            elif isinstance(interface, str):
                if ":" in interface:
                    self.__address = interface.split(":")[0]
                    self.__port = int(interface.split(":")[1])
                else:
                    self.__address = interface
                    self.__port = 12345
            else:
                self.__address = None
                self.__port = None
        except ValueError:
            self.__address = None
            self.__port = None
        self.__socket = None
        self.__fileno = None
        self.__opened = False

    @property
    def identifier(self):
        '''
        Returns the identifier of the device (e.g., socket path).
        '''
        return str(self.__address) + ":" + str(self.__port)


    def open(self):
        """
        Open device.
        """
        if not self.__opened:
            try:
                # Open TCP socket
                self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.__socket.connect((self.__address, self.__port))
                self.__fileno = self.__socket.fileno()
                self.__opened = True
                # Ask parent class to run a background I/O thread
                super().open()
            except ConnectionRefusedError as conn_refused:
                logger.error('Connection refused')
                raise WhadDeviceNotFound from conn_refused

    def reset(self):
        """Reset device.

        This method is not supported by this type of device.
        """


    def close(self):
        """
        Close current device.
        """
        # Close underlying device.
        if self.__socket is not None:
            self.__socket.close()

        # Clear fileno and status
        self.__fileno = None
        self.__opened = False

        # Ask parent class to stop I/O thread
        super().close()


    def write(self, payload):
        """Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes payload: Data to write
        :returns: number of bytes written to the device
        """
        logger.debug("sending data to TCP socket: %s", data.hex())
        if not self.__opened:
            raise WhadDeviceNotReady()

        nb_bytes_written = 0
        wlist = [self.__fileno]
        elist = [self.__fileno]
        _, writers, __ = select.select(
            [],
            wlist,
            elist
        )

        if len(writers) > 0:
            nb_bytes_written = self.__socket.send(payload)
        return nb_bytes_written

    def read(self) -> bytes:
        """Fetches data from the device, if there is any data to read. We call select()
        to make sure data is waiting to be read before reading it. Data is then sent to
        our parsing method through on_data_received() that will handle data reassembling
        and message parsing and dispatch.
        """
        try:
            if not self.__opened:
                raise WhadDeviceNotReady()

            rlist = [self.__fileno]
            wlist = []
            elist = [self.__fileno]

            readers, _, __ = select.select(
                rlist,
                wlist,
                elist,
                1
            )

            # Handle incoming messages if any
            if len(readers) > 0:
                data = self.__socket.recv(1024)
                if len(data) > 0:
                    return data
                else:
                    #logger.error('No data received from device')
                    raise WhadDeviceDisconnected()
        except ConnectionResetError:
            logger.error('Connection reset by peer')
        except Exception as exc:
            raise WhadDeviceDisconnected() from exc

    def change_transport_speed(self, speed):
        """Not supported by TCP socket devices.
        """


class TCPSocketConnector(Connector):
    """TCP socket server connector.

    This connector will create a TCP socket and accept a single connection
    to this socket. It will then forward every message receveived from the
    underlying WHAD device to the connected client, and the messages received
    from the client to the device (passthrough mode).
    """

    def __init__(self, device, address="127.0.0.1", port=12345):
        """Create a TCPSocketConnector
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

        logger.debug("TCP socket address and port: %s (%s)", str(self.__address),
                     str(self.__port))

    def on_data_received(self, data: bytes):
        """Handle incoming data and parse it.

        :param data: Incoming data
        :type data: bytes
        """
        logger.debug("received raw data from socket: %s", data.hex())
        self.__inpipe.extend(data)
        while len(self.__inpipe) > 2:
            # Is the magic correct ?
            if self.__inpipe[0] == 0xAC and self.__inpipe[1] == 0xBE:
                # Have we received a complete message ?
                if len(self.__inpipe) > 4:
                    msg_size = self.__inpipe[2] | (self.__inpipe[3] << 8)
                    if len(self.__inpipe) >= (msg_size+4):
                        raw_message = self.__inpipe[4:4+msg_size]

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
        self.__shutdown_required = True

    def serve(self, timeout=None):
        """Serve TCP socket

        Forward data received through our TCP socket to the underlying device.

        :param float timeout: number of seconds to wait for incoming data
        """
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

    def on_event(self, event):
        """Generic event handler.
        """

    def on_msg_sent(self, message):
        """Called when a message has successfully been sent.
        """

    def on_generic_msg(self, message: HubMessage):
        """Callback function to process incoming generic messages.

        This method MUST be overriden by inherited classes.

        :param message: Generic message
        :type message: HubMessage
        """

    def on_discovery_msg(self, message: HubMessage):
        """Callback method to process incoming discovery messages.

        :param message: Discovery message
        :type message: HubMessage
        """

    def on_domain_msg(self, domain, message: HubMessage):
        """Callback function to process incoming domain-related messages.

        This method MUST be overriden by inherited classes.

        :param message: Domain message
        """
