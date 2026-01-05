"""This module provides a UnixSocket class that can be used with a WhadDeviceConnector
to interact with a unix socket connected to a Whad-enable device. This class implements
a Unix socket client that connects to a remote device through a Unix socket.

It also provides a dedicated connector to be used as a Unix socket server.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""

import sys
import os
import socket
import select
import re
import logging
from threading import Thread
from random import randint

from scapy.config import conf

from whad.exceptions import WhadDeviceNotReady, WhadDeviceDisconnected
from whad.hub.message import AbstractPacket

from .device import Device
from .connector import Connector

logger = logging.getLogger(__name__)

class UnixSocket(Device):
    """
    UnixSocket device class.
    """

    INTERFACE_NAME = "unix"

    @classmethod
    def list(cls):
        '''
        Returns a list of available Unix socket devices.

        To prevent identifying serial ports which are not compatible with WHAD, it implements
        a filtering mechanism based on vid, pid, manufacturer and / or product.
        '''
        devices = []

        try:
            with open("/proc/net/unix",'r', encoding="utf-8") as s:
                # Read /proc/net/unix (Linux only)
                proc_net_unix = s.read()

                # Extract all Unix sockets names, only keep those following the WHAD pattern:
                # whad_<random>.sock
                p = re.compile("^[0-9a-f]+: [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ (.*)$",
                            re.I | re.M)
                for socket_ in p.findall(proc_net_unix):
                    _, filename = os.path.split(socket_)
                    if re.match('whad_[0-9a-f]+\\.sock', filename):
                        dev = UnixSocket(socket_)
                        devices.append(dev)
            return devices
        except IOError:
            # Not supported, cannot enumerate devices
            return devices

    def __init__(self, path=None):
        """
        Create device connection
        """
        super().__init__()

        # Connect to target Unix Socket device in non-blocking mode
        self.__path = path
        self.__fileno = None
        self.__socket = None
        self.__opened = False
        self.__stalled = False

    @property
    def identifier(self):
        '''
        Returns the identifier of the device (e.g., socket path).
        '''
        return self.__path


    def open(self):
        """
        Open device.
        """
        if not self.__opened:
            # Open Unix socket
            self.__socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.__socket.connect(self.__path)
            self.__fileno = self.__socket.fileno()
            self.__opened = True

            # Ask parent class to run a background I/O thread
            super().open()


    def reset(self):
        """Reset device.

        This method is not supported by this type of device.
        """


    def close(self):
        """
        Close current device.
        """
        logger.debug('[UnixSocket] closing unix socket ...')
        # Close underlying device.
        if self.__socket is not None:
            self.__socket.close()

        # Clear fileno and status
        self.__fileno = None
        self.__opened = False

        # Ask parent class to stop I/O thread
        logger.debug('[UnixSocket] stopping I/O thread')
        super().close()


    def write(self, payload) -> int:
        """Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes data: Data to write
        :returns: number of bytes written to the device
        """
        logger.debug("sending data to unix socket: %s", payload.hex())
        if not self.__opened:
            raise WhadDeviceNotReady()

        logger.debug("[%s] fileno: %s", self.interface, self.__fileno)
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
            # If not opened, device is not ready
            if not self.__opened:
                raise WhadDeviceNotReady()

            rlist = [self.__fileno]
            wlist = [self.__fileno]
            elist = [self.__fileno]

            readers, _, errors = select.select(
                rlist,
                wlist,
                elist,
                1.0
            )

            # Handle incoming messages if any
            #print(readers, errors)
            if len(readers) > 0:
                data = self.__socket.recv(1024)
                logger.info("[%s] Read data from socket: %s", self.interface, data)
                if len(data) > 0:
                    return data
                else:
                    logger.info("[%s] Read data, received empty buffer", self.interface)
                    # Unix socket client is stalled if we have pending messages
                    if not self.busy():
                        # If no pending message then consider the socket disconnected
                        logger.debug("[%s] Socket closed by remote peer.",
                                     self.interface)
                        raise WhadDeviceDisconnected()
                    elif not self.__stalled:
                        logger.debug((
                            "[%s] There are pending messages awaiting "
                            "for processing, consider unix socket stalled."),
                                     self.interface)
                        self.__stalled = True

            elif len(errors) > 0:
                logger.info("[%s] Unix socket in error", self.interface)
                raise WhadDeviceDisconnected()
        except ConnectionResetError:
            logger.error('Connection reset by peer')
        except Exception as err:
            raise WhadDeviceDisconnected() from err

    def change_transport_speed(self, speed):
        """Not supported by Unix socket devices.
        """

class UnixSocketServer(Device):
    """Unix socket server device
    """

    INTERFACE_NAME = "unix_server"

    def __init__(self, path: str = None, parameters: dict = None):
        """Create a WHAD unix socket.
        """
        super().__init__()

        # Indicate if a timeout occurred during opening
        self.__timedout = False

        # Create our Unix socket path
        if path is not None:
            # Use the provided Unix socket path
            self.__path = path
        else:
            # Generate socket path if not provided
            inst = randint(0x100000, 0x1000000)
            self.__path = f"/tmp/whad_{inst:x}.sock"

        logger.debug("Unix socket path: %s", self.__path)

        # Make sure this path is available
        try:
            if os.path.exists(self.__path) and os.path.isfile(self.__path):
                logger.debug("Unix socket path exists, deleting file...")
                os.unlink(self.__path)
            elif os.path.exists(self.__path):
                logger.debug("Unix socket path exist but is not a file")
                raise WhadDeviceNotReady
        except IOError as err:
            logger.debug("Error while cleaning Unix socket path %s", self.__path)
            raise WhadDeviceNotReady from err

        self.__socket = None
        self.__client = None
        self.__fileno = None
        self.__opened = False

        # Set unix socket server parameters
        if parameters is not None:
            self.__parameters = parameters
        else:
            self.__parameters = {}


    @property
    def identifier(self):
        '''
        Returns the identifier of the device (e.g., socket path).
        '''
        return self.__path


    @property
    def opened(self):
        '''
        Returns if a client is connected on the UNIX socket.
        '''
        return self.__opened

    @property
    def timedout(self):
        '''
        Returns if a client timed out.
        '''
        return self.__timedout


    def add_parameter(self, key: str, value):
        """Add a parameter to this Unix Socket connector.

        :param str key: parameter key
        :param object value: associated value
        """
        self.__parameters[key] = value

    def get_parameter(self, key : str):
        """Get value from a parameter.

        :param str key: parameter key
        """
        try:
            return self.__parameters[key]
        except KeyError:
            return None

    def get_url(self):
        """Return socket URL
        """
        if len(self.__parameters.keys()) == 0:
            return "unix://{self.__path}\n"

        params = '&'.join(['%s=%s' % item for item in self.__parameters.items()])
        return f"unix://{self.__path}?{params}\n"

    def open(self):
        """Open socket server and wait for a connection.
        """
        if not self.__opened:
            try:
                self.__socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.__socket.settimeout(0.5)
                self.__socket.bind(self.__path)
                self.__socket.listen(5)

                logger.debug('Publishing unix socket info')
                sys.stdout.write(self.get_url())
                sys.stdout.flush()

                self.__client, infos = self.__socket.accept()
                logger.debug("unix socket server got a connection from %s", infos)
                self.__fileno = self.__client.fileno()
                logger.debug("fileno=%s", self.__fileno)
                self.__opened = True

                # Ask parent class to run a background I/O thread
                super().open()
            except BrokenPipeError:
                logger.error("Broken pipe.")
                self.__client = None
            except TimeoutError:
                logger.info("Timed out.")
                self.__timedout = True
                self.__client = None
            except Exception as other_err:
                logger.error("Another exception occurred: %s", other_err)

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

            readers, _, errors = select.select(
                rlist,
                wlist,
                elist,
                1
            )

            # Handle incoming messages if any
            if len(readers) > 0:
                data = self.__client.recv(1024)
                if len(data) > 0:
                    return data
                else:
                    logger.debug('No data received from client device')
                    raise WhadDeviceDisconnected()
            elif len(errors) > 0:
                raise WhadDeviceDisconnected()

        except ConnectionResetError:
            logger.debug('Connection reset by peer')
        except Exception as err:
            #logger.error('Unknown exception occurred (%s)' % err)
            raise WhadDeviceDisconnected() from err

    def write(self, payload):
        """Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes payload: Data to write
        :returns: number of bytes written to the device
        """
        logger.debug("sending data to unix server client socket: %s", payload.hex())
        if not self.__opened:
            raise WhadDeviceNotReady()

        nb_bytes_written = 0
        wlist = [self.__fileno]
        elist = [self.__fileno]
        try:
            _, writers, errors = select.select(
                [],
                wlist,
                elist,
                .2
            )
        except TypeError:
            return 0

        if len(writers) > 0:
            nb_bytes_written = self.__client.send(payload)
        elif len(errors) > 0:
            raise WhadDeviceDisconnected()
        return nb_bytes_written

    def close(self):
        """Close connection.
        """
        if self.__client is not None:
            logger.debug("Closing UnixSocketServer client ...")
            self.__client.close()
            logger.debug("Client closed")
        self.__fileno = None

    def reset(self):
        """Reset device.

        This method is not supported by this type of device.
        """

    def change_transport_speed(self, speed):
        """Not supported by Unix socket devices.
        """

class UnixConnector(Connector):
    """Dummy connector for Unix socket.

    Connector is locked by default.
    """

    def __init__(self, device, locked: bool = True):
        """Create a locked connector.
        """
        if locked:
            # Create an empty connector, attach to no device
            super().__init__(None)

            # Lock connector
            self.lock()

            # Attach to device
            self.set_device(device)
            device.set_connector(self)
        else:
            #Create a dummy connector.
            super().__init__(device)

        # Open device if not already opened
        if not device.opened:
            # Unix socket server has already sent some messages but is now
            # closed, the previous tool must have finished earlier. We don't
            # need to open the socket again (it would fail) but simply consider
            # it open in order to process messages.
            if device.busy():
                logger.debug("[%s] Unix socket has sent messages and closed.",
                             device.interface)
            else:
                # Open socket if no pending message
                device.open()

    def on_discovery_msg(self, message):
        pass

    def on_generic_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        pass

    def on_packet(self, packet):
        pass

    def on_event(self, event):
        pass

class UnixSocketConnector(Connector):
    """Unix socket server connector.

    This connector will create a Unix socket and accept a single connection
    to this socket. It will then forward every message receveived from the
    underlying WHAD device to the connected client, and the messages received
    from the client to the device (passthrough mode).

    WHAD Device <-> Unix socket (created)
    """

    def __init__(self, device, path=None):
        """Create a UnixSocketConnector
        """
        # No client connected
        self.__client = None
        self.__socket = None

        # Input pipes
        self.__inpipe = bytearray()

        # Parameters
        self.__parameters = {}

        # Shutdown require (to force exit in  ̀`serve()`)
        self.__shutdown_required = False

        # Initialize parent class (device connector)
        super().__init__(None)
        self.lock()
        self.set_device(device)
        device.set_connector(self)

        # Create our Unix socket path
        if path is not None:
            # Use the provided Unix socket path
            self.__path = path
        else:
            # Generate socket path if not provided
            inst = randint(0x100000, 0x1000000)
            self.__path = f"/tmp/whad_{inst:x}.sock"

        logger.debug("Unix socket path: %s", self.__path)

        # Make sure this path is available
        try:
            if os.path.exists(self.__path) and os.path.isfile(self.__path):
                logger.debug('Unix socket path exists, deleting file...')
                os.unlink(self.__path)
            elif os.path.exists(self.__path):
                logger.debug('Unix socket path exist but is not a file')
                raise WhadDeviceNotReady
        except IOError as err:
            logger.debug("Error while cleaning Unix socket path %s", self.__path)
            raise WhadDeviceNotReady from err

    def add_parameter(self, key: str, value):
        """Add a parameter to this Unix Socket connector.

        :param str key: parameter key
        :param object value: associated value
        """
        self.__parameters[key] = value

    def get_parameter(self, key : str):
        """Get value from a parameter.

        :param str key: parameter key
        """
        try:
            return self.__parameters[key]
        except KeyError:
            return None

    def send_message(self, message, keep=None):
        """Send message into the unix socket.
        """
        logger.debug("[%s] sending message %s", self.device.interface, message)
        self.device.send_message(message, keep=keep)

    def on_data_received(self, data):
        """Handle received data from the unix socket.
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

                        # Parse message using our Protocol Hub
                        _msg = self.hub.parse(bytes(raw_message))

                        # Send to device
                        logger.debug(("WHAD message successfully parsed, "
                                     "forward to underlying device"))
                        self.send_message(_msg)

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

    def process_message(self, message):
        """Process received message.
        """
        # Send to device
        logger.debug(("WHAD message successfully parsed, "
                        "forward to underlying device"))
        self.send_message(message)

        # Notify message
        self.on_msg_sent(message)

    def shutdown(self):
        """Shutdown unix socket.
        """
        self.__shutdown_required = True

    def serve(self, timeout=None):
        """Serve Unix socket

        Forward data received through our Unix socket to the underlying device.

        :param float timeout: number of seconds to wait for incoming data
        """
        logger.debug('Creating Unix socket server')
        self.__socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.__socket.settimeout(0.5)
        self.__socket.bind(self.__path)
        self.__socket.listen(5)

        logger.debug('Publishing unix socket info')
        sys.stdout.write(self.get_url())
        sys.stdout.flush()

        try:
            while not self.__shutdown_required:
                self.__client,_ = self.__socket.accept()
                self.unlock()
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
                    logger.error("connection reset")

                self.__client = None

        except BrokenPipeError:
            logger.error("Broken pipe.")
            self.__client = None
        except TimeoutError:
            logger.debug("Timeout error.")
            self.__client = None
        except Exception as other_err:
            logger.debug("Unknown error of type %s: %s", type(other_err), other_err)

    # Message callbacks
    def on_any_msg(self, message):
        """Callback function to process incoming discovery messages.

        This method MUST be overriden by inherited classes.

        :param message: Discovery message
        """
        try:
            logger.debug("Received a message (%s) from device, forward to client if any (%s)", message, self.__client)
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

    def on_msg_sent(self, message):
        """Outgoing message handler, actually doing nothing but needed by
        classes that inherit from WhadDeviceConnector.
        """

    def on_generic_msg(self, message):
        """Callback function to process incoming generic messages.

        This method MUST be overriden by inherited classes.

        :param message: Generic message
        """

    def on_discovery_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        """Callback function to process incoming domain-related messages.

        This method MUST be overriden by inherited classes.

        :param message: Domain message
        """

    def on_packet(self, packet):
        """Callback function to process incoming packets.
        """

    def on_event(self, event):
        """Handle generic WHAD events.
        """

    def get_url(self):
        """Return socket URL
        """
        if len(self.__parameters.keys()) == 0:
            return f"unix://{self.__path}\n"

        params = '&'.join(["%s=%s" % item for item in self.__parameters.items()])
        return f"unix://{self.__path}?{params}\n"

class UnixSocketCallbacksConnector(UnixSocketConnector):
    """
    Unix Socket Callbacks Connector.

    Allows to configure callbacks to extract & alter the packet stream on the fly.
    """
    def __init__(self, device, path=None):
        super().__init__(device, path)
        conf.dot15d4_protocol = self.get_parameter('domain')

    def send_message(self, message, keep=None):
        """Send message to unix socket.
        """
        on_tx_packet = self.get_parameter('on_tx_packet_cb')
        if on_tx_packet is not None:
            if isinstance(msg, AbstractPacket):
                pkt = msg.to_packet()
                pkt = on_tx_packet(pkt)
                if pkt is None:
                    msg = None
                else:
                    msg = msg.from_packet(pkt)

        if msg is not None:
            return super().send_message(message, keep=keep)

        return None


    def on_any_msg(self, message):
        """Handle any incoming message.
        """
        on_rx_packet = self.get_parameter('on_rx_packet_cb')
        if on_rx_packet is not None:

            if isinstance(message, AbstractPacket):
                pkt = message.to_packet()
                if pkt is None:
                    msg = None
                else:
                    pkt = on_rx_packet(pkt)
                    msg = msg.from_packet(pkt)

        if msg is not None:
            return super().on_any_msg(msg)

        return None


class UnixSocketProxy(Thread):
    """Unix socket proxy thread.

    This class provides a convenient way to start a WHAD device proxy
    over a Unix socket, while outputing the socket URL on stdout with
    a set of parameters that will be passed to the next (piped) tool.
    """

    def __init__(self, interface, params, connector=UnixSocketConnector):
        """Create a Unix socket proxy.

        :param WhadDevice   interface   WHAD interface to proxify
        :param dict         params      Dictionnary of params to pass to the next tool
        """
        super().__init__()
        self.__interface = interface
        self.__params = params

        # Remove any previously set interface message filter
        self.__interface.set_queue_filter(None)

        # Connected, switch to a unix socket server
        self.__connector = connector(self.__interface)
        for param in self.__params:
            self.__connector.add_parameter(param, self.__params[param])

    @property
    def interface(self):
        """Get the underlying interface.
        """
        return self.__interface

    @property
    def connector(self):
        """Get the underlying connector.
        """
        return self.__connector

    def stop(self):
        """Stop Unix socket proxy.
        """
        self.__connector.shutdown()

    def run(self):
        """Run device proxy thread.

        This method removes the previous connector associated with the underlying
        device interface (WhadDevice) and connects its own. This connector will
        create a Unix server socket and wait for client connection, and send the
        related URL to stdout along with the provided parameters.

        This method ends when client disconnects.
        """
        self.__connector.serve()
