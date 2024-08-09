"""This module provides a UnixSocketDevice class that can be used with a WhadDeviceConnector
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
from threading import Thread
from time import sleep
from random import randint
from binascii import hexlify

from whad.device import WhadDevice, WhadDeviceConnector
from whad.exceptions import WhadDeviceNotReady, WhadDeviceDisconnected
from whad.protocol.whad_pb2 import Message
from whad.hub.message import AbstractPacket
from scapy.config import conf

import logging
logger = logging.getLogger(__name__)

class UnixSocketDevice(WhadDevice):
    """
    UnixSocketDevice device class.
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
            # Read /proc/net/unix (Linux only)
            proc_net_unix = open('/proc/net/unix','r').read()

            # Extract all Unix sockets names, only keep those following the WHAD pattern:
            # whad_<random>.sock
            p = re.compile('^[0-9a-f]+: [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ (.*)$', re.I | re.M)
            for socket in p.findall(proc_net_unix):
                _, filename = os.path.split(socket)
                if re.match('whad_[0-9a-f]+\\.sock', filename):
                    dev = UnixSocketDevice(socket)
                    devices.append(dev)
            return devices
        except IOError as err:
            # Not supported, cannot enumerate devices
            return devices

    def __init__(self, path=None):
        """
        Create device connection
        """
        super().__init__()

        # Connect to target Unix Socket device in non-blocking mode
        self.__path = path
        self.__socket = None
        self.__client = None
        self.__opened = False

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
        pass


    def close(self):
        """
        Close current device.
        """
        logger.debug('[UnixSocketDevice] closing unix socket ...')
        # Close underlying device.
        if self.__socket is not None:
            self.__socket.close()

        # Clear fileno and status
        self.__fileno = None
        self.__opened = False

        # Ask parent class to stop I/O thread
        logger.debug('[UnixSocketDevice] stopping I/O thread')
        super().close()


    def write(self, data):
        """Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes data: Data to write
        :returns: number of bytes written to the device
        """
        logger.debug('sending data to unix socket: %s' % hexlify(data))
        if not self.__opened:
            raise WhadDeviceNotReady()

        nb_bytes_written = 0
        wlist = [self.__fileno]
        elist = [self.__fileno]
        readers,writers,errors = select.select(
            [],
            wlist,
            elist
        )

        if len(writers) > 0:
            nb_bytes_written = self.__socket.send(data)
        return nb_bytes_written

    def read(self):
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

            readers,writers,errors = select.select(
                rlist,
                wlist,
                elist,
                0.1
            )

            # Handle incoming messages if any
            if len(readers) > 0:
                data = self.__socket.recv(1024)
                if len(data) > 0:
                    self.on_data_received(data)
                else:
                    logger.debug('No data received from device')
                    raise WhadDeviceDisconnected()
            elif len(errors) > 0:
                raise WhadDeviceDisconnected()
        except ConnectionResetError as err:
            logger.error('Connection reset by peer')
        except Exception as err:
            raise WhadDeviceDisconnected()

    def change_transport_speed(self, speed):
        """Not supported by Unix socket devices.
        """
        pass

class UnixSocketServerDevice(WhadDevice):
    """Unix socket server device
    """

    INTERFACE_NAME = "unix_server"

    def __init__(self, path: str = None, parameters: dict = None):
        """Create a WHAD unix socket.
        """
        super().__init__()

        # Indicate if a timeout occured during opening
        self.__timedout = False

        # Create our Unix socket path
        if path is not None:
            # Use the provided Unix socket path
            self.__path = path
        else:
            # Generate socket path if not provided
            inst = randint(0x100000, 0x1000000)
            self.__path = '/tmp/whad_%x.sock' % inst

        logger.debug('Unix socket path: %s' % self.__path)

        # Make sure this path is available
        try:
            if os.path.exists(self.__path) and os.path.isfile(self.__path):
                logger.debug('Unix socket path exists, deleting file...')
                os.unlink(self.__path)
            elif os.path.exists(self.__path):
                logger.debug('Unix socket path exist but is not a file')
                raise WhadDeviceNotReady
        except IOError as err:
            logger.debug('Error while cleaning Unix socket path %s' % self.__path)
            raise WhadDeviceNotReady from err

        self.__socket = None
        self.__client = None
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
            return 'unix://%s\n' % (
                self.__path
            )
        else:
            params = '&'.join(['%s=%s' % item for item in self.__parameters.items()])
            return 'unix://%s?%s\n' % (
                self.__path,
                params
            )

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
                logger.debug('unix socket server got a connection from %s' % infos)
                self.__fileno = self.__client.fileno()
                logger.debug('fileno=%s' % self.__fileno)
                self.__opened = True

                # Ask parent class to run a background I/O thread
                super().open()
            except BrokenPipeError as err:
                logger.error('Broken pipe.')
                self.__client = None
            except TimeoutError as err:
                logger.info('Timed out.')
                self.__timedout = True
                self.__client = None
            except Exception as other_err:
                logger.error("Another exception occured: %s", other_err)
                pass

    def read(self):
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

            readers,writers,errors = select.select(
                rlist,
                wlist,
                elist,
                1
            )

            # Handle incoming messages if any
            if len(readers) > 0:
                data = self.__client.recv(1024)
                if len(data) > 0:
                    self.on_data_received(data)
                else:
                    logger.debug('No data received from client device')
                    raise WhadDeviceDisconnected()
            elif len(errors) > 0:
                raise WhadDeviceDisconnected()

        except ConnectionResetError as err:
            logger.debug('Connection reset by peer')
        except Exception as err:
            #logger.error('Unknown exception occured (%s)' % err)
            raise WhadDeviceDisconnected()

    def write(self, data):
        """Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes data: Data to write
        :returns: number of bytes written to the device
        """
        logger.debug('sending data to unix server client socket: %s' % hexlify(data))
        if not self.__opened:
            raise WhadDeviceNotReady()

        nb_bytes_written = 0
        wlist = [self.__fileno]
        elist = [self.__fileno]
        try:
            readers,writers,errors = select.select(
                [],
                wlist,
                elist
            )
        except TypeError:
            return 0

        if len(writers) > 0:
            nb_bytes_written = self.__client.send(data)
        elif len(errors) > 0:
            raise WhadDeviceDisconnected()
        return nb_bytes_written

    def close(self):
        """Close connection.
        """
        if self.__client is not None:
            self.__client.close()
        self.__fileno = None

    def reset(self):
        """Reset device.

        This method is not supported by this type of device.
        """
        pass

    def change_transport_speed(self, speed):
        """Not supported by Unix socket devices.
        """
        pass

class UnixConnector(WhadDeviceConnector):
    def __init__(self, device):
        super().__init__(device)
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

class UnixSocketConnector(WhadDeviceConnector):
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

        # Input pipes
        self.__inpipe = bytearray()

        # Parameters
        self.__parameters = {}

        # Shutdown require (to force exit in  ̀`serve()`)
        self.__shutdown_required = False

        # Initialize parent class (device connector)
        super().__init__(device)

        # Create our Unix socket path
        if path is not None:
            # Use the provided Unix socket path
            self.__path = path
        else:
            # Generate socket path if not provided
            inst = randint(0x100000, 0x1000000)
            self.__path = '/tmp/whad_%x.sock' % inst

        logger.debug('Unix socket path: %s' % self.__path)

        # Make sure this path is available
        try:
            if os.path.exists(self.__path) and os.path.isfile(self.__path):
                logger.debug('Unix socket path exists, deleting file...')
                os.unlink(self.__path)
            elif os.path.exists(self.__path):
                logger.debug('Unix socket path exist but is not a file')
                raise WhadDeviceNotReady
        except IOError as err:
            logger.debug('Error while cleaning Unix socket path %s' % self.__path)
            raise WhadDeviceNotReady

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

    def send_message(self, msg):
        self.device.send_message(msg)

    def on_data_received(self, data):
        logger.debug('received raw data from socket: %s' % hexlify(data))
        messages = []
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
                        logger.debug('WHAD message successfully parsed, forward to underlying device')
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
                while (len(self.__inpipe) >= 2):
                    if (self.__inpipe[0] != 0xAC) or (self.__inpipe[1] != 0xBE):
                        self.__inpipe = self.__inpipe[1:]
                    else:
                        break

    def shutdown(self):
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
                try:
                    while not self.__shutdown_required:
                        rlist = [self.__client.fileno()]
                        readers,writers,errors = select.select(rlist, [], rlist, timeout)

                        # Do we have pending data ?
                        if len(readers) > 0:
                            data = self.__client.recv(4096)
                            # Is socket closed ?
                            if len(data) == 0:
                                # Exit serve loop
                                break
                            else:
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
            logger.debug("Received a message (%s) from device, forward to client if any", message)
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

    def on_generic_msg(self, generic_message):
        """Callback function to process incoming generic messages.

        This method MUST be overriden by inherited classes.

        :param message: Generic message
        """

    def on_discovery_msg(self, discovery_message):
        pass

    def on_domain_msg(self, domain, domain_message):
        """Callback function to process incoming domain-related messages.

        This method MUST be overriden by inherited classes.

        :param message: Domain message
        """
        pass

    def on_packet(self, packet):
        """Callback function to process incoming packets.
        """
        pass

    def on_event(self, event):
        pass

    def get_url(self):
        """Return socket URL
        """
        if len(self.__parameters.keys()) == 0:
            return 'unix://%s\n' % (
                self.__path
            )
        else:
            params = '&'.join(['%s=%s' % item for item in self.__parameters.items()])
            return f"unix://{self.__path}?{params}\n"

class UnixSocketCallbacksConnector(UnixSocketConnector):
    """
    Unix Socket Callbacks Connector.

    Allows to configure callbacks to extract & alter the packet stream on the fly.
    """
    def __init__(self, device, path=None):
        super().__init__(device, path)
        conf.dot15d4_protocol = self.get_parameter('domain')

    def send_message(self, msg):
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
            return super().send_message(msg)


    def on_any_msg(self, msg):
        on_rx_packet = self.get_parameter('on_rx_packet_cb')
        if on_rx_packet is not None:

            if isinstance(msg, AbstractPacket):
                pkt = msg.to_packet()
                pkt = on_rx_packet(pkt)
                if pkt is None:
                    msg = None
                else:
                    msg = msg.from_packet(pkt)

        if msg is not None:
            return super().on_any_msg(msg)


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
        self.__canceled = False

        # Remove any previously set interface message filter
        self.__interface.set_queue_filter(None)

        # Connected, switch to a unix socket server
        self.__connector = connector(self.__interface)
        for param in self.__params:
            self.__connector.add_parameter(param, self.__params[param])

    @property
    def interface(self):
        return self.__interface

    @property
    def connector(self):
        return self.__connector

    def stop(self):
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
