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
from whad.exceptions import WhadDeviceNotReady
from whad.protocol.whad_pb2 import Message

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
                if re.match('whad_[0-9a-f]+\.sock', filename):
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
        # Close underlying device.
        if self.__socket is not None:
            self.__socket.close()
        
        # Unlink socket path
        if os.path.exists(self.__path):
            os.unlink(self.__path)
        
        # Clear fileno and status
        self.__fileno = None
        self.__opened = False

        # Ask parent class to stop I/O thread
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
            data = self.__socket.recv(1024)
            self.on_data_received(data)

    def change_transport_speed(self, speed):
        """Not supported by Unix socket devices.
        """
        pass


class UnixSocketConnector(WhadDeviceConnector):
    """Unix socket server connector.

    This connector will create a Unix socket and accept a single connection
    to this socket. It will then forward every message receveived from the
    underlying WHAD device to the connected client, and the messages received
    from the client to the device (passthrough mode).
    """

    def __init__(self, device, path=None):
        """Create a UnixSocketConnector
        """
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

        # No client connected
        self.__client = None
        
        # Input pipes
        self.__inpipe = bytearray()

        # Parameters
        self.__parameters = {}

    def add_parameter(self, key: str, value):
        """Add a parameter to this Unix Socket connector.

        :param str key: parameter key
        :param object value: associated value
        """
        self.__parameters[key] = value


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
                        _msg = Message()
                        _msg.ParseFromString(bytes(raw_message))
                        logger.debug('WHAD message successfully parsed, forward to underlying device')
                        self.device.send_message(_msg)
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

    def serve(self, timeout=None):
        """Serve Unix socket

        Forward data received through our Unix socket to the underlying device.

        :param float timeout: number of seconds to wait for incoming data
        """
        logger.debug('Creating Unix socket server')
        self.__socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.__socket.bind(self.__path)
        self.__socket.listen(1)

        logger.debug('Publishing unix socket info')
        sys.stdout.write(self.get_url())
        sys.stdout.flush()

        try:
            self.__client,_ = self.__socket.accept()
            while True:
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
        except ConnectionResetError as err:
            logger.debug('Client closed connection.')
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
                raw_message = message.SerializeToString()

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
        except BrokenPipeError as err:
            logger.debug('Client socket disconnected')


    def on_generic_msg(self, generic_message):
        """Callback function to process incoming generic messages.

        This method MUST be overriden by inherited classes.

        :param message: Generic message
        """
        pass

    def on_discovery_msg(self, discovery_message):
        pass

    def on_domain_msg(self, domain, domain_message):
        """Callback function to process incoming domain-related messages.

        This method MUST be overriden by inherited classes.

        :param message: Domain message
        """
        pass

    def get_url(self):
        """Return socket URL
        """
        if len(self.__parameters.keys()) == 0:
            return 'unix://%s' % (
                self.__path
            )
        else:
            params = '&'.join(['%s=%s' % item for item in self.__parameters.items()])
            return 'unix://%s?%s\n' % (
                self.__path,
                params
            )

class UnixSocketProxy(Thread):
    """Unix socket proxy thread.

    This class provides a convenient way to start a WHAD device proxy
    over a Unix socket, while outputing the socket URL on stdout with
    a set of parameters that will be passed to the next (piped) tool.
    """

    def __init__(self, interface, params):
        """Create a Unix socket proxy.

        :param WhadDevice   interface   WHAD interface to proxify
        :param dict         params      Dictionnary of params to pass to the next tool
        """
        super().__init__()
        self.__interface = interface
        self.__params = params

    def run(self):
        """Run device proxy thread.

        This method removes the previous connector associated with the underlying
        device interface (WhadDevice) and connects its own. This connector will
        create a Unix server socket and wait for client connection, and send the
        related URL to stdout along with the provided parameters.

        This method ends when client disconnects.
        """
        # Connected, switch to a unix socket server
        unix_serv = UnixSocketConnector(self.__interface)
        for param in self.__params:
            unix_serv.add_parameter(param, self.__params[param])    
        unix_serv.serve()