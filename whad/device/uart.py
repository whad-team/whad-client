"""This module provides a UartDevice class that can be used with a WhadDeviceConnector
to interact with a WHAD-enable firmware device that uses UART as its transport layer.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""

import os
import select
from threading import Lock
from serial import Serial

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotReady
from whad.protocol.whad_pb2 import Message

class UartDevice(WhadDevice):
    """
    UartDevice device class.
    """

    def __init__(self, port='/dev/ttyUSB0', baudrate=115200):
        """
        Create device connection
        """
        super().__init__()

        # Connect to target UART device in non-blocking mode
        self.__port = port
        self.__baudrate = baudrate
        self.__fileno = None
        self.__uart = None
        self.__opened = False


    def open(self):
        """
        Open device.
        """
        if not self.__opened:
            # Open UART device
            self.__uart = Serial(self.__port, self.__baudrate)

            # Get file number to use with select()
            self.__fileno = self.__uart.fileno()
            self.__opened = True

            # Ask parent class to run a background I/O thread
            super().open()

    def close(self):
        """
        Close current device.
        """
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        self.__uart.close()
        self.__uart = None
        self.__fileno = None
        self.__opened = False       

    def write(self, data):
        """Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to. 

        :param bytes data: Data to write
        :returns: number of bytes written to the device
        """
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
            nb_bytes_written = os.write(self.__fileno, data)
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
            data = os.read(self.__fileno, 1024)
            self.on_data_received(data)
