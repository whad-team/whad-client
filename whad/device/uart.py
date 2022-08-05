"""This module provides a UartDevice class that can be used with a WhadDeviceConnector
to interact with a WHAD-enable firmware device that uses UART as its transport layer.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""

from asyncio import QueueEmpty
import os
import select
from threading import Lock
from serial import Serial
from time import sleep
from queue import Empty

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotReady
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter
from whad.protocol.device_pb2 import DeviceResetQuery
from whad.protocol.generic_pb2 import ResultCode

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

            self.__uart.dtr = False             # Non reset state
            self.__uart.rts = False             # Non reset state
            self.__uart.dtr = self.__uart.dtr   # usbser.sys workaround

            # Ask parent class to run a background I/O thread
            super().open()


    def reset(self):
        """Reset device.

        This routine tries to reset device by setting RTS to high. This works
        on NodeMCU chips as well as any Arduino-compatible device.
        """
        # Reset device through DTR
        self.__uart.dtr = False             # Non reset state
        self.__uart.rts = True             # Non reset state
        sleep(0.2)
        self.__uart.dtr = False             # Non reset state
        self.__uart.rts = False             # Non reset state

        try:
            # Wait for a ready message for 1 second
            msg = self.wait_for_single_message(
                1.0,
                message_filter('discovery', 'ready_resp')
            )
            self.dispatch_message(msg)
        except Empty:
            # Use the classic way to reset device (RTS-based reset failed)
            msg = Message()
            msg.discovery.reset_query.CopyFrom(DeviceResetQuery())
            self.send_command(
                msg,
                message_filter('discovery', 'ready_resp')
            )
        


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

    def change_transport_speed(self, speed):
        """Set UART speed
        """
        msg = Message()
        msg.discovery.set_speed.speed = speed
        resp = self.send_command(
            msg,
            message_filter('generic', 'cmd_result')
        )

        if (resp.generic.cmd_result.result == ResultCode.SUCCESS):
            # Change baudrate
            self.__uart.baudrate = speed

            # Wait for device to be ready (500ms)
            sleep(0.5)