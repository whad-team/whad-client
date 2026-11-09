"""This module provides a UartIface class that can be used with a WhadDeviceConnector
to interact with a WHAD-enable firmware device that uses UART as its transport layer.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""

import os
import re
import select
from time import sleep
from queue import Empty

# Import serial
from serial import Serial
from serial.tools.list_ports import comports

from whad.exceptions import WhadDeviceNotReady, WhadDeviceError
from whad.helpers import message_filter
from whad.exceptions import WhadDeviceNotFound

from whad.hub.generic.cmdresult import CommandResult, Success
from whad.hub.discovery import DeviceReady

from .device import Device

SUPPORTED_UART_DEVICES = (
    (0xc0ff, 0xeeee, "WHAD", "ButteRFly dongle"), # Butterfly Dongle
    (0x303A, None, None, None),   # Espressif ESP-32 board
    (0x10C4, 0xEA60, None, None), # Espressif ESP-32 CP2102 board
    (0x0483, 0x374e, None, None), # Nucleo WL55
)

# Largest baud rate pyserial takes on Linux (a C int): a larger trailing
# field of a port name is not read as a baud rate
MAX_BAUDRATE = 2**31 - 1

def get_port_info(port):
    """Find information about a serial port

    :param string port: Target serial port
    """
    for p in comports():
        if p.device == port:
            return p
    return None

def is_device_supported(vid, pid, manufacturer, product):
    """Check if a device is supported by WHAD.
    """
    for devinfo in SUPPORTED_UART_DEVICES:
        _vid, _pid, _manuf, _product = devinfo
        if _vid is not None and _vid != vid:
            continue
        if _pid is not None and _pid != pid:
            continue
        if _manuf is not None and _manuf != manufacturer:
            continue
        if _product is not None and _product != product:
            continue

        # Device is supported.
        return True

    # Device is not supported.
    return False

class Uart(Device):
    """
    UartIface device class.
    """
    INTERFACE_NAME = "uart"

    @classmethod
    def list(cls):
        '''
        Returns a list of available UART devices.

        To prevent identifying serial ports which are not compatible with WHAD, it implements
        a filtering mechanism based on vid, pid, manufacturer and / or product.

        A serial port left out by this filter can still be used by naming it,
        see `create_inst()`.
        '''

        devices = []
        for uart_dev in comports():
            if is_device_supported(uart_dev.vid, uart_dev.pid, uart_dev.manufacturer,
                                   uart_dev.product):
                dev = Uart(uart_dev.device, baudrate=115200)
                devices.append(dev)
        return devices

    @classmethod
    def create_inst(cls, interface_string):
        '''
        Returns the UART device an interface string designates:

        - `uart`, `uart0`, `uart1`, ...: a supported device, by its index in
          `list()`
        - `uart:<port>`: the serial port `<port>` (e.g. `/dev/ttyACM0`, `COM3`)
        - `uart:<port>:<baudrate>`: the same at a given baud rate (115200 by
          default), e.g. `uart:/dev/ttyACM0:230400`

        A named serial port is used regardless of its USB IDs, so that a WHAD
        device behind a USB-serial bridge left out by `list()` can be opened.
        On POSIX systems, a port that is a symbolic link (e.g. in
        `/dev/serial/by-id/`) is resolved to the port it points to. A
        trailing field that is not a baud rate from 1 to 2**31-1 is read as
        part of the port name.
        '''
        named = re.match(
            r'^' + cls.INTERFACE_NAME
            + r':(?P<port>.+?)(:(?P<baudrate>[1-9]\d*))?$',
            interface_string
        )
        if named is None:
            return super().create_inst(interface_string)

        port, baudrate = named.group('port', 'baudrate')
        if baudrate is not None and int(baudrate) > MAX_BAUDRATE:
            port, baudrate = f"{port}:{baudrate}", None

        # comports() names a port by its device node, not by a link to it.
        # Windows port names (COM3) are not looked up on the filesystem.
        if os.name == 'posix' and os.path.islink(port):
            port = os.path.realpath(port)

        if baudrate is not None:
            return cls(port, baudrate=int(baudrate))

        # A supported device is returned as listed
        for dev in cls.list():
            if dev.identifier == port:
                return dev
        return cls(port)


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

        # Determine if device is CDC ACM (usb subsystem)
        port_info = get_port_info(self.__port)
        if port_info is None:
            raise WhadDeviceNotFound

        # 'subsystem' is only defined on Linux serial ports, we check if
        # this property is missing to handle Mac OS (Windows system is
        # marked as unsupported for now)
        if not hasattr(port_info, "subsystem"):
            # Determine if device is ACM on Mac OS
            self.__is_acm = port_info.usb_info is not None
        else:
            # On Linux systems, ACM devices use the "usb" subsystem.
            self.__is_acm = port_info.subsystem == "usb"

    @property
    def identifier(self):
        '''
        Returns the identifier of the device (e.g., serial port).
        '''
        return self.__port

    def is_acm(self):
        """Determine if this UART device is a CDC ACM one.

        :return: True if CDC ACM, False otherwise.
        """
        return self.__is_acm


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

            # If device is CDC ACM, we don't need to reset it
            # only reset true serial devices
            if not self.__is_acm:
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
        # If device is a true serial device, ask for a reset through DTR/RTS
        if not self.__is_acm:
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
                    message_filter(DeviceReady)
                )
                self.put_message(msg)
            except Empty:
                # Use the classic way to reset device (RTS-based reset failed)
                msg = self.hub.discovery.create_reset_query()
                self.send_command(
                    msg,
                    message_filter(DeviceReady)
                )
        else:
            # Device is ACM, send a classic reset message to device
            msg = self.hub.discovery.create_reset_query()
            self.send_command(
                msg,
                message_filter(DeviceReady)
            )


    def close(self):
        """
        Close current device.
        """
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        if self.__uart is not None:
            self.__uart.close()
        self.__uart = None
        self.__fileno = None
        self.__opened = False

    def write(self, payload):
        """Writes payload to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes payload: Data to write
        :returns: number of bytes written to the device
        """
        try:
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
                nb_bytes_written = os.write(self.__fileno, payload)
            return nb_bytes_written
        except OSError as os_error:
            raise WhadDeviceError("Sending data to WHAD device failed.") from os_error

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

        readers, _, __ = select.select(
            rlist,
            wlist,
            elist,
            1
        )

        if not self.__opened:
            raise WhadDeviceNotReady()

        # Handle incoming messages if any
        if len(readers) > 0 and self.__fileno is not None:
            data = os.read(self.__fileno, 1024)

            # Make sure data is not empty (detect device disconnection/malfunction)
            if len(data) == 0 :
                # Device does not behave as expected, may not be ready.
                raise WhadDeviceNotReady()

            # Feed our IO thread with received data
            return data

        # Nothing to read
        return None

    def change_transport_speed(self, speed):
        """Set UART speed for true serial devices. CDC ACM devices will ignore
        it.

        :param int speed: New baudrate to apply to current serial device.
        """
        if not self.__is_acm:
            #msg = Message()
            #msg.discovery.set_speed.speed = speed
            msg = self.hub.discovery.create_set_speed(speed)
            resp = self.send_command(
                msg,
                message_filter(CommandResult)
            )

            if isinstance(resp, Success):
                # Change baudrate
                self.__uart.baudrate = speed

                # Wait for device to be ready (500ms)
                sleep(0.5)
