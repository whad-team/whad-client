from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from serial import Serial,PARITY_NONE
from serial.tools.list_ports import comports
from whad.device.uart import get_port_info
from whad.scapy.layers.apimote import GoodFET_Hdr,GoodFET_Init_Reply
from scapy.compat import raw
from time import sleep
import select
import os

class APIMoteDevice(VirtualDevice):

    INTERFACE_NAME = "apimote"

    @classmethod
    def list(cls):
        '''
        Returns a list of available APIMote devices.
        '''
        available_devices = []
        for apimote in [uart_dev for uart_dev in comports() if uart_dev.vid == 0x0403 and uart_dev.pid == 0x6015]:
            available_devices.append(APIMoteDevice(apimote.device))
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., serial port).
        '''
        return self.__port


    def __init__(self, index=0, port='/dev/ttyUSB1', baudrate=115200):
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
        port_info = get_port_info(self.__port)
        if port_info is None:
            raise WhadDeviceNotFound()


    def open(self):
        """
        Open device.
        """
        if not self.__opened:
            # Open UART device
            self.__uart = Serial(self.__port, self.__baudrate, parity = PARITY_NONE)


            # Get file number to use with select()
            self.__fileno = self.__uart.fileno()
            self.__opened = True
            self.__synced = False

            self.__input_data = b""
            self.__uart.dtr = False             # Non reset state
            self.__uart.rts = False             # Non reset state
            self.__uart.dtr = self.__uart.dtr   # usbser.sys workaround

            # Ask parent class to run a background I/O thread
            super().open()


    def reset(self):
        """Reset device.

        This routine tries to reset device by setting RTS to high.
        """
        # If device is a true serial device, ask for a reset through DTR/RTS
        # Reset device through DTR
        self.__uart.dtr = False             # Non reset state
        self.__uart.rts = True             # Non reset state
        sleep(0.2)
        self.__uart.dtr = False             # Non reset state
        self.__uart.rts = False             # Non reset state

    def read(self):

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
            self._process_input_data(data)


    def write(self, cmd):
        """Writes command to the device. It relies on select() in order to make sure
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
            nb_bytes_written = os.write(self.__fileno, raw(cmd))
        return nb_bytes_written


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

    def _process_goodfet_reply(self, reply):
        if GoodFET_Init_Reply in reply and reply.url == "http://goodfet.sf.net/":
            self.synced = True

    def _process_input_data(self, data):
        self.__input_data += data
        if len(self.__input_data) >= 4:
            reply_length = (self.__input_data[2] | self.__input_data[3] << 8) + 4
            if len(self.__input_data) >= reply_length:
                self._process_goodfet_reply(GoodFET_Hdr(self.__input_data[:reply_length]))
                self.__input_data = self.__input_data[reply_length:]
