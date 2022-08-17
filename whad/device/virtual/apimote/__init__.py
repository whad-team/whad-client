from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual.apimote.constants import APIMoteId, APIMoteRegisters
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from serial import Serial,PARITY_NONE
from serial.tools.list_ports import comports
from whad.device.uart import get_port_info
from whad.scapy.layers.apimote import GoodFET_Command_Hdr, GoodFET_Reply_Hdr, GoodFET_Init_Reply, \
    GoodFET_Peek_Command, GoodFET_Monitor_Connected_Command, GoodFET_Peek_Reply, \
    GoodFET_Setup_CCSPI_Command, GoodFET_Setup_CCSPI_Reply,GoodFET_Transfer_Command, \
    GoodFET_Transfer_Reply, GoodFET_Poke_Reply, GoodFET_Poke_Command, CC_VERSIONS
from struct import pack
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
        for apimote in [
                        uart_dev for uart_dev in comports() if
                            (
                            uart_dev.vid == APIMoteId.APIMOTE_ID_VENDOR and
                            uart_dev.pid == APIMoteId.APIMOTE_ID_PRODUCT
                            )
                        ]:
            available_devices.append(APIMoteDevice(apimote.device))
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., serial port).
        '''
        return self.__port


    def __init__(self, port, baudrate=115200):
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
        self.__synced = False
        self.__last_reply = None

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

            self.__input_data = b""
            self.__uart.dtr = False             # Non reset state
            self.__uart.rts = False             # Non reset state
            self.__uart.dtr = self.__uart.dtr   # usbser.sys workaround

            # Ask parent class to run a background I/O thread
            super().open()

            self._dev_id = b"\xFF"*16

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

        while not self.__synced:
            sleep(0.1)

        self._setup_ccspi()
        if self._peek_ccspi(APIMoteRegisters.MANFIDL) != 0x233D:
            raise WhadDeviceNotReady()

        print(self._peek_ccspi(APIMoteRegisters.MANFIDH))

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

    def _send_goodfet_cmd(self, cmd, app="MONITOR", reply_filter=None):
        self.write(raw(GoodFET_Command_Hdr(app=app)/cmd))
        if reply_filter is not None and callable(reply_filter):
            while self.__last_reply is None or not reply_filter(self.__last_reply):
                sleep(0.1)
            matched_reply = self.__last_reply
            self.__last_reply = None
            return matched_reply

    def _process_goodfet_reply(self, reply):
        print("reply", repr(reply))

        if GoodFET_Init_Reply in reply and reply.url == b"http://goodfet.sf.net/":
            self.__synced = True
            self._monitor_connected()
        elif self.__synced:
            self.__last_reply = reply

    def _process_input_data(self, data):
        print(data)
        self.__input_data += data
        if len(self.__input_data) >= 4:
            reply_length = (self.__input_data[2] | self.__input_data[3] << 8) + 4
            if len(self.__input_data) >= reply_length:
                self._process_goodfet_reply(GoodFET_Reply_Hdr(self.__input_data[:reply_length]))
                self.__input_data = self.__input_data[reply_length:]

    def _monitor_connected(self):
        self._send_goodfet_cmd(GoodFET_Monitor_Connected_Command())


    def _strobe_ccspi(self, register=0x00):
        data = bytes([register])
        status = self._transfer_ccspi(data)
        return status[0]


    def _poke_ccspi(self, register, value):
        data = bytes([
            register,
            0xFF & (value >> 8) ,
            (value & 0xFF)]
        )
        reply = self._send_goodfet_cmd(
                                        GoodFET_Poke_Command(address=address),
                                        app="CCSPI"
        )
        return self._peek_ccspi(register) == value

    def _peek_ccspi(self, register):
        address = bytes([register, 0 , 0 ])
        reply = self._send_goodfet_cmd(
                                        GoodFET_Peek_Command(address=address),
                                        app="CCSPI",
                                        reply_filter=lambda reply:GoodFET_Peek_Reply in reply
        )
        value = 0
        for i in range(1,len(reply.data)):
            value |= (reply.data[i] << (len(reply.data)-i-1)*8)
        return value

    def _transfer_ccspi(self, data):
        reply = self._send_goodfet_cmd(
                                        GoodFET_Transfer_Command(data=data),
                                        app="CCSPI",
                                        reply_filter = lambda reply:GoodFET_Transfer_Reply in reply
        )
        return reply.data

    def _setup_ccspi(self):
        reply = self._send_goodfet_cmd(
                                        GoodFET_Setup_CCSPI_Command(),
                                        app="CCSPI",
                                        reply_filter = lambda reply:GoodFET_Setup_CCSPI_Reply in reply
        )
        return reply

    def _monitor_peek(self, address, size=8):
        if size == 8:
            reply = self._send_goodfet_cmd(
                                            GoodFET_Peek_Command(address=pack("H", address)),
                                            reply_filter=lambda reply:GoodFET_Peek_Reply in reply
            )
            return reply.data[0]
        elif size == 16:
            reply_low = self._send_goodfet_cmd(
                                                GoodFET_Peek_Command(address=pack("H", address)),
                                                reply_filter=lambda reply:GoodFET_Peek_Reply in reply
            )
            reply_high = self._send_goodfet_cmd(
                                                GoodFET_Peek_Command(address=pack("H", address)+1),
                                                reply_filter=lambda reply:GoodFET_Peek_Reply in reply
            )
            return reply_low.data[0] + (reply_high.data[0] << 8)
        else:
            return None
