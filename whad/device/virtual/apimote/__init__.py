from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual.apimote.constants import APIMoteId, APIMoteRegisters, APIMoteRegistersMasks
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad import WhadDomain, WhadCapability
from whad.domain.zigbee.utils.phy import channel_to_frequency, frequency_to_channel
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.zigbee.zigbee_pb2 import Sniff, Send, Start, Stop
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from serial import Serial,PARITY_NONE
from serial.tools.list_ports import comports
from whad.device.uart import get_port_info
from whad.scapy.layers.apimote import GoodFET_Command_Hdr, GoodFET_Reply_Hdr, GoodFET_Init_Reply, \
    GoodFET_Peek_Command, GoodFET_Monitor_Connected_Command, GoodFET_Peek_Reply, \
    GoodFET_Setup_CCSPI_Command, GoodFET_Setup_CCSPI_Reply,GoodFET_Transfer_Command, \
    GoodFET_Transfer_Reply, GoodFET_Poke_Reply, GoodFET_Poke_Command, GoodFET_Peek_RAM_Command, \
    GoodFET_Poke_RAM_Command, GoodFET_Peek_RAM_Reply, GoodFET_Poke_RAM_Reply, CC_VERSIONS
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

        self._dev_id = self._generate_dev_id(port_info)
        self._fw_author = self._get_author()
        self._fw_url = self._get_firmware_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Zigbee : (
                                (WhadCapability.Sniff | WhadCapability.Inject),
                                [Sniff, Send, Start, Stop]
            )
        }
        return capabilities

    def _generate_dev_id(self, port_info):
        dev_id = (
                        port_info.serial_number.encode('utf-8') +
                        pack("H", port_info.vid) +
                        pack("H", port_info.pid)
        )
        dev_id = b"\x00"*(16 - len(dev_id)) + dev_id
        return dev_id

    def _get_firmware_version(self):
        return (4, 0, 0) # APIMote v4 beta

    def _get_author(self):
        return "Ryan Speers".encode("utf-8")

    def _get_firmware_url(self):
        # Maybe we should replace it by GoodFET URL ?
        return "https://github.com/riverloopsec/apimote".encode("utf-8")

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

        self._init_radio()

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


    def _strobe_ccspi(self, register):
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
                                        GoodFET_Poke_Command(data=data),
                                        app="CCSPI",
                                        reply_filter=lambda reply:GoodFET_Poke_Reply in reply
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

    def _peek_ram(self, address, count=4):
        reply = self._send_goodfet_cmd(
                                        GoodFET_Peek_RAM_Command(address=address, count=count),
                                        app="CCSPI",
                                        reply_filter = lambda reply:GoodFET_Peek_RAM_Reply in reply
        )
        return reply.data

    def _poke_ram(self, address, value):
        data = bytes([address & 0xFF, (address & 0xFF00) >> 8]) + value
        reply = self._send_goodfet_cmd(
                                        GoodFET_Poke_RAM_Command(data=data),
                                        app="CCSPI",
                                        reply_filter = lambda reply:GoodFET_Poke_RAM_Reply in reply
        )

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

    def _init_radio(self):
        self._setup_crystal_oscillator()
        self._setup_rf_calibration()
        self._configure_mdmctrl0(
                                    auto_ack=False,
                                    auto_crc=False,
                                    leading_zeroes=3,
                                    hardware_access_decoding=False,
                                    pan_coordinator=False,
                                    reserved_accepted=False
        )
        self._configure_mdmctrl1(demodulator_thresold=20)
        self._configure_iocfg0(filter_beacons=False)

        print(self._get_frequency())
        print(self._set_frequency(2425))
        print(self._get_frequency())

    def _get_rssi(self):
        return self._peek_ccspi(APIMoteRegisters.RSSI)

    def _setup_crystal_oscillator(self):
        # Must be performed two times for some reason. See GOODFETCCSPI.py in Killerbee drivers.
        self._strobe_ccspi(APIMoteRegisters.SXOSCON)
        self._strobe_ccspi(APIMoteRegisters.SXOSCON)

    def _setup_rf_calibration(self):
        self._strobe_ccspi(APIMoteRegisters.STXCAL)

    def _switch_rf_to_idle(self):
        self._strobe_ccspi(APIMoteRegisters.SRFOFF)

    def _switch_rf_to_rx(self):
        self._strobe_ccspi(APIMoteRegisters.SRXON)

    def _switch_rf_to_tx(self):
        self._strobe_ccspi(APIMoteRegisters.STXON)

    def _get_syncword(self):
        return self._peek_ccspi(APIMoteRegisters.SYNCWORD)

    def _set_syncword(self, syncword = 0xA70F):
        return self._poke_ccspi(APIMoteRegisters.SYNCWORD, syncword)

    def _get_channel(self):
        return frequency_to_channel(self._get_frequency())

    def _set_channel(self, channel):
        self._set_frequency(channel_to_frequency(channel))

    def _get_frequency(self):
        masks = APIMoteRegistersMasks.FSCTRL
        fsctrl_value = self._peek_ccspi(APIMoteRegisters.FSCTRL)
        frequency_offset = (fsctrl_value & masks.FREQ.mask) >> masks.FREQ.offset
        return 2048+frequency_offset

    def _set_frequency(self, frequency):
        masks = APIMoteRegistersMasks.FSCTRL
        fsctrl_value = self._peek_ccspi(APIMoteRegisters.FSCTRL)
        self._poke_ccspi( APIMoteRegisters.FSCTRL,
                            (fsctrl_value & ~(masks.FREQ.mask << masks.FREQ.offset)) |
                            ((int(frequency - 2048) & masks.FREQ.mask) << masks.FREQ.offset)
        )
        self._setup_rf_calibration()
        sleep(0.01)
        self._switch_rf_to_rx()

    def _configure_mdmctrl0(self, auto_ack=False, auto_crc=False, leading_zeroes=4, hardware_access_decoding=False, pan_coordinator=False, reserved_accepted=False):
        masks = APIMoteRegistersMasks.MDMCTRL0
        return self._poke_ccspi(APIMoteRegisters.MDMCTRL0,
            (
                ((int(reserved_accepted) & masks.RESERVED_FRAME_MODE.mask) << masks.RESERVED_FRAME_MODE.offset) |
                ((int(pan_coordinator) & masks.PAN_COORDINATOR.mask) << masks.PAN_COORDINATOR.offset) |
                ((int(hardware_access_decoding) & masks.ADR_DECODE.mask) << masks.ADR_DECODE.offset) |
                ((2 & masks.CCA_MODE.mask) << masks.CCA_HYST.offset) |
                ((3 & masks.CCA_MODE.mask) << masks.CCA_MODE.offset) |
                ((int(auto_ack) & masks.AUTO_ACK.mask) << masks.AUTO_ACK.offset) |
                ((int(auto_crc) & masks.AUTO_CRC.mask) << masks.AUTO_CRC.offset) |
                ((leading_zeroes-1 & masks.PREAMBLE_LENGTH.mask) << masks.PREAMBLE_LENGTH.offset)
            )
        )


    def _configure_mdmctrl1(self, demodulator_thresold=20):
        masks = APIMoteRegistersMasks.MDMCTRL1
        return self._poke_ccspi(APIMoteRegisters.MDMCTRL1,
            (
                ((demodulator_thresold & masks.CORR_THR.mask) << masks.CORR_THR.offset) |
                ((0 & masks.DEMOD_AVG_MODE.mask) << masks.DEMOD_AVG_MODE.offset) |
                ((0 & masks.MODULATION_MODE.mask) << masks.MODULATION_MODE.offset) |
                ((0 & masks.TX_MODE.mask) << masks.TX_MODE.offset) |
                ((0 & masks.RX_MODE.mask) << masks.RX_MODE.offset)
            )
        )

    def _configure_iocfg0(self, filter_beacons=False):
        masks = APIMoteRegistersMasks.IOCFG0
        return self._poke_ccspi(APIMoteRegisters.IOCFG0,
            (
                ((int(not filter_beacons) & masks.BCN_ACCEPT.mask) << masks.BCN_ACCEPT.offset) |
                ((0 & masks.FIFO_POLARITY.mask) << masks.FIFO_POLARITY.offset) |
                ((0 & masks.FIFOP_POLARITY.mask) << masks.FIFOP_POLARITY.offset) |
                ((0 & masks.SFD_POLARITY.mask) << masks.SFD_POLARITY.offset) |
                ((0 & masks.CCA_POLARITY.mask) << masks.CCA_POLARITY.offset) |
                ((0x7F & masks.FIFOP_THR.mask) << masks.FIFOP_THR.offset)
            )
        )

    def _configure_secctrl0(self, enable_cbcmac=False, M=4, rx_key_select=0, tx_key_select=1, sa_key_select=1):
        masks = APIMoteRegistersMasks.SECCTRL0
        return self._poke_ccspi(APIMoteRegisters.SECCTRL0,
            (
                ((0 & masks.RXFIFO_PROTECTION.mask) << masks.RXFIFO_PROTECTION.offset) |
                ((1 & masks.SEC_CBC_HEAD.mask) << masks.SEC_CBC_HEAD.offset) |
                ((sa_key_select & masks.SEC_SAKEYSEL.mask) << masks.SEC_SAKEYSEL.offset) |
                ((tx_key_select & masks.SEC_TXKEYSEL.mask) << masks.SEC_TXKEYSEL.offset) |
                ((rx_key_select & masks.SEC_RXKEYSEL.mask) << masks.SEC_RXKEYSEL.offset) |
                ((int((M-2)//2) & masks.SEC_M.mask) << masks.SEC_M.offset) |
                ((int(enable_cbcmac) & masks.SEC_MODE.mask) << masks.SEC_MODE.offset)
            )
        )
