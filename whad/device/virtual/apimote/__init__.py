from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual.apimote.constants import APIMoteId, APIMoteRegisters, APIMoteRegistersMasks, \
    APIMoteInternalStates
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad import WhadDomain, WhadCapability
from whad.zigbee.utils.phy import channel_to_frequency, frequency_to_channel
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.dot15d4.dot15d4_pb2 import Sniff, Send, Start, Stop
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from serial import Serial,PARITY_NONE
from serial.tools.list_ports import comports
from whad.device.uart import get_port_info
from whad.scapy.layers.apimote import GoodFET_Command_Hdr, GoodFET_Reply_Hdr, GoodFET_Init_Reply, \
    GoodFET_Peek_Command, GoodFET_Monitor_Connected_Command, GoodFET_Peek_Reply, \
    GoodFET_Setup_CCSPI_Command, GoodFET_Setup_CCSPI_Reply,GoodFET_Transfer_Command, \
    GoodFET_Transfer_Reply, GoodFET_Poke_Reply, GoodFET_Poke_Command, GoodFET_Peek_RAM_Command, \
    GoodFET_Poke_RAM_Command, GoodFET_Peek_RAM_Reply, GoodFET_Poke_RAM_Reply, \
    GoodFET_Read_RF_Packet_Command, GoodFET_Read_RF_Packet_Reply, GoodFET_Send_RF_Packet_Command, \
    GoodFET_Send_RF_Packet_Reply, CC_VERSIONS
from struct import pack, unpack
from scapy.layers.dot15d4 import Dot15d4FCS
from scapy.compat import raw
from threading import Thread
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
        self.__packet_polling = False
        self.__polling_thread = Thread(target=self._polling, daemon=True)

        self.__internal_state = APIMoteInternalStates.NONE
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
            WhadDomain.Dot15d4 : (
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
        self.__polling_thread.start()

        self._setup_ccspi()
        while self._peek_ccspi(APIMoteRegisters.MANFIDL) != 0x233D:
            sleep(0.1)

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
        self.__opened = False
        self.__polling_thread.join()
        self.__uart.close()
        self.__uart = None
        self.__fileno = None

    def _send_whad_dot15d4_raw_pdu(self, packet, rssi=None):
        pdu = packet[:-2]
        fcs = unpack("H",packet[-2:])[0]
        is_fcs_valid = Dot15d4FCS().compute_fcs(pdu) == packet[-2:]
        timestamp = None

        msg = self.hub.dot15d4.create_raw_pdu_received(
            self._get_channel(),
            pdu,
            fcs,
            fcs_validity=is_fcs_valid
        )

        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp

        self._send_whad_message(msg)

    def _polling(self):
        while self.__opened:
            if self.__packet_polling:
                if self._packet_queue is None:
                    packet = self._get_packet()
                    if packet is not None:
                        rssi = self._get_rssi()
                        packet_size = packet[0]
                        # size of packet + 1-byte long length field
                        if packet_size + 1 < len(packet):
                            packet, self._packet_queue = packet[1:packet_size+1], (packet[packet_size+2:], rssi)
                            self._send_whad_dot15d4_raw_pdu(packet, rssi)
                        else:
                            self._send_whad_dot15d4_raw_pdu(packet[1:], rssi)
                else:
                    packet, rssi = (self._packet_queue,rssi)
                    self._packet_queue = None
                    self._send_whad_dot15d4_raw_pdu(packet, rssi)

    # Virtual device whad message callbacks
    def _on_whad_dot15d4_stop(self, message):
        if self._switch_rf_to_idle():
            self.__internal_state = APIMoteInternalStates.NONE
            self.__packet_polling = False
            self._send_whad_command_result(ResultCode.SUCCESS)
        else:
            self._send_whad_command_result(ResultCode.ERROR)


    def _on_whad_dot15d4_send_raw(self, message):
        #print("here")
        channel = message.channel
        if self._set_channel(channel):
            packet = message.pdu
            old_state = self.__internal_state
            #self._switch_rf_to_tx()
            self.__internal_state = APIMoteInternalStates.TRANSMITTING
            self._configure_mdmctrl0(auto_crc=True)
            success = self._send_packet(packet)
            self._configure_mdmctrl0(auto_crc=False)


            if old_state == APIMoteInternalStates.SNIFFING:
                self._switch_rf_to_rx()
                self.__internal_state = APIMoteInternalStates.SNIFFING
            else:
                self._switch_rf_to_idle()
                self.__internal_state = APIMoteInternalStates.NONE

        else:
            success = False
        self._send_whad_command_result(ResultCode.SUCCESS if success else ResultCode.ERROR)


    def _on_whad_dot15d4_sniff(self, message):
        channel = message.channel
        if self._set_channel(channel):
            self.__internal_state = APIMoteInternalStates.SNIFFING
            self._send_whad_command_result(ResultCode.SUCCESS)
        else:
            self._send_whad_command_result(ResultCode.PARAMETER_ERROR)

    def _on_whad_dot15d4_start(self, message):
        if self.__internal_state == APIMoteInternalStates.SNIFFING:
            if self._switch_rf_to_rx():
                self._packet_queue = None
                self.__packet_polling = True
                self._send_whad_command_result(ResultCode.SUCCESS)
            else:
                self._send_whad_command_result(ResultCode.ERROR)
        elif self.__internal_state == APIMoteInternalStates.NONE:
            self._switch_rf_to_idle()
            self._send_whad_command_result(ResultCode.SUCCESS)

    # APIMote / GoodFET low level primitives
    def _send_goodfet_cmd(self, cmd, app="MONITOR", reply_filter=None):
        #print("> cmd", repr(GoodFET_Command_Hdr(app=app)/cmd))
        self.write(raw(GoodFET_Command_Hdr(app=app)/cmd))
        if reply_filter is not None and callable(reply_filter):
            while self.__last_reply is None or not reply_filter(self.__last_reply):
                sleep(0.001)
            matched_reply = self.__last_reply
            self.__last_reply = None
            return matched_reply

    def _process_goodfet_reply(self, reply):
        #print("< reply", repr(reply))

        if GoodFET_Init_Reply in reply and reply.url == b"http://goodfet.sf.net/":
            self.__synced = True
            self._monitor_connected()
        elif self.__synced:
            self.__last_reply = reply

    def _process_input_data(self, data):
        #print(data)

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


    def _setup_ccspi(self):
        reply = self._send_goodfet_cmd(
                                        GoodFET_Setup_CCSPI_Command(),
                                        app="CCSPI",
                                        reply_filter = lambda reply:GoodFET_Setup_CCSPI_Reply in reply
        )
        return reply

    def _show_registers(self):
        '''
        Show current value of main registers (debugging purposes).
        '''
        print("MDMCTRL0", hex(self._peek_ccspi(APIMoteRegisters.MDMCTRL0)))
        print("MDMCTRL1", hex(self._peek_ccspi(APIMoteRegisters.MDMCTRL1)))
        print("IOCFG0", hex(self._peek_ccspi(APIMoteRegisters.IOCFG0)))
        print("SECCTRL0", hex(self._peek_ccspi(APIMoteRegisters.SECCTRL0)))

    # APIMote RF-related primitives
    def _init_radio(self):
        """
        Configure the radio as promiscuous and switch to idle.
        """
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
        self._configure_secctrl0(
                                    enable_cbcmac=False,
                                    M=4,
                                    rx_key_select=0,
                                    tx_key_select=1,
                                    sa_key_select=1
        )
        self._switch_rf_to_idle()


    def _get_packet(self):
        """
        Return RX packet (if any is available).
        """
        reply = self._send_goodfet_cmd(
                                GoodFET_Read_RF_Packet_Command(),
                                app = "CCSPI",
                                reply_filter=lambda reply:True
        )
        if GoodFET_Read_RF_Packet_Reply in reply and reply.size > 0:
            return reply.data
        return None

    def _send_packet(self, packet):
        reply = self._send_goodfet_cmd(
            GoodFET_Send_RF_Packet_Command(data=bytes([len(packet)+2]) + packet),
            app = "CCSPI",
            reply_filter=lambda reply:True
        )
        return GoodFET_Send_RF_Packet_Reply in reply

    def _get_rssi(self):
        """
        Return last RSSI.
        """
        rssi = (self._peek_ccspi(APIMoteRegisters.RSSI) & 0xFF)
        # 2's complement, 8 bits
        if (rssi >> 7) == 1:
            rssi = rssi - (1 << 8)
        return rssi

    def _setup_crystal_oscillator(self):
        """
        Configure the crystal oscillator.
        """
        # Must be performed two times for some reason. See GOODFETCCSPI.py in Killerbee drivers.
        self._strobe_ccspi(APIMoteRegisters.SXOSCON)
        return self._strobe_ccspi(APIMoteRegisters.SXOSCON)

    def _setup_rf_calibration(self):
        """
        Setup the RF calibration.
        """
        return self._strobe_ccspi(APIMoteRegisters.STXCAL)

    def _switch_rf_to_idle(self):
        """
        Switch radio to idle mode.
        """
        return self._strobe_ccspi(APIMoteRegisters.SRFOFF)

    def _switch_rf_to_rx(self):
        """
        Switch radio to reception mode (RX).
        """
        return self._strobe_ccspi(APIMoteRegisters.SRXON)

    def _switch_rf_to_tx(self):
        """
        Switch radio to transmission mode (TX).
        """
        return self._strobe_ccspi(APIMoteRegisters.STXON)

    def _get_syncword(self):
        """
        Return syncword in use (default is 802.15.4 SFD).
        """
        return self._peek_ccspi(APIMoteRegisters.SYNCWORD)

    def _set_syncword(self, syncword = 0xA70F):
        """
        Configure syncword to use.
        """
        return self._poke_ccspi(APIMoteRegisters.SYNCWORD, syncword)

    def _get_channel(self):
        """
        Return channel currently in use.
        """
        return frequency_to_channel(self._get_frequency())

    def _set_channel(self, channel):
        """
        Configure channel to use.
        """
        if channel < 11 or channel > 26:
            return False
        self._set_frequency(channel_to_frequency(channel))
        return True

    def _get_frequency(self):
        """
        Return frequency in use.
        """
        masks = APIMoteRegistersMasks.FSCTRL
        fsctrl_value = self._peek_ccspi(APIMoteRegisters.FSCTRL)
        frequency_offset = (fsctrl_value & masks.FREQ.mask) >> masks.FREQ.offset
        return 2048+frequency_offset

    def _set_frequency(self, frequency):
        """
        Configure frequency to use.
        """
        masks = APIMoteRegistersMasks.FSCTRL
        fsctrl_value = self._peek_ccspi(APIMoteRegisters.FSCTRL)
        self._poke_ccspi( APIMoteRegisters.FSCTRL,
                            (fsctrl_value & ~(masks.FREQ.mask << masks.FREQ.offset)) |
                            ((int(frequency - 2048) & masks.FREQ.mask) << masks.FREQ.offset)
        )
        self._setup_rf_calibration()
        sleep(0.01)
        self._switch_rf_to_rx()

    def _configure_mdmctrl0(self, auto_ack=False, auto_crc=False, leading_zeroes=3, hardware_access_decoding=False, pan_coordinator=False, reserved_accepted=False):
        """
        Configure MDMCTRL0 register (manages various RF related features and hardware processing).
        """
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
        """
        Configure MDMCTRL1 register (manages various RF-related features).
        """
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
        """
        Configure IOCFG0 register (manages polarity, beacon filtering and FIFO).
        """
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
        """
        Configure SECCTRL0 register (manages security-related features implemented in hardware).
        """
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
