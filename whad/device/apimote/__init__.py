"""
APIMote adaptation layer.
"""
import select
import os
from struct import pack, unpack
from threading import Thread
from time import sleep
from threading import Lock

from serial import Serial,PARITY_NONE
from serial.tools.list_ports import comports

from scapy.layers.dot15d4 import Dot15d4FCS
from scapy.compat import raw


from whad.scapy.layers.apimote import GoodFET_Command_Hdr, GoodFET_Reply_Hdr, GoodFET_Init_Reply, \
    GoodFET_Peek_Command, GoodFET_Monitor_Connected_Command, GoodFET_Peek_Reply, \
    GoodFET_Setup_CCSPI_Command, GoodFET_Setup_CCSPI_Reply,GoodFET_Transfer_Command, \
    GoodFET_Transfer_Reply, GoodFET_Poke_Reply, GoodFET_Poke_Command, GoodFET_Peek_RAM_Command, \
    GoodFET_Poke_RAM_Command, GoodFET_Peek_RAM_Reply, GoodFET_Poke_RAM_Reply, \
    GoodFET_Read_RF_Packet_Command, GoodFET_Read_RF_Packet_Reply, GoodFET_Send_RF_Packet_Command, \
    GoodFET_Send_RF_Packet_Reply, CC_VERSIONS

from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.hub.discovery import Domain, Capability
from whad.hub.generic.cmdresult import Error, Success
from whad.hub.dot15d4 import Commands, Start, Stop, SendRawPdu, SniffMode

from whad.zigbee.utils.phy import channel_to_frequency, frequency_to_channel
from whad.device.uart import get_port_info

from ..device import VirtualDevice
from .constants import APIMoteId, APIMoteRegisters, \
    APIMoteRegistersMasks, APIMoteInternalStates


class Apimote(VirtualDevice):
    """Apimote virtual device implementation.
    """

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
            available_devices.append(Apimote(apimote.device))
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
        self.__input_data = None
        self.__packet_queue = None
        self.__packet_polling = False
        self.__pending_messages = []
        self.__pending_lock = Lock()
        self.__polling_thread = Thread(target=self._polling, daemon=True)

        self.__internal_state = APIMoteInternalStates.NONE
        port_info = get_port_info(self.__port)
        if port_info is None:
            raise WhadDeviceNotFound()

        # Set device information
        self.dev_id = self.__generate_dev_id(port_info)
        self.author = self.__get_author()
        self.url = self.__get_firmware_url()
        self.version = self.__get_firmware_version()
        self.capabilities = self.__get_capabilities()

    # Discovery related functions
    def __get_capabilities(self):
        capabilities = {
            Domain.Dot15d4 : (
                (Capability.Sniff | Capability.Inject),
                [Commands.Sniff, Commands.Send, Commands.Start, Commands.Stop]
            )
        }
        return capabilities

    def __generate_dev_id(self, port_info):
        dev_id = (
                        port_info.serial_number.encode('utf-8') +
                        pack("H", port_info.vid) +
                        pack("H", port_info.pid)
        )
        dev_id = b"\x00"*(16 - len(dev_id)) + dev_id
        return dev_id

    def __get_firmware_version(self):
        return (4, 0, 0) # APIMote v4 beta

    def __get_author(self) -> str:
        """Return the project author's name.

        :return: Project author name
        :rtype: str
        """
        return "Ryan Speers"

    def __get_firmware_url(self) -> str:
        # Maybe we should replace it by GoodFET URL ?
        return "https://github.com/riverloopsec/apimote"

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

        self.__setup_ccspi()
        while self.__peek_ccspi(APIMoteRegisters.MANFIDL) != 0x233D:
            sleep(0.1)

        self.__init_radio()

    def read(self):
        """Read and process incoming data.
        """
        if not self.__opened or self.__fileno is None:
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

        # Handle incoming messages if any
        if len(readers) > 0:
            data = os.read(self.__fileno, 1024)
            self.__process_input_data(data)

        # Return pending messages
        with self.__pending_lock:
            if len(self.__pending_messages) > 0:
                messages = self.__pending_messages
            else:
                messages = None
            self.__pending_messages = []
        return messages

    def write(self, payload: bytes) -> int:
        """Writes command to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param data: Data to write
        :type data: bytes
        :return: number of bytes written to the device
        :rtype: int
        """
        if not self.__opened or self.__fileno is None:
            raise WhadDeviceNotReady()

        nb_bytes_written = 0
        wlist = [self.__fileno]
        elist = [self.__fileno]
        _ ,writers, __ = select.select(
            [],
            wlist,
            elist
        )

        if len(writers) > 0:
            nb_bytes_written = os.write(self.__fileno, raw(payload))
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
        if self.__uart is not None:
            self.__uart.close()
        self.__uart = None
        self.__fileno = None

    def __create_raw_pdu(self, packet, rssi=None):
        pdu = packet[:-2]
        fcs = unpack("H",packet[-2:])[0]
        is_fcs_valid = Dot15d4FCS().compute_fcs(pdu) == packet[-2:]
        timestamp = None

        msg = self.hub.dot15d4.create_raw_pdu_received(
            self.__get_channel(),
            pdu,
            fcs,
            fcs_validity=is_fcs_valid
        )

        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp

        return msg

    def __add_rx_packet(self, packet: bytes, rssi: int):
        """Add a received packet to the pending messages to send to
        an attached connector.

        :param packet: Received packet
        :type  packet: bytes
        :param rssi: Received signal strength indicator
        :type  rssi: int
        """
        with self.__pending_lock:
            self.__pending_messages.append(self.__create_raw_pdu(packet, rssi))

    def _polling(self):
        while self.__opened:
            if self.__packet_polling:
                if self.__packet_queue is None:
                    packet = self.__get_packet()
                    if packet is not None:
                        rssi = self.__get_rssi()
                        packet_size = packet[0]
                        # size of packet + 1-byte long length field
                        if packet_size + 1 < len(packet):
                            packet = packet[1:packet_size+1]
                            self.__packet_queue = (packet[packet_size+2:], rssi)
                            self.__add_rx_packet(packet, rssi)
                        else:
                            self.__add_rx_packet(packet[1:], rssi)
                else:
                    packet = self.__packet_queue
                    self.__packet_queue = None
                    self.__add_rx_packet(packet, rssi)

    # Virtual device whad message callbacks
    @VirtualDevice.route(Stop)
    def on_stop(self, message):
        if self.__switch_rf_to_idle():
            self.__internal_state = APIMoteInternalStates.NONE
            self.__packet_polling = False
            return Success()
        else:
            return Error()

    @VirtualDevice.route(SendRawPdu)
    def on_send_raw(self, message):
        channel = message.channel
        if self.__set_channel(channel):
            packet = message.pdu
            old_state = self.__internal_state
            #self._switch_rf_to_tx()
            self.__internal_state = APIMoteInternalStates.TRANSMITTING
            self.__configure_mdmctrl0(auto_crc=True)
            success = self.__send_packet(packet)
            self.__configure_mdmctrl0(auto_crc=False)


            if old_state == APIMoteInternalStates.SNIFFING:
                self.__switch_rf_to_rx()
                self.__internal_state = APIMoteInternalStates.SNIFFING
            else:
                self.__switch_rf_to_idle()
                self.__internal_state = APIMoteInternalStates.NONE

        else:
            success = False

        # Return operation status
        return Success() if success else Error()

    @VirtualDevice.route(SniffMode)
    def on_sniff(self, message):
        channel = message.channel
        if self.__set_channel(channel):
            self.__internal_state = APIMoteInternalStates.SNIFFING
            return Success()

        return Error()

    @VirtualDevice.route(Start)
    def on_start(self, message):
        if self.__internal_state == APIMoteInternalStates.SNIFFING:
            if self.__switch_rf_to_rx():
                self._packet_queue = None
                self.__packet_polling = True
                return Success()
            return Error()
        elif self.__internal_state == APIMoteInternalStates.NONE:
            self.__switch_rf_to_idle()
            return Success()
        return Error()

    # APIMote / GoodFET low level primitives
    def __send_goodfet_cmd(self, cmd, app="MONITOR", reply_filter=None):
        self.write(raw(GoodFET_Command_Hdr(app=app)/cmd))
        if reply_filter is not None and callable(reply_filter):
            while self.__last_reply is None or not reply_filter(self.__last_reply):
                sleep(0.001)
            matched_reply = self.__last_reply
            self.__last_reply = None
            return matched_reply

        # Error
        return None

    def __process_goodfet_reply(self, reply):
        if GoodFET_Init_Reply in reply and reply.url == b"http://goodfet.sf.net/":
            self.__synced = True
            self.__monitor_connected()
        elif self.__synced:
            self.__last_reply = reply

    def __process_input_data(self, data):
        self.__input_data += data
        if len(self.__input_data) >= 4:
            reply_length = (self.__input_data[2] | self.__input_data[3] << 8) + 4
            if len(self.__input_data) >= reply_length:
                self.__process_goodfet_reply(GoodFET_Reply_Hdr(self.__input_data[:reply_length]))
                self.__input_data = self.__input_data[reply_length:]

    def __monitor_connected(self):
        self.__send_goodfet_cmd(GoodFET_Monitor_Connected_Command())


    def __strobe_ccspi(self, register: int):
        data = bytes([register])
        status = self.__transfer_ccspi(data)
        return status[0]


    def __poke_ccspi(self, register: int, value: int):
        data = bytes([
            register,
            0xFF & (value >> 8) ,
            (value & 0xFF)]
        )
        self.__send_goodfet_cmd(
            GoodFET_Poke_Command(data=data),
            app="CCSPI",
            reply_filter=lambda reply:GoodFET_Poke_Reply in reply
        )
        return self.__peek_ccspi(register) == value

    def __peek_ccspi(self, register):
        address = bytes([register, 0 , 0 ])
        reply = self.__send_goodfet_cmd(
            GoodFET_Peek_Command(address=address),
            app="CCSPI",
            reply_filter=lambda reply:GoodFET_Peek_Reply in reply
        )
        value = 0
        if reply is not None:
            for i in range(1,len(reply.data)):
                value |= (reply.data[i] << (len(reply.data)-i-1)*8)
        return value

    def __transfer_ccspi(self, data):
        reply = self.__send_goodfet_cmd(
            GoodFET_Transfer_Command(data=data),
            app="CCSPI",
            reply_filter = lambda reply:GoodFET_Transfer_Reply in reply
        )
        if reply is not None:
            return reply.data
        return None

    def __peek_ram(self, address: int, count : int = 4):
        reply = self.__send_goodfet_cmd(
            GoodFET_Peek_RAM_Command(address=address, count=count),
            app="CCSPI",
            reply_filter = lambda reply:GoodFET_Peek_RAM_Reply in reply
        )
        if reply is not None:
            return reply.data
        return None

    def __poke_ram(self, address: int, value: int):
        data = bytes([address & 0xFF, (address & 0xFF00) >> 8]) + value
        self.__send_goodfet_cmd(
            GoodFET_Poke_RAM_Command(data=data),
            app="CCSPI",
            reply_filter = lambda reply:GoodFET_Poke_RAM_Reply in reply
        )

    def __monitor_peek(self, address, size=8):
        if size == 8:
            reply = self.__send_goodfet_cmd(
                GoodFET_Peek_Command(address=pack("H", address)),
                reply_filter=lambda reply:GoodFET_Peek_Reply in reply
            )
            if reply is not None:
                return reply.data[0]
            return None

        if size == 16:
            reply_low = self.__send_goodfet_cmd(
                GoodFET_Peek_Command(address=pack("H", address)),
                reply_filter=lambda reply:GoodFET_Peek_Reply in reply
            )
            reply_high = self.__send_goodfet_cmd(
                GoodFET_Peek_Command(address=pack("H", address)+1),
                reply_filter=lambda reply:GoodFET_Peek_Reply in reply
            )
            if reply_high is not None and reply_low is not None:
                return reply_low.data[0] + (reply_high.data[0] << 8)
            return None

        # Invalid size
        return None


    def __setup_ccspi(self):
        reply = self.__send_goodfet_cmd(
            GoodFET_Setup_CCSPI_Command(),
            app="CCSPI",
            reply_filter = lambda reply:GoodFET_Setup_CCSPI_Reply in reply
        )
        return reply

    def __show_registers(self):
        '''
        Show current value of main registers (debugging purposes).
        '''
        print("MDMCTRL0", hex(self.__peek_ccspi(APIMoteRegisters.MDMCTRL0)))
        print("MDMCTRL1", hex(self.__peek_ccspi(APIMoteRegisters.MDMCTRL1)))
        print("IOCFG0", hex(self.__peek_ccspi(APIMoteRegisters.IOCFG0)))
        print("SECCTRL0", hex(self.__peek_ccspi(APIMoteRegisters.SECCTRL0)))

    # APIMote RF-related primitives
    def __init_radio(self):
        """
        Configure the radio as promiscuous and switch to idle.
        """
        self.__setup_crystal_oscillator()
        self.__setup_rf_calibration()
        self.__configure_mdmctrl0(auto_ack=False, auto_crc=False, leading_zeroes=3,
                                 hardware_access_decoding=False, pan_coordinator=False,
                                 reserved_accepted=False)
        self.__configure_mdmctrl1(demodulator_thresold=20)
        self.__configure_iocfg0(filter_beacons=False)
        self.__configure_secctrl0(enable_cbcmac=False, m=4, rx_key_select=0,
                                 tx_key_select=1, sa_key_select=1)
        self.__switch_rf_to_idle()


    def __get_packet(self):
        """
        Return RX packet (if any is available).
        """
        reply = self.__send_goodfet_cmd(
            GoodFET_Read_RF_Packet_Command(),
            app = "CCSPI",
            reply_filter=lambda reply:True
        )
        if GoodFET_Read_RF_Packet_Reply in reply and reply.size > 0:
            return reply.data
        return None

    def __send_packet(self, packet):
        reply = self.__send_goodfet_cmd(
            GoodFET_Send_RF_Packet_Command(data=bytes([len(packet)+2]) + packet),
            app = "CCSPI",
            reply_filter=lambda reply:True
        )
        return GoodFET_Send_RF_Packet_Reply in reply

    def __get_rssi(self) -> int:
        """
        Return last RSSI.
        """
        rssi = self.__peek_ccspi(APIMoteRegisters.RSSI) & 0xFF
        # 2's complement, 8 bits
        if (rssi >> 7) == 1:
            rssi = rssi - (1 << 8)
        return rssi

    def __setup_crystal_oscillator(self):
        """
        Configure the crystal oscillator.
        """
        # Must be performed two times for some reason. See GOODFETCCSPI.py in Killerbee drivers.
        self.__strobe_ccspi(APIMoteRegisters.SXOSCON)
        return self.__strobe_ccspi(APIMoteRegisters.SXOSCON)

    def __setup_rf_calibration(self):
        """
        Setup the RF calibration.
        """
        return self.__strobe_ccspi(APIMoteRegisters.STXCAL)

    def __switch_rf_to_idle(self):
        """
        Switch radio to idle mode.
        """
        return self.__strobe_ccspi(APIMoteRegisters.SRFOFF)

    def __switch_rf_to_rx(self):
        """
        Switch radio to reception mode (RX).
        """
        return self.__strobe_ccspi(APIMoteRegisters.SRXON)

    def __switch_rf_to_tx(self):
        """
        Switch radio to transmission mode (TX).
        """
        return self.__strobe_ccspi(APIMoteRegisters.STXON)

    def __get_syncword(self) -> int:
        """
        Return syncword in use (default is 802.15.4 SFD).
        """
        return self.__peek_ccspi(APIMoteRegisters.SYNCWORD)

    def __set_syncword(self, syncword: int = 0xA70F):
        """
        Configure syncword to use.
        """
        return self.__poke_ccspi(APIMoteRegisters.SYNCWORD, syncword)

    def __get_channel(self) -> int:
        """
        Return channel currently in use.
        """
        return frequency_to_channel(self._get_frequency())

    def __set_channel(self, channel: int):
        """
        Configure channel to use.
        """
        if channel < 11 or channel > 26:
            return False
        self.__set_frequency(channel_to_frequency(channel))
        return True

    def __get_frequency(self) -> int:
        """
        Return frequency in use.
        """
        masks = APIMoteRegistersMasks.FSCTRL
        fsctrl_value = self.__peek_ccspi(APIMoteRegisters.FSCTRL)
        frequency_offset = (fsctrl_value & masks.FREQ.mask) >> masks.FREQ.offset
        return 2048+frequency_offset

    def __set_frequency(self, frequency: int):
        """
        Configure frequency to use.
        """
        masks = APIMoteRegistersMasks.FSCTRL
        fsctrl_value = self.__peek_ccspi(APIMoteRegisters.FSCTRL)
        self.__poke_ccspi( APIMoteRegisters.FSCTRL,
                            (fsctrl_value & ~(masks.FREQ.mask << masks.FREQ.offset)) |
                            ((int(frequency - 2048) & masks.FREQ.mask) << masks.FREQ.offset)
        )
        self.__setup_rf_calibration()
        sleep(0.01)
        self.__switch_rf_to_rx()

    def __configure_mdmctrl0(self, auto_ack=False, auto_crc=False, leading_zeroes=3,
                            hardware_access_decoding=False, pan_coordinator=False,
                            reserved_accepted=False):
        """
        Configure MDMCTRL0 register (manages various RF related features and hardware processing).
        """
        masks = APIMoteRegistersMasks.MDMCTRL0
        return self.__poke_ccspi(APIMoteRegisters.MDMCTRL0,
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


    def __configure_mdmctrl1(self, demodulator_thresold=20):
        """
        Configure MDMCTRL1 register (manages various RF-related features).
        """
        masks = APIMoteRegistersMasks.MDMCTRL1
        return self.__poke_ccspi(APIMoteRegisters.MDMCTRL1,
            (
                ((demodulator_thresold & masks.CORR_THR.mask) << masks.CORR_THR.offset) |
                ((0 & masks.DEMOD_AVG_MODE.mask) << masks.DEMOD_AVG_MODE.offset) |
                ((0 & masks.MODULATION_MODE.mask) << masks.MODULATION_MODE.offset) |
                ((0 & masks.TX_MODE.mask) << masks.TX_MODE.offset) |
                ((0 & masks.RX_MODE.mask) << masks.RX_MODE.offset)
            )
        )

    def __configure_iocfg0(self, filter_beacons=False):
        """
        Configure IOCFG0 register (manages polarity, beacon filtering and FIFO).
        """
        masks = APIMoteRegistersMasks.IOCFG0
        return self.__poke_ccspi(APIMoteRegisters.IOCFG0,
            (
                ((int(not filter_beacons) & masks.BCN_ACCEPT.mask) << masks.BCN_ACCEPT.offset) |
                ((0 & masks.FIFO_POLARITY.mask) << masks.FIFO_POLARITY.offset) |
                ((0 & masks.FIFOP_POLARITY.mask) << masks.FIFOP_POLARITY.offset) |
                ((0 & masks.SFD_POLARITY.mask) << masks.SFD_POLARITY.offset) |
                ((0 & masks.CCA_POLARITY.mask) << masks.CCA_POLARITY.offset) |
                ((0x7F & masks.FIFOP_THR.mask) << masks.FIFOP_THR.offset)
            )
        )

    def __configure_secctrl0(self, enable_cbcmac=False, m=4, rx_key_select=0, tx_key_select=1,
                            sa_key_select=1):
        """
        Configure SECCTRL0 register (manages security-related features implemented in hardware).
        """
        masks = APIMoteRegistersMasks.SECCTRL0
        return self.__poke_ccspi(APIMoteRegisters.SECCTRL0,
            (
                ((0 & masks.RXFIFO_PROTECTION.mask) << masks.RXFIFO_PROTECTION.offset) |
                ((1 & masks.SEC_CBC_HEAD.mask) << masks.SEC_CBC_HEAD.offset) |
                ((sa_key_select & masks.SEC_SAKEYSEL.mask) << masks.SEC_SAKEYSEL.offset) |
                ((tx_key_select & masks.SEC_TXKEYSEL.mask) << masks.SEC_TXKEYSEL.offset) |
                ((rx_key_select & masks.SEC_RXKEYSEL.mask) << masks.SEC_RXKEYSEL.offset) |
                ((int((m-2)//2) & masks.SEC_M.mask) << masks.SEC_M.offset) |
                ((int(enable_cbcmac) & masks.SEC_MODE.mask) << masks.SEC_MODE.offset)
            )
        )

