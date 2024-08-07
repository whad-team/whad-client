from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.device.virtual.yard.constants import YardStickOneId, YardStickOneEndPoints, \
    YardApplications, YardSystemCommands, YardRadioStructure, YardRFStates, \
    YardMemoryRegisters, YardMARCStates, YardCCA, YardFrequencyTransitionPoints, \
    YardNICCommands, YardVCOType, YardRegistersMasks, YardModulations, YardEncodings, \
    POSSIBLE_CHANNEL_BANDWIDTHS, NUM_PREAMBLE_LOOKUP_TABLE, YardUSBProperties, \
    YardInternalStates
from whad import WhadDomain, WhadCapability
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.phy import Commands, TxPower, Endianness as PhyEndianness, Modulation as PhyModulation
from usb.core import find, USBError, USBTimeoutError
from usb.util import get_string
from whad.phy import Endianness
from struct import unpack, pack
from time import sleep,time
from whad.helpers import swap_bits
from queue import Queue, Empty



# Helpers functions
def get_yardstickone(id=0,bus=None, address=None):
    '''
    Returns a YardStickOne USB object based on index or bus and address.
    '''
    devices = list(find(idVendor=YardStickOneId.YARD_ID_VENDOR, idProduct=YardStickOneId.YARD_ID_PRODUCT,find_all=True))
    if bus is not None and address is not None:
        for device in devices:
            if device.bus == bus and device.address == address:
                return (devices.index(device), device)
        # No device found with the corresponding bus/address, return None
        return None
    else:
        try:
            return (id, devices[id])
        except IndexError:
            return None

class YardStickOneDevice(VirtualDevice):

    INTERFACE_NAME = "yardstickone"

    @classmethod
    def list(cls):
        '''
        Returns a list of available RZUSBStick devices.
        '''
        available_devices = []
        for yard in find(idVendor=YardStickOneId.YARD_ID_VENDOR, idProduct=YardStickOneId.YARD_ID_PRODUCT,find_all=True):
            available_devices.append(YardStickOneDevice(bus=yard.bus, address=yard.address))
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in format "<bus>-<address>").
        '''
        return str(self.__yard.bus)+"-"+str(self.__yard.address)


    def __init__(self, index=0, bus=None, address=None):
        """
        Create device connection
        """
        device = get_yardstickone(index,bus=bus,address=address)
        if device is None:
            raise WhadDeviceNotFound
        self.__opened_stream = False

        self.__supported_frequency_range = [
            (281000000, 361000000),
            (378000000, 481000000),
            (749000000, 962000000),
        ]

        self.__internal_state = YardInternalStates.YardModeIdle
        self.__frequency = None
        self.__endianness = Endianness.BIG

        self.__start_time = time()*1000000
        self.__in_buffer = b""
        self.__queue = Queue()

        self.__opened = False
        self.__index, self.__yard = device
        super().__init__()

    def _enter_configuration_mode(self):
        self._set_idle_mode()
        self._strobe_idle_mode()

    def _restore_previous_mode(self):
        if self.__internal_state == YardInternalStates.YardModeRx:
            self._set_rx_mode()
            self._strobe_rx_mode()

        elif self.__internal_state == YardInternalStates.YardModeTx:
            self._set_tx_mode()
            self._strobe_tx_mode()

    def _on_whad_phy_get_supported_freq(self, message):
        # Create a SupportedFreqRanges
        msg = self.hub.phy.create_supported_freq_ranges(
            self.__supported_frequency_range
        )

        # Send message
        self._send_whad_message(msg)

    def _on_whad_phy_send(self, message):
        self._send_packet(message.packet)
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_set_freq(self, message):
        found = False
        for supported_range in self.__supported_frequency_range:
            range_start, range_end = supported_range[0], supported_range[1]
            if message.frequency >= range_start and message.frequency <= range_end:
                found = True
                break

        if found:
            self._enter_configuration_mode()
            self._set_frequency(message.frequency)
            self.__frequency = message.frequency
            self._restore_previous_mode()
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_datarate(self, message):
        self._enter_configuration_mode()
        self._set_data_rate(message.rate)
        self._restore_previous_mode()
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_packet_size(self, message):
        if message.packet_size < 255:
            self._enter_configuration_mode()
            self._set_packet_length(message.packet_size)
            self._restore_previous_mode()
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_endianness(self, message):
        if message.endianness in (Endianness.BIG, Endianness.LITTLE):
            self.__endianness = message.endianness
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_tx_power(self, message):
        tx_powers = {
            TxPower.LOW : 0x20,
            TxPower.MEDIUM : 0x80,
            TxPower.HIGH : 0xC0
        }

        if message.power in list(tx_powers.keys()):
            self._enter_configuration_mode()
            self._set_power(
                tx_powers[message.power]
            )
            self._restore_previous_mode()
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_mod_ask(self, message):
        self._enter_configuration_mode()
        self._set_modulation(YardModulations.MODULATION_ASK)
        self._set_encoding(YardEncodings.NON_RETURN_TO_ZERO)
        self._restore_previous_mode()
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_4fsk(self, message):
        self._enter_configuration_mode()
        self._set_modulation(YardModulations.MODULATION_4FSK)
        self._set_encoding(YardEncodings.NON_RETURN_TO_ZERO)
        self._set_deviation(message.deviation)
        self._restore_previous_mode()
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_mod_fsk(self, message):
        self._enter_configuration_mode()
        self._set_modulation(YardModulations.MODULATION_2FSK)
        self._set_encoding(YardEncodings.NON_RETURN_TO_ZERO)
        self._set_deviation(message.deviation)
        self._restore_previous_mode()
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_gfsk(self, message):
        self._enter_configuration_mode()
        self._set_modulation(YardModulations.MODULATION_GFSK)
        self._set_encoding(YardEncodings.NON_RETURN_TO_ZERO)
        self._set_deviation(message.deviation)
        # message.gaussian_filter can't be processed
        self._restore_previous_mode()
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_sync_word(self, message):
        if len(message.sync_word) == 0:
            self._enter_configuration_mode()
            self._set_crc(enable=False)
            self._set_whitening(enable=False)
            self._set_packet_format(0)
            self._set_forward_error_correction(enable=False)
            self._set_clear_channel_assessment(mode=YardCCA.NO_CCA)
            self._set_sync_word(b"")
            self._set_preamble_quality_threshold(0)
            self._restore_previous_mode()
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif len(message.sync_word) <= 2:
            self._enter_configuration_mode()
            self._set_crc(enable=False)
            self._set_whitening(enable=False)
            self._set_packet_format(0)
            self._set_forward_error_correction(enable=False)
            self._set_clear_channel_assessment(mode=YardCCA.NO_CCA)
            if self.__endianness == Endianness.LITTLE:
                sync = bytes([swap_bits(i) for i in message.sync_word])[::-1]
            else:
                sync = message.sync_word
            self._set_sync_word(sync)
            self._set_preamble_quality_threshold(0)
            self._restore_previous_mode()
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif len(message.sync_word) == 4 and message.sync_word[:2] == message.sync_word[2:]:
            self._enter_configuration_mode()
            self._set_crc(enable=False)
            self._set_whitening(enable=False)
            self._set_packet_format(0)
            self._set_forward_error_correction(enable=False)
            self._set_clear_channel_assessment(mode=YardCCA.NO_CCA)
            if self.__endianness == Endianness.LITTLE:
                sync = bytes([swap_bits(i) for i in message.sync_word])[::-1]
            else:
                sync = message.sync_word
            self._set_sync_word(sync)
            self._set_preamble_quality_threshold(0)
            self._restore_previous_mode()
            self._send_whad_command_result(CommandResult.SUCCESS)

        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)


    def _on_whad_phy_sniff(self, message):
        self.__internal_state = YardInternalStates.YardModeRx
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_start(self, message):
        if self.__internal_state == YardInternalStates.YardModeRx:
            self._set_rx_mode()
            self._strobe_rx_mode()
            self.__opened_stream = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_stop(self, message):
        #self._set_idle_mode()
        #self._strobe_idle_mode()
        self.__opened_stream = False
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _send_whad_phy_pdu(self, packet, timestamp=None):
        # Create a PacketReceived message
        msg = self.hub.phy.create_packet_received(
            self._get_frequency(),
            packet,
            syncword=self._get_sync_word(),
            endianness=PhyEndianness.LITTLE if self.__endianness == Endianness.LITTLE else PhyEndianness.BIG,
            deviation=int(self._get_deviation()),
            datarate=int(self._get_data_rate())
        )

        # Set packet timestamp if available
        if timestamp is not None:
            msg.timestamp = timestamp

        self._send_whad_message(msg)


    def open(self):
        try:
            self.__yard.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("yardstickone")
            else:
                raise WhadDeviceNotReady()
        self.reset()
        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self.__opened = True

        self.radio_structure = YardRadioStructure(self._poke, self._peek)

        self._frequency_offset_accumulator = 0
        #print(self.radio_structure)

        self._set_idle_mode()
        self._set_rf_register("MDMCFG4",0x68)
        self._set_rf_register("MDMCFG3",0xb5)
        self._set_rf_register("MDMCFG2",0x80)
        self._set_rf_register("MDMCFG1",0x23)
        self._set_rf_register("MDMCFG0",0x11)
        self._set_modulation(YardModulations.MODULATION_ASK)
        self._set_encoding(YardEncodings.NON_RETURN_TO_ZERO)
        self._set_crc(enable=False)
        self._set_whitening(enable=False)
        self._set_packet_format(0)
        self._set_forward_error_correction(enable=False)
        self._set_clear_channel_assessment(mode=YardCCA.NO_CCA)
        self._set_frequency(433870000)
        self._set_data_rate(10000)
        #self._set_channel_spacing(self.compute_best_channel_bandwidth())
        self._set_channel(0)
        self._set_intermediate_frequency(44444)
        self._set_idle_mode()

        # Ask parent class to run a background I/O thread
        super().open()
        self.__opened_stream = False

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()

        if self.__opened_stream:
            try:
                self._yard_send_command(YardApplications.NIC, YardNICCommands.SET_RECV_LARGE, pack("<H", 200))
                data = self._yard_send_command(YardApplications.NIC,YardNICCommands.RECV)
                while self.__opened_stream and self.__internal_state == YardInternalStates.YardModeRx:

                    data = self._yard_read_response()

                    if data[0] is not None and data[0] != 0xFF and not (len(data[2]) == 1 and data[2] == b"\xC8"):
                        if self.__endianness == Endianness.LITTLE:
                            formatted_data = bytes([swap_bits(i) for i in data[2]])
                        else:
                            formatted_data = data[2]

                        self._send_whad_phy_pdu(formatted_data, int(time()*1000000 - self.__start_time))

            except USBTimeoutError:
                pass

    def reset(self):
        value = self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.RESET,
            b"RESET_NOW\x00"
        )

    def close(self):
        if self.__opened:
            self.__opened_stream = False
            self._set_idle_mode()
        super().close()

    # Yard Stick One low level communication primitives

    def _yard_read_response(self, timeout=1000):
        try:
            response = bytes(self.__yard.read(YardStickOneEndPoints.IN_ENDPOINT, 512, timeout=timeout))
            if len(response) >= 3:
                size = unpack("<H", response[3:5])[0]
                if len(response) >= 5 + size:
                    app = response[1]
                    verb = response[2]
                    data = response[5:5+size]
                    return app, verb, data
        except USBTimeoutError:
            response = (None, None, None)
        return response

    def _yard_send_command(self, app, command, data=b"", timeout=1000, no_response=False):
        message = bytes([app, command]) + pack("<H", len(data)) + data
        if no_response:
            return
        recv_app, recv_verb, recv_data = None, None, None
        while (recv_app != app and recv_verb != command):
            self.__yard.write(YardStickOneEndPoints.OUT_ENDPOINT, message, timeout=timeout)
            recv_app, recv_verb, recv_data = self._yard_read_response()
        return recv_data

    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Phy : (
                                (WhadCapability.Sniff | WhadCapability.NoRawData),
                                [
                                    Commands.GetSupportedFrequencies,
                                    Commands.SetASKModulation,
                                    Commands.SetFSKModulation,
                                    Commands.Set4FSKModulation,
                                    Commands.GetSupportedFrequencies,
                                    Commands.SetFrequency,
                                    Commands.SetDataRate,
                                    Commands.SetEndianness,
                                    Commands.SetTXPower,
                                    Commands.SetPacketSize,
                                    Commands.SetSyncWord,
                                    Commands.Sniff,
                                    Commands.Send,
                                    Commands.Start,
                                    Commands.Stop,
                                    Commands.Set4FSKModulation
                                ]
            )
        }

        return capabilities

    def _get_manufacturer(self):
        return get_string(self.__yard, self.__yard.iManufacturer).encode('utf-8')

    def _get_serial_number(self):

        return bytes.fromhex(
                                self.__yard.serial_number +
                                "{:04x}".format(self.__yard.bus)  +
                                "{:04x}".format(self.__yard.address)
        )

    def _get_firmware_version(self):
        response = self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.BUILDTYPE
        )
        revision = int(response.split(b" r")[1][:-1])
        return (revision, 0, 0)

    def _get_url(self):
        return "https://github.com/atlas0fd00m/rfcat".encode('utf-8')

    def _send_packet(self, packet, repeat=1, offset=0):
        data = bytes(packet)

        # It is the only solution we found to allow transmitting data without breaking the sniffer mode.
        old_state = self.__internal_state
        self.__internal_state = YardInternalStates.YardModeTx
        opened_stream = self.__opened_stream
        self.__opened_stream = False

        self._set_idle_mode()
        self._strobe_idle_mode()


        self._set_tx_mode()
        self._strobe_tx_mode()

        self._yard_send_command(YardApplications.NIC, YardNICCommands.XMIT, pack("<HHH", len(data), repeat, offset) + data, timeout=500)
        #message = bytes([YardApplications.NIC, YardNICCommands.LONG_XMIT]) + pack("<H", len(data)) + data
        #self.__yard.write(YardStickOneEndPoints.OUT_ENDPOINT, message, timeout=5000)
        #message = bytes([YardApplications.NIC, YardNICCommands.LONG_XMIT_MORE]) + b"\x00"
        #self.__yard.write(YardStickOneEndPoints.OUT_ENDPOINT, message, timeout=1000)

        self.__internal_state = old_state
        self._restore_previous_mode()

        self.__opened_stream = opened_stream


    def _peek(self, address, size):
        return self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.PEEK,
            pack("<HH", size, address)
        )

    def _poke(self, address, data=b""):
        return self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.POKE,
            pack("<H", address) + data
        )

    def _set_rf_mode(self, mode):
        self._rf_mode = mode
        return self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.RFMODE,
            bytes([mode])
        )

    def _set_tx_mode(self):
        self._set_rf_mode(YardRFStates.STX)

    def _set_rx_mode(self):
        self._set_rf_mode(YardRFStates.SRX)

    def _set_idle_mode(self):
        self._set_rf_mode(YardRFStates.SIDLE)

    def _strobe_tx_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.STX]))

    def _strobe_rx_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SRX]))

    def _strobe_idle_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SIDLE]))

    def _strobe_cal_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SCAL]))

    def _strobe_fstxon_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SFSTXON]))

    def _strobe_return_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([self._rf_mode]))

    def _set_rf_register(self, register, value):
        # Update the radio structure
        self.radio_structure.update()
        # Check Main Radio Control State
        old_marc_state = self.radio_structure.get("MARCSTATE")

        # Go back to idle state
        if old_marc_state != YardMARCStates.MARC_STATE_IDLE:
            self._strobe_idle_mode()

        self.radio_structure.set(register, value)

        # Go back to configured mode
        self._strobe_return_mode()


    def _set_clear_channel_assessment(self, mode=YardCCA.CCA_PACKET, absolute_threshold=0, relative_threshold=1, magnitude=3):

        masks_mcsm1 = YardRegistersMasks.MCSM1
        mcsm1 = self.radio_structure.get("MCSM1") & ~(masks_mcsm1.CCA_MODE.mask << masks_mcsm1.CCA_MODE.offset)
        mcsm1 |= (mode << masks_mcsm1.CCA_MODE.offset)

        mask_agcctrl2 = YardRegistersMasks.AGCCTRL2
        agcctrl2 = self.radio_structure.get("AGCCTRL2") & ~(mask_agcctrl2.MAGN_TARGET.mask << mask_agcctrl2.MAGN_TARGET.offset)
        agcctrl2 |= (magnitude << mask_agcctrl2.MAGN_TARGET.offset)

        mask_agcctrl1 = YardRegistersMasks.AGCCTRL1
        agcctrl1 = self.radio_structure.get("AGCCTRL1") & ~(
            (mask_agcctrl1.CARRIER_SENSE_REL_THR.mask << mask_agcctrl1.CARRIER_SENSE_REL_THR.offset) |
            (mask_agcctrl1.CARRIER_SENSE_ABS_THR.mask << mask_agcctrl1.CARRIER_SENSE_ABS_THR.offset)
        )
        agcctrl1 |= (
                        ((relative_threshold & mask_agcctrl1.CARRIER_SENSE_REL_THR.mask) << mask_agcctrl1.CARRIER_SENSE_REL_THR.offset) |
                        ((absolute_threshold & mask_agcctrl1.CARRIER_SENSE_ABS_THR.mask) << mask_agcctrl1.CARRIER_SENSE_ABS_THR.offset)
        )

        self._set_rf_register("MCSM1", mcsm1)
        self._set_rf_register("AGCCTRL1", agcctrl1)
        self._set_rf_register("AGCCTRL2", agcctrl2)

    def _set_frequency(self, frequency=433920000):
        freq_multiplier = (0x10000 / 1000000.0) / 24
        computed_value = int(frequency * freq_multiplier)

        self._set_rf_register("FREQ2", (computed_value >> 16))
        self._set_rf_register("FREQ1", (computed_value >> 8) & 0xFF)
        self._set_rf_register("FREQ0", (computed_value & 0xFF))

        if (
            (frequency > YardFrequencyTransitionPoints.FREQ_EDGE_900 and
            frequency < YardFrequencyTransitionPoints.FREQ_MID_900) or
            (frequency > YardFrequencyTransitionPoints.FREQ_EDGE_400 and
            frequency < YardFrequencyTransitionPoints.FREQ_MID_400) or
            (frequency < YardFrequencyTransitionPoints.FREQ_MID_300)
        ):
            self._set_rf_register("FSCAL2", YardVCOType.LOW_VCO)
        elif (
            frequency < 1e9 and (
                (frequency > YardFrequencyTransitionPoints.FREQ_MID_900) or
                (frequency > YardFrequencyTransitionPoints.FREQ_MID_400) or
                (frequency > YardFrequencyTransitionPoints.FREQ_MID_300))
            ):
            self._set_rf_register("FSCAL2", YardVCOType.HIGH_VCO)

    def _get_frequency(self):
        freq_multiplier = (0x10000 / 1000000.0) / 24

        self.radio_structure.update()
        num = (
                (self.radio_structure.get("FREQ2") << 16) +
                (self.radio_structure.get("FREQ1") << 8) +
                self.radio_structure.get("FREQ0")
        )
        return int(num / freq_multiplier)

    def _get_frequency_offset_estimate(self):
        self.radio_structure.update()
        frequency_offset_estimate = self.radio_structure.get("FREQEST")
        return int(frequency_offset_estimate)

    def _set_frequency_offset(self, intermediate_frequency_offset):
        self._set_rf_register("FSCTRL0", intermediate_frequency_offset)

    def _get_frequency_offset(self):
        self.radio_structure.update()
        return self.radio_structure.get("FSCTRL0")

    def _adjust_frequency_offset(self):
        self._get_frequency_offset_estimate()
        self._frequency_offset_accumulator += self.radio_structure.get("FREQEST")
        self._frequency_offset_accumulator &= 0xFF
        self._set_frequency_offset(self._frequency_offset_accumulator)

    def _set_modulation(self, modulation, invert=False):
        self.radio_structure.update()
        mask_mdmcfg2 = YardRegistersMasks.MDMCFG2
        mdmcfg2 = self.radio_structure.get("MDMCFG2") & ~(mask_mdmcfg2.MOD_FORMAT.mask << mask_mdmcfg2.MOD_FORMAT.offset)
        mdmcfg2 |= ((modulation & mask_mdmcfg2.MOD_FORMAT.mask) << mask_mdmcfg2.MOD_FORMAT.offset)

        if modulation == YardModulations.MODULATION_ASK and not invert:
            if self.radio_structure.get("PA_TABLE0") != 0 and self.radio_structure.get("PA_TABLE1") == 0:
                power = self.radio_structure.get("PA_TABLE0")
                self._set_power(power, invert=invert)
        else:
            if self.radio_structure.get("PA_TABLE0") == 0 and self.radio_structure.get("PA_TABLE1") != 0:
                power = self.radio_structure.get("PA_TABLE1")
                self._set_power(power, invert=invert)
        #print(mdmcfg2)
        self._set_rf_register("MDMCFG2", mdmcfg2)

    def _get_modulation(self):
        self.radio_structure.update()
        mask_mdmcfg2 = YardRegistersMasks.MDMCFG2
        format = (
                    self.radio_structure.get("MDMCFG2") &
                    (mask_mdmcfg2.MOD_FORMAT.mask << mask_mdmcfg2.MOD_FORMAT.offset)
        ) >> mask_mdmcfg2.MOD_FORMAT.offset
        return format

    def _set_power(self, power, invert=False):
        modulation = self._get_modulation()
        if modulation == YardModulations.MODULATION_ASK and not invert:
            self.radio_structure.set("PA_TABLE0", 0)
            self.radio_structure.set("PA_TABLE1", power)
            self.radio_structure.set("PA_TABLE2", 0)
            self.radio_structure.set("PA_TABLE3", 0)
            self.radio_structure.set("PA_TABLE4", 0)
            self.radio_structure.set("PA_TABLE5", 0)
            self.radio_structure.set("PA_TABLE6", 0)
            self.radio_structure.set("PA_TABLE7", 0)


        else:
            self.radio_structure.set("PA_TABLE0", power)
            self.radio_structure.set("PA_TABLE1", 0)
            self.radio_structure.set("PA_TABLE2", 0)
            self.radio_structure.set("PA_TABLE3", 0)
            self.radio_structure.set("PA_TABLE4", 0)
            self.radio_structure.set("PA_TABLE5", 0)
            self.radio_structure.set("PA_TABLE6", 0)
            self.radio_structure.set("PA_TABLE7", 0)

        mask_frend0 = YardRegistersMasks.FREND0
        frend0 = self.radio_structure.get("FREND0") & ~(mask_frend0.PA_POWER.mask << mask_frend0.PA_POWER.offset)
        if modulation == YardModulations.MODULATION_ASK:
            frend0 |= (1 << mask_frend0.PA_POWER.offset)
        self._set_rf_register("FREND0", frend0)

    def _get_channel_spacing(self):
        self.radio_structure.update()
        mask_mdmcfg1 = YardRegistersMasks.MDMCFG1
        channel_spacing_mantissa = self.radio_structure.get("MDMCFG0")
        channel_spacing_exponent = (
            (self.radio_structure.get("MDMCFG1") &
            (mask_mdmcfg1.CHANSPC_E.mask << mask_mdmcfg1.CHANSPC_E.offset)
            ) >> mask_mdmcfg1.CHANSPC_E.offset
        )
        channel_spacing = 1000000.0 * (24/(2**18)) * (256 + channel_spacing_mantissa) * (2**channel_spacing_exponent)
        return channel_spacing


    def _set_channel_spacing(self, channel_spacing_khz):
        self.radio_structure.update()
        mask_mdmcfg1 = YardRegistersMasks.MDMCFG1

        for exponent in range(4):
            mantissa = int((channel_spacing_khz * (2**18)) / (((((1000000.0 * 24 * (2**exponent))))-256) +.5))
            if mantissa < 256:
                mdmcfg1 = (
                    self.radio_structure.get("MDMCFG1") &
                    ~(mask_mdmcfg1.CHANSPC_E.mask << mask_mdmcfg1.CHANSPC_E.offset)
                )
                mdmcfg1 |= ((exponent & mask_mdmcfg1.CHANSPC_E.mask) << mask_mdmcfg1.CHANSPC_E.offset)
                self._set_rf_register("MDMCFG1", mdmcfg1)
                self._set_rf_register("MDMCFG0", mantissa)
                return True
        return False

    def _set_packet_length(self, length, variable=False):
        self.radio_structure.update()
        mask_pktctrl0 = YardRegistersMasks.PKTCTRL0
        pktctrl0 = self.radio_structure.get("PKTCTRL0") & ~(mask_pktctrl0.LENGTH_CONFIG.mask << mask_pktctrl0.LENGTH_CONFIG.offset)
        pktctrl0 |= ((int(variable) & mask_pktctrl0.LENGTH_CONFIG.mask) << mask_pktctrl0.LENGTH_CONFIG.offset)

        self._set_rf_register("PKTLEN", length if length <= 255 else 0)

    def _is_packet_length_variable(self):
        self.radio_structure.update()
        mask_pktctrl0 = YardRegistersMasks.PKTCTRL0
        length_config = (
                        (
                            self.radio_structure.get("PKTCTRL0") &
                            (mask_pktctrl0.LENGTH_CONFIG.mask << mask_pktctrl0.LENGTH_CONFIG.offset)
                        ) >> mask_pktctrl0.LENGTH_CONFIG.offset
        )
        return bool(length_config)

    def _get_packet_length(self):
        self.radio_structure.update()
        return self.radio_structure.get("PKTLEN")

    def _set_crc(self, enable=False):
        self.radio_structure.update()
        mask_pktctrl0 = YardRegistersMasks.PKTCTRL0
        pktctrl0 = self.radio_structure.get("PKTCTRL0") & ~(mask_pktctrl0.CRC_EN.mask << mask_pktctrl0.CRC_EN.offset)
        pktctrl0 |= int(enable) << mask_pktctrl0.CRC_EN.offset
        self._set_rf_register("PKTCTRL0", pktctrl0)


    def _is_crc_enabled(self):
        self.radio_structure.update()
        mask_pktctrl0 = YardRegistersMasks.PKTCTRL0
        crc_enabled = bool(
            (
                self.radio_structure.get("PKTCTRL0") &
                (mask_pktctrl0.CRC_EN.mask << mask_pktctrl0.CRC_EN.offset)
            ) >> mask_pktctrl0.CRC_EN.offset
        )
        return crc_enabled

    def _set_whitening(self, enable=False):
        self.radio_structure.update()
        mask_pktctrl0 = YardRegistersMasks.PKTCTRL0
        pktctrl0 = self.radio_structure.get("PKTCTRL0") & ~(mask_pktctrl0.WHITE_DATA.mask << mask_pktctrl0.WHITE_DATA.offset)
        pktctrl0 |= int(enable) << mask_pktctrl0.WHITE_DATA.offset
        self._set_rf_register("PKTCTRL0", pktctrl0)


    def _is_whitening_enabled(self):
        self.radio_structure.update()
        mask_pktctrl0 = YardRegistersMasks.PKTCTRL0
        whitening_enabled = bool(
            (
                self.radio_structure.get("PKTCTRL0") &
                (mask_pktctrl0.WHITE_DATA.mask << mask_pktctrl0.WHITE_DATA.offset)
            ) >> mask_pktctrl0.WHITE_DATA.offset
        )
        return crc_enabled


    def _set_preamble_quality_threshold(self, threshold=3):
        self.radio_structure.update()
        mask_pktctrl1 = YardRegistersMasks.PKTCTRL1
        pktctrl1 = self.radio_structure.get("PKTCTRL1") & ~(mask_pktctrl1.PQT.mask << mask_pktctrl1.PQT.offset)
        pktctrl1 |= (threshold & mask_pktctrl1.PQT.mask) << mask_pktctrl1.PQT.offset
        self._set_rf_register("PKTCTRL1", pktctrl1)


    def _get_preamble_quality_threshold(self):
        self.radio_structure.update()
        mask_pktctrl1 = YardRegistersMasks.PKTCTRL1
        pqt = int(
            (
                self.radio_structure.get("PKTCTRL1") &
                (mask_pktctrl1.PQT.mask << mask_pktctrl1.PQT.offset)
            ) >> mask_pktctrl1.PQT.offset
        )
        return pqt


    def _is_append_packet_status_enabled(self):
        self.radio_structure.update()
        mask_pktctrl1 = YardRegistersMasks.PKTCTRL1
        append_packet_status_enabled = bool(
            (
                self.radio_structure.get("PKTCTRL1") &
                (mask_pktctrl1.APPEND_STATUS.mask << mask_pktctrl1.APPEND_STATUS.offset)
            ) >> mask_pktctrl1.APPEND_STATUS.offset
        )
        return append_packet_status_enabled

    def _set_append_packet_status(self, enable=False):
        self.radio_structure.update()
        mask_pktctrl1 = YardRegistersMasks.PKTCTRL1
        pktctrl1 = self.radio_structure.get("PKTCTRL1") & ~(mask_pktctrl1.APPEND_STATUS.mask << mask_pktctrl1.APPEND_STATUS.offset)
        pktctrl1 |= int(enable) << mask_pktctrl1.APPEND_STATUS.offset
        self._set_rf_register("PKTCTRL1", pktctrl1)


    def _set_encoding(self, encoding=YardEncodings.NON_RETURN_TO_ZERO):
        self.radio_structure.update()
        mask_mdmcfg2 = YardRegistersMasks.MDMCFG2
        mdmcfg2 = self.radio_structure.get("MDMCFG2") & ~(mask_mdmcfg2.MANCHESTER_EN.mask << mask_mdmcfg2.MANCHESTER_EN.offset)
        mdmcfg2 |= (int(encoding) << mask_mdmcfg2.MANCHESTER_EN.offset)
        self._set_rf_register("MDMCFG2", mdmcfg2)


    def _get_encoding(self):
        self.radio_structure.update()
        mask_mdmcfg2 = YardRegistersMasks.MDMCFG2
        encoding = int(
            (
                self.radio_structure.get("MDMCFG2") &
                (mask_mdmcfg2.MANCHESTER_EN.mask << mask_mdmcfg2.MANCHESTER_EN.offset)
            ) >> mask_mdmcfg2.MANCHESTER_EN.offset
        )
        return YardEncodings.MANCHESTER if encoding else YardEncodings.NON_RETURN_TO_ZERO


    def _set_forward_error_correction(self, enable=False):
        self.radio_structure.update()
        mask_mdmcfg1 = YardRegistersMasks.MDMCFG1
        mdmcfg1 = self.radio_structure.get("MDMCFG1") & ~(mask_mdmcfg1.FEC_EN.mask << mask_mdmcfg1.FEC_EN.offset)
        mdmcfg1 |= int(enable) << mask_mdmcfg1.FEC_EN.offset
        self._set_rf_register("MDMCFG1", mdmcfg1)


    def _get_forward_error_correction(self):
        self.radio_structure.update()
        mask_mdmcfg1 = YardRegistersMasks.MDMCFG1
        forward_error_correction = bool(
            (
                self.radio_structure.get("MDMCFG1") &
                (mask_mdmcfg1.FEC_EN.mask << mask_mdmcfg1.FEC_EN.offset)
            ) >> mask_mdmcfg1.FEC_EN.offset
        )
        return forward_error_correction


    def _set_intermediate_frequency(self, intermediate_frequency):
        self.radio_structure.update()
        mask_fsctrl1 = YardRegistersMasks.FSCTRL1
        computed_value = int(0.5 + (intermediate_frequency * (2**10)) / (1000000.0 * 24))
        fsctrl1 = self.radio_structure.get("FSCTRL1") & ~(mask_fsctrl1.FREQ_IF.mask << mask_fsctrl1.FREQ_IF.offset)
        fsctrl1 |= int(computed_value) << mask_fsctrl1.FREQ_IF.offset
        self._set_rf_register("FSCTRL1", fsctrl1)


    def _get_intermediate_frequency(self):
        self.radio_structure.update()
        mask_fsctrl1 = YardRegistersMasks.FSCTRL1
        if_value = int(
            (
                self.radio_structure.get("MDMCFG1") &
                (mask_fsctrl1.FREQ_IF.mask << mask_fsctrl1.FREQ_IF.offset)
            ) >> mask_fsctrl1.FREQ_IF.offset
        )
        intermediate_frequency = (if_value * ((1000000.0 * 24) / (2**10)))
        return intermediate_frequency

    def _set_channel(self, channel):
        self.radio_structure.set("CHANNR", channel)

    def _get_channel(self, channel):
        self.radio_structure.update()
        return self.radio_structure.get("CHANNR")


    def _set_channel_bandwidth(self, bandwidth):
        self.radio_structure.update()

        for exponent in range(4):
            mantissa = int((((24*1000000.0)/(bandwidth*(2**exponent)*8.0)) - 4) + 0.5)
            if mantissa < 4:
                mdmcfg4_mask = YardRegistersMasks.MDMCFG4
                mdmcfg4 = self.radio_structure.get("MDMCFG4") & ~(
                    (mdmcfg4_mask.CHANBW_E.mask << mdmcfg4_mask.CHANBW_E.offset ) |
                    (mdmcfg4_mask.CHANBW_M.mask << mdmcfg4_mask.CHANBW_M.offset )
                )
                mdmcfg4 |= (
                    ((exponent & mdmcfg4_mask.CHANBW_E.mask) << mdmcfg4_mask.CHANBW_E.offset) |
                    ((mantissa & mdmcfg4_mask.CHANBW_M.mask) << mdmcfg4_mask.CHANBW_M.offset)
                )
                self._set_rf_register("MDMCFG4", mdmcfg4)
                bw = 1000.0*24 / (8.0*(4+mantissa) * (2**exponent))
                if bw > 102e3:
                    self._set_rf_register("FREND1", 0xb6)
                else:
                    self._set_rf_register("FREND1", 0x56)

                if bw > 325e3:
                    self._set_rf_register("TEST2", 0x88)
                    self._set_rf_register("TEST1", 0x31)
                else:
                    self._set_rf_register("TEST2", 0x81)
                    self._set_rf_register("TEST1", 0x35)
                return True
        return False

    def _get_channel_bandwidth(self):
        self.radio_structure.update()

        mdmcfg4_mask = YardRegistersMasks.MDMCFG4
        mdmcfg4 = self.radio_structure.get("MDMCFG4")
        exponent = (
            mdmcfg4 & (mdmcfg4_mask.CHANBW_E.mask << mdmcfg4_mask.CHANGW_E.offset )
            ) >> mdmcfg4.CHANGW_E.offset
        mantissa = (
            mdmcfg4 & (mdmcfg4_mask.CHANBW_M.mask << mdmcfg4_mask.CHANGW_M.offset )
            ) >> mdmcfg4.CHANGW_M.offset

        return (1000000.0*24) / (8.0*(4+mantissa) * (2**exponent))

    def _set_data_rate(self, data_rate):
        self.radio_structure.update()
        mdmcfg4 = self.radio_structure.get("MDMCFG4")
        mdmcfg4_mask = YardRegistersMasks.MDMCFG4

        for exponent in range(16):
            mantissa = int(((data_rate * (2**28)) / ((2**exponent) * (24*1000000.0)) - 256) + 0.5)
            if mantissa < 256:
                self._set_rf_register("MDMCFG3", mantissa)
                mdmcfg4 = mdmcfg4 & ~(mdmcfg4_mask.DRATE_E.mask << mdmcfg4_mask.DRATE_E.offset)
                mdmcfg4 |= ((exponent & mdmcfg4_mask.DRATE_E.mask) << mdmcfg4_mask.DRATE_E.offset)
                self._set_rf_register("MDMCFG4", mdmcfg4)
                return True
        return False

    def _get_data_rate(self):
        self.radio_structure.update()
        mdmcfg4_mask = YardRegistersMasks.MDMCFG4
        exponent = int(
            (
                self.radio_structure.get("MDMCFG4") &
                (mdmcfg4_mask.DRATE_E.mask << mdmcfg4_mask.DRATE_E.offset)
            ) >> mdmcfg4_mask.DRATE_E.offset
        )
        mantissa = self.radio_structure.get("MDMCFG3")
        data_rate = 1000000.0 * 24 * (256+mantissa) * (2**exponent) / (2**28)
        return data_rate


    def _set_deviation(self, deviation):
        deviatn_mask = YardRegistersMasks.DEVIATN

        for exponent in range(8):
            mantissa = int(((deviation * (2**17)) / ((2**exponent) * (24*1000000.0)) - 8) + 0.5)
            if mantissa < 8:
                deviatn = (
                    ((mantissa & deviatn_mask.DEVIATION_M.mask) << deviatn_mask.DEVIATION_M.offset) |
                    ((exponent & deviatn_mask.DEVIATION_E.mask) << deviatn_mask.DEVIATION_E.offset)
                )
                self._set_rf_register("DEVIATN", deviatn)
                return True
        return False

    def _get_deviation(self):
        self.radio_structure.update()
        deviatn_mask = YardRegistersMasks.DEVIATN
        deviatn = self.radio_structure.get("DEVIATN")
        exponent = int(
            (
                deviatn &
                (deviatn_mask.DEVIATION_E.mask << deviatn_mask.DEVIATION_E.offset)
            ) >> deviatn_mask.DEVIATION_E.offset
        )
        mantissa = int(
            (
                deviatn &
                (deviatn_mask.DEVIATION_E.mask << deviatn_mask.DEVIATION_E.offset)
            ) >> deviatn_mask.DEVIATION_E.offset
        )

        deviation = 1000000.0 * 24 * (8+mantissa) * (2**exponent) / (2**17)
        return deviation

    def _set_sync_word(self, sync_word, carrier_sense=False, bitflip_tolerance=False):
        sync_mode = 0
        if len(sync_word) == 0:
            sync_mode = int(carrier_sense) << 2 | 0
        elif len(sync_word) == 2:
            sync_mode = (int(carrier_sense) << 2) | (1 << int(bitflip_tolerance))
        elif len(sync_word) == 4:
            if sync_word[:2] == sync_word[2:]:
                sync_mode = (int(carrier_sense) << 2) | 0b11
            else:
                return False
        else:
            return False

        self.radio_structure.update()
        mdmcfg2 = self.radio_structure.get("MDMCFG2")
        mdmcfg2_mask = YardRegistersMasks.MDMCFG2

        mdmcfg2 &= ~(mdmcfg2_mask.SYNC_MODE.mask << mdmcfg2_mask.SYNC_MODE.offset)
        mdmcfg2 |= ((sync_mode & mdmcfg2_mask.SYNC_MODE.mask) <<  mdmcfg2_mask.SYNC_MODE.offset)
        if len(sync_word) > 0:
            self._set_rf_register("SYNC1",sync_word[1])
            self._set_rf_register("SYNC0",sync_word[0])
        self._set_rf_register("MDMCFG2", mdmcfg2)

        return True

    def _get_sync_word(self):
        self.radio_structure.update()
        mdmcfg2 = self.radio_structure.get("MDMCFG2")
        mdmcfg2_mask = YardRegistersMasks.MDMCFG2
        sync_mode = int(
            (mdmcfg2 & (mdmcfg2_mask.SYNC_MODE.mask << mdmcfg2_mask.SYNC_MODE.offset))
            >>  mdmcfg2_mask.SYNC_MODE.offset
        )
        if sync_mode & 0b11 == 0b11:
            multiplier = 2
        elif sync_mode & 0b11 == 0:
            multiplier = 0
        else:
            multiplier = 1
        return multiplier * bytes([self.radio_structure.get("SYNC0"), self.radio_structure.get("SYNC1")])

    def _get_number_of_preamble_bytes(self):
        self.radio_structure.update()
        mdmcfg1 = self.radio_structure.get("MDMCFG1")
        mdmcfg1_mask = YardRegistersMasks.MDMCFG1
        num_preamble_flag = int((
            mdmcfg1 &
            (mdmcfg1.NUM_PREAMBLE.mask << mdmcfg1.NUM_PREAMBLE.offset)
        ) >> mdmcfg1.NUM_PREAMBLE.offset)
        return NUM_PREAMBLE_LOOKUP_TABLE[num_preamble_flag]

    def _set_number_of_preamble_bytes(self, number):
        try:
            num_preamble_flag = NUM_PREAMBLE_LOOKUP_TABLE[number]
        except IndexError:
            return False

        self.radio_structure.update()
        mdmcfg1 = self.radio_structure.get("MDMCFG1")
        mdmcfg1_mask = YardRegistersMasks.MDMCFG1
        mdmcfg1 &= ~(mdmcfg1.NUM_PREAMBLE.mask << mdmcfg1.NUM_PREAMBLE.offset)

        mdmcfg1 |= ((num_preamble_flag & mdmcfg1.NUM_PREAMBLE.mask) << mdmcfg1.NUM_PREAMBLE.offset)
        self._set_rf_register("MDMCFG1", mdmcfg1)
        return True

    def compute_best_deviation(self):
        data_rate = self._get_data_rate()
        if data_rate <= 2400:
            deviation = 5100
        elif data_rate <= 38400:
            deviation = 20000 * ((data_rate - 2400) / 36000)
        else:
            deviation = 129000 * ((data_rate - 38400) / 211600)
        return deviation

    def compute_best_channel_bandwidth(self):
        frequency = self._get_frequency()
        data_rate = self._get_data_rate()
        center_frequency = frequency + 14000000
        frequency_uncertainty = 2 * (20e-6 * frequency)
        min_bandwidth = frequency_uncertainty + data_rate
        best_bandwidth = None
        for possible in POSSIBLE_CHANNEL_BANDWIDTHS:
            if min_bandwidth < possible:
                best_bandwidth = possible
                break
        return best_bandwidth

    def _set_power_amplifier_mode(self, mode=0):
        return self._yard_send_command(
            YardApplications.NIC,
            YardNICCommands.SET_AMP_MODE,
            pack("B", mode)
        )
    def _get_power_amplifier_mode(self):
        return self._yard_send_command(
            YardApplications.NIC,
            YardNICCommands.GET_AMP_MODE
        )[0]

    def _set_packet_format(self, format=0):
        self.radio_structure.update()
        mask_pktctrl0 = YardRegistersMasks.PKTCTRL0

        pktctrl0 = self.radio_structure.get("PKTCTRL0") & ~(mask_pktctrl0.PKT_FORMAT.mask << mask_pktctrl0.PKT_FORMAT.offset)
        pktctrl0 |= ((int(format) & mask_pktctrl0.PKT_FORMAT.mask) << mask_pktctrl0.PKT_FORMAT.offset)

        self._set_rf_register("PKTCTRL0", pktctrl0)

    def set_test_config(self):
        self._set_rf_register("IOCFG0",0x06)
        self._set_rf_register("SYNC1",0xaa)
        self._set_rf_register("SYNC0",0xaa)
        self._set_rf_register("PKTLEN",255)
        self._set_rf_register("PKTCTRL1",0x00)
        self._set_rf_register("PKTCTRL0",0x08)
        self._set_rf_register("FSCTRL1",0x0b)
        self._set_rf_register("FSCTRL0",0x00)
        self._set_rf_register("ADDR",0x00)
        self._set_rf_register("CHANNR",0x00)
        self._set_rf_register("MDMCFG4",0x68)
        self._set_rf_register("MDMCFG3",0xb5)
        self._set_rf_register("MDMCFG2",0x80)
        self._set_rf_register("MDMCFG1",0x23)
        self._set_rf_register("MDMCFG0",0x11)
        self._set_rf_register("MCSM2",0x07)
        self._set_rf_register("MCSM1",0x3f)
        self._set_rf_register("MCSM0",0x14)
        self._set_rf_register("DEVIATN",0x45)
        self._set_rf_register("FOCCFG",0x16)
        self._set_rf_register("BSCFG",0x6c)
        self._set_rf_register("AGCCTRL2",0x43)
        self._set_rf_register("AGCCTRL1",0x40)
        self._set_rf_register("AGCCTRL0",0x91)
        self._set_rf_register("FREND1",0x56)
        self._set_rf_register("FREND0",0x10)
        self._set_rf_register("FSCAL3",0xad)
        self._set_rf_register("FSCAL2",0x0A)
        self._set_rf_register("FSCAL1",0x00)
        self._set_rf_register("FSCAL0",0x11)
        self._set_rf_register("TEST2",0x88)
        self._set_rf_register("TEST1",0x31)
        self._set_rf_register("TEST0",0x09)
        self._set_rf_register("PA_TABLE0",0x05)
        self._set_rf_register("PA_TABLE1",0x00)
