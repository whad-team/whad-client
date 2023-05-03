from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.device.virtual.yard.constants import YardStickOneId, YardStickOneEndPoints, \
    YardApplications, YardSystemCommands, YardRadioStructure, YardRFStates, \
    YardMemoryRegisters, YardMARCStates, YardCCA, YardFrequencyTransitionPoints, \
    YardNICCommands, YardVCOType, YardRegistersMasks,YardModulations
from whad.helpers import message_filter,is_message_type
from whad import WhadDomain, WhadCapability
from whad.protocol.generic_pb2 import ResultCode
from usb.core import find, USBError, USBTimeoutError
from usb.util import get_string
from struct import unpack, pack
from time import sleep
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
        self.__in_buffer = b""
        self.__queue = Queue()
        self.__opened = False
        self.__index, self.__yard = device
        super().__init__()

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
        print(self.radio_structure)

        self._set_idle_mode()
        self.set_test_config()
        self._set_rx_mode()
        self._strobe_rx_mode()


        # Ask parent class to run a background I/O thread
        super().open()
        self.__opened_stream = True

        try:
            while True:
                sleep(1)
        except:
            self.close()

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
                while self.__opened_stream:
                    data = self._yard_read_response()
                    print("recv:", data)
                    print(self._get_frequency(), self._get_frequency_offset_estimate())
                    #self.radio_structure.update()
                    #print(self.radio_structure.get("MARCSTATE"))
                    #print(self.radio_structure)


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

    def _yard_read_response(self, timeout=500):
        try:
            response = bytes(self.__yard.read(YardStickOneEndPoints.IN_ENDPOINT, 500, timeout=timeout))
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

    def _yard_send_command(self, app, command, data=b"", timeout=500):
        message = bytes([app, command]) + pack("<H", len(data)) + data
        recv_app, recv_verb, recv_data = None, None, None
        while recv_app != app and recv_verb != command:
            print(">", message.hex())
            self.__yard.write(YardStickOneEndPoints.OUT_ENDPOINT, message, timeout=timeout)
            recv_app, recv_verb, recv_data = self._yard_read_response()
        return recv_data

    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Phy : (
                                (WhadCapability.Sniff),
                                []
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
        mcsm1 |= (mode << masks_mcsm1.offset)

        mask_magn_target = YardRegistersMasks.AGCCTRL2.MAGN_TARGET
        agcctrl2 = self.radio_structure.get("AGCCTRL2") & ~(mask_magn_target.mask << mask_magn_target.offset)
        agcctrl2 |= (magnitude << magn_target.offset)

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
        else:
            self.radio_structure.set("PA_TABLE0", power)
            self.radio_structure.set("PA_TABLE1", 0)

        mask_frend0 = YardRegistersMasks.FREND0
        frend0 = self.radio_structure.get("FREND0") & ~(mask_frend0.PA_POWER.mask << mask_frend0.PA_POWER.offset)
        if modulation == YardModulations.MODULATION_ASK:
            frend0 |= 1
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
        pktctrl0 |= (int(variable) << mask_pktctrl0.LENGTH_CONFIG.offset)
        self._set_rf_register("PKTCTRL0", pktctrl0)
        self._set_rf_register("PKTLEN", length if length <= 255 else 0)



    def set_test_config(self):
        self._set_rf_register("IOCFG0",0x06)
        self._set_rf_register("SYNC1",0xaa)
        self._set_rf_register("SYNC0",0xaa)
        self._set_rf_register("PKTLEN",0xff)
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
        self._set_rf_register("PA_TABLE0",0x00)
        self._set_rf_register("PA_TABLE1",0x01)
        self._set_frequency(433920000)
        self._set_modulation(YardModulations.MODULATION_ASK)
        self._set_packet_length(30)
