"""
This module provides some constants used by WHAD to communicate with the Yard Stick One.
"""
from enum import IntEnum
from dataclasses import dataclass


class YardInternalStates(IntEnum):
    """Internal states.
    """
    YARD_MODE_IDLE = 0
    YARD_MODE_RX = 1
    YARD_MODE_TX = 2

@dataclass
class RegisterMask:
    """Register mask class.

    This class stores the offset to a register and its
    associated mask.
    """
    mask : int = 0
    offset : int = 0

class YardUSBProperties:
    """USB timeouts.
    """
    USB_RX_WAIT = 1000
    USB_TX_WAIT = 10000

class YardStickOneId(IntEnum):
    """Yard USB vendor and product IDs.
    """
    YARD_ID_VENDOR    = 0x1d50
    YARD_ID_PRODUCT   = 0x605b

class YardStickOneEndPoints(IntEnum):
    """USB endpoints.
    """
    SETUP_ENDPOINT      = 0x00
    IN_ENDPOINT         = 0x85
    OUT_ENDPOINT        = 0x05

class YardApplications(IntEnum):
    """Applications.
    """
    GENERIC                 = 0x01
    DEBUG                   = 0xfe
    SYSTEM                  = 0xff
    NIC                     = 0x42
    SPECAN                  = 0x43

class YardSystemCommands(IntEnum):
    """System commands op-codes.
    """
    PEEK                    = 0x80
    POKE                    = 0x81
    PING                    = 0x82
    STATUS                  = 0x83
    POKE_REG                = 0x84
    GET_CLOCK               = 0x85
    BUILDTYPE               = 0x86
    BOOTLOADER              = 0x87
    RFMODE                  = 0x88
    COMPILER                = 0x89
    PARTNUM                 = 0x8e
    RESET                   = 0x8f
    CLEAR_CODES             = 0x90
    DEVICE_SERIAL_NUMBER    = 0x91
    LED_MODE                = 0x93

class YardNICCommands(IntEnum):
    """NICC commands.
    """
    RECV                = 0x1
    XMIT                = 0x2
    SET_ID              = 0x3
    SET_RECV_LARGE      = 0x5
    SET_AES_MODE        = 0x6
    GET_AES_MODE        = 0x7
    SET_AES_IV          = 0x8
    SET_AES_KEY         = 0x9
    SET_AMP_MODE        = 0xa
    GET_AMP_MODE        = 0xb
    LONG_XMIT           = 0xc
    LONG_XMIT_MORE      = 0xd

class YardRFStates:
    """RF states
    """
    SFSTXON                 = 0x00
    SCAL                    = 0x01
    SRX                     = 0x02
    STX                     = 0x03
    SIDLE                   = 0x04
    SNOP                    = 0x05

class YardMARCStates(IntEnum):
    """Main Radio Control State.
    """
    MARC_STATE_SLEEP               = 0x00
    MARC_STATE_IDLE                = 0x01
    MARC_STATE_VCOON_MC            = 0x03
    MARC_STATE_BWBOOST             = 0x09
    MARC_STATE_ENDCAL              = 0x0C
    MARC_STATE_FSTXON              = 0x12
    MARC_STATE_FS_LOCK             = 0x0A
    MARC_STATE_IFADCON             = 0x0B
    MARC_STATE_MANCAL              = 0x05
    MARC_STATE_REGON               = 0x07
    MARC_STATE_REGON_MC            = 0x04
    MARC_STATE_RX                  = 0x0D
    MARC_STATE_RXTX_SWITCH         = 0x15
    MARC_STATE_RX_END              = 0x0E
    MARC_STATE_RX_OVERFLOW         = 0x11
    MARC_STATE_RX_RST              = 0x0F
    MARC_STATE_STARTCAL            = 0x08
    MARC_STATE_TX                  = 0x13
    MARC_STATE_TXRX_SWITCH         = 0x10
    MARC_STATE_TX_END              = 0x14
    MARC_STATE_TX_UNDERFLOW        = 0x16
    MARC_STATE_VCOON               = 0x06

class YardRadioStructure:
    """Radio configuration structure.
    """
    FIELDS = [
        "SYNC1",
        "SYNC0",
        "PKTLEN",
        "PKTCTRL1",
        "PKTCTRL0",
        "ADDR",
        "CHANNR",
        "FSCTRL1",
        "FSCTRL0",
        "FREQ2",
        "FREQ1",
        "FREQ0",
        "MDMCFG4",
        "MDMCFG3",
        "MDMCFG2",
        "MDMCFG1",
        "MDMCFG0",
        "DEVIATN",
        "MCSM2",
        "MCSM1",
        "MCSM0",
        "FOCCFG",
        "BSCFG",
        "AGCCTRL2",
        "AGCCTRL1",
        "AGCCTRL0",
        "FREND1",
        "FREND0",
        "FSCAL3",
        "FSCAL2",
        "FSCAL1",
        "FSCAL0",
        "Z0",
        "Z1",
        "Z2",
        "TEST2",
        "TEST1",
        "TEST0",
        "Z3",
        "PA_TABLE7",
        "PA_TABLE6",
        "PA_TABLE5",
        "PA_TABLE4",
        "PA_TABLE3",
        "PA_TABLE2",
        "PA_TABLE1",
        "PA_TABLE0",
        "IOCFG2",
        "IOCFG1",
        "IOCFG0",
        "Z4",
        "Z5",
        "Z6",
        "Z7",
        "PARTNUM",
        "CHIPID",
        "FREQEST",
        "LQI",
        "RSSI",
        "MARCSTATE",
        "PKSTATUS",
        "VCO_VC_DAC"
    ]

    BASE_ADDRESS = 0xDF00
    MEMORY_SIZE = 0x3E

    def __init__(self, poke, peek):
        self._poke = poke
        self._peek = peek

        self._memory = self._peek(YardRadioStructure.BASE_ADDRESS,YardRadioStructure.MEMORY_SIZE)

    def update(self):
        """Read current configuration from memory.
        """
        self._memory = self._peek(YardRadioStructure.BASE_ADDRESS,YardRadioStructure.MEMORY_SIZE)

    def get(self, name: str) -> int:
        """Get a specific configuration field from current configuration.

        :param name: Configuration field
        :type name: str
        :return: Field value
        :rtype: bytes
        """
        offset = YardRadioStructure.FIELDS.index(name)
        return self._memory[offset]

    def set(self, name: str, data: int) -> bool:
        """Set a specific field value in current configuration.

        :param name: Field name
        :type name: str
        :param data: Field value
        :type data: int
        :return: `True` if field has successfully been updated, `False` otherwise.
        :rtype: bool
        """
        offset = YardRadioStructure.FIELDS.index(name)
        self._poke(YardRadioStructure.BASE_ADDRESS + offset, bytes([data]))
        if self._peek(YardRadioStructure.BASE_ADDRESS + offset, 1) == bytes([data]):
            self._memory = self._memory[:offset] + bytes([data]) + self._memory[offset+1:]
            return True
        return False

    def __repr__(self) -> str:
        """Get the textual representation of the Yard configuration structure.

        :return: Configuration structure reprensentation
        :rtype: str
        """
        return "\n".join([f"{name} -> {self.get(name):02x}" for name in YardRadioStructure.FIELDS])


class YardMemoryRegisters(IntEnum):
    """Yard registers
    """
    RFST = 0xDFE1

class YardCCA(IntEnum):
    """Yard clear channel assessment (CCA)
    """
    NO_CCA                      = 0
    CCA_RSSI_THRESHOLD          = 1
    CCA_PACKET                  = 2
    CCA_PACKET_RSSI_THRESHOLD   = 3

class YardFrequencyTransitionPoints:
    """Frequency band and VCO transition points.
    """

    # band transition points in Hz
    FREQ_EDGE_400 = 369000000
    FREQ_EDGE_900 = 615000000

    # VCO transition points in Hz
    FREQ_MID_300  = 318000000
    FREQ_MID_400  = 424000000
    FREQ_MID_900  = 848000000

class YardVCOType:
    """Voltage Control Oscillator types.
    """
    LOW_VCO = 0x0A
    HIGH_VCO = 0x2A

class YardModulations:
    """Supported modulations.
    """
    MODULATION_2FSK                        = 0b000
    MODULATION_GFSK                        = 0b001
    MODULATION_ASK                         = 0b011
    MODULATION_4FSK                        = 0b100
    MODULATION_MSK                         = 0b111

class YardEncodings:
    """Supported encodings.
    """
    NON_RETURN_TO_ZERO  = 0
    MANCHESTER          = 1

# Yard Registers Masks
class YardRegistersMasks:
    """Registers masks.
    """

    class MDMCFG1:
        """Modem Config register 1
        """
        CHANSPC_E = RegisterMask(mask=0b11, offset=0)
        NUM_PREAMBLE = RegisterMask(mask=0b111, offset=4)
        FEC_EN = RegisterMask(mask=0b1, offset=7)


    class MDMCFG2:
        """Modem config register 2
        """
        SYNC_MODE = RegisterMask(mask=0b111, offset=0)
        MANCHESTER_EN = RegisterMask(mask=0b1, offset=3)
        MOD_FORMAT = RegisterMask(mask=0b111, offset=4)
        DEM_DCFILT_OFF = RegisterMask(mask=0b1, offset=7)


    class MDMCFG3:
        """Modem config register 3
        """
        DRATE_M = RegisterMask(mask=0b11111111, offset=0)

    class MDMCFG4:
        """Modem config register 4
        """
        DRATE_E = RegisterMask(mask=0b1111, offset=0)
        CHANBW_M = RegisterMask(mask=0b11, offset=4)
        CHANBW_E = RegisterMask(mask=0b11, offset=6)

    class PKTCTRL0:
        """Packet control register 0
        """
        LENGTH_CONFIG = RegisterMask(mask=0b11, offset=0)
        CRC_EN = RegisterMask(mask=0b1, offset=2)
        PKT_FORMAT = RegisterMask(mask=0b11, offset=4)
        WHITE_DATA = RegisterMask(mask=0b1, offset=6)


    class PKTCTRL1:
        """Packet control register 1
        """
        ADR_CHK = RegisterMask(mask=0b11, offset=0)
        APPEND_STATUS = RegisterMask(mask=0b1, offset=2)
        PQT = RegisterMask(mask=0b111, offset=5)

    class MCSM1:
        """Mode control registers.
        """
        TXOFF_MODE = RegisterMask(mask=0b11, offset=0)
        RXOFF_MODE = RegisterMask(mask=0b11, offset=2)
        CCA_MODE = RegisterMask(mask=0b11, offset=4)


    class MCSM2:
        """RX time registers.
        """
        RX_TIME = RegisterMask(mask=0b111, offset=0)
        RX_TIME_QUAL = RegisterMask(mask=0b1, offset=3)
        RX_TIME_RSSI = RegisterMask(mask=0b1, offset=4)

    class AGCCTRL1:
        """Adaptative Gain Control control register 1
        """
        CARRIER_SENSE_ABS_THR = RegisterMask(mask=0b1111, offset=0)
        CARRIER_SENSE_REL_THR = RegisterMask(mask=0b11, offset=4)
        AGC_LNA_PRIORITY = RegisterMask(mask=0b1, offset=6)


    class AGCCTRL2:
        """Adaptative Gain Control control register 2
        """
        MAGN_TARGET  = RegisterMask(mask=0b111, offset=0)
        MAX_LNA_GAIN  = RegisterMask(mask=0b111, offset=3)
        MAX_DVGA_GAIN  = RegisterMask(mask=0b11, offset=6)

    class DEVIATN:
        """Deviation control register
        """
        DEVIATION_M = RegisterMask(mask=0b111, offset=0)
        DEVIATION_E = RegisterMask(mask=0b111, offset=4)

    class FSCTRL0:
        """Frequency offset control register 0
        """
        FREQ_OFFSET = RegisterMask(mask=0b11111111, offset=0)

    class FSCTRL1:
        """Frequency offset control register 1
        """
        FREQ_IF = RegisterMask(mask=0b11111, offset=0)

    class FREND0:
        """Power amplifier control registers.
        """
        PA_POWER = RegisterMask(mask=0b111, offset=0)
        LODIV_BUF_CURRENT_TX = RegisterMask(mask=0b11, offset=4)

    class FREND1:
        """Low-noise amplifier control registers.
        """
        MIX_CURRENT = RegisterMask(mask=0b11, offset=0)
        LODIV_BUF_CURRENT_RX = RegisterMask(mask=0b11, offset=2)
        LNA2MIX_CURRENT = RegisterMask(mask=0b11, offset=4)
        LNA_CURRENT = RegisterMask(mask=0b11, offset=6)


# Number of preamble bytes lookup table
NUM_PREAMBLE_LOOKUP_TABLE = [
    2,
    3,
    4,
    6,
    8,
    12,
    16,
    24
]

# Possible bandwidth list
POSSIBLE_CHANNEL_BANDWIDTHS = [
    53e3,
    63e3,
    75e3,
    93e3,
    107e3,
    125e3,
    150e3,
    188e3,
    214e3,
    250e3,
    300e3,
    375e3,
    428e3,
    500e3,
    600e3,
    750e3,
]
