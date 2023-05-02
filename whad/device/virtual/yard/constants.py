"""
This module provides some constants used by WHAD to communicate with the Yard Stick One.
"""
from enum import IntEnum

# USB identifiers
class YardStickOneId(IntEnum):
    YARD_ID_VENDOR    = 0x1d50
    YARD_ID_PRODUCT   = 0x605b

# USB Endpoints
class YardStickOneEndPoints(IntEnum):
    SETUP_ENDPOINT      = 0x00
    IN_ENDPOINT         = 0x85
    OUT_ENDPOINT        = 0x05

# YardStickOne applications
class YardApplications(IntEnum):
    GENERIC                 = 0x01
    DEBUG                   = 0xfe
    SYSTEM                  = 0xff
    NIC                     = 0x42
    SPECAN                  = 0x43

# YardStickOne System commands
class YardSystemCommands(IntEnum):
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

#YardStickOne NIC commands
class YardNICCommands(IntEnum):
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

# YardStickOne RF States
class YardRFStates:
    SFSTXON                 = 0x00
    SCAL                    = 0x01
    SRX                     = 0x02
    STX                     = 0x03
    SIDLE                   = 0x04
    SNOP                    = 0x05

# YardStickOne Main Radio Control State
class YardMARCStates(IntEnum):
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

# YardStickOne Radio Configuration Structure
class YardRadioStructure:
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
        self._memory = self._peek(YardRadioStructure.BASE_ADDRESS,YardRadioStructure.MEMORY_SIZE)

    def get(self, name):
        offset = YardRadioStructure.FIELDS.index(name)
        return self._memory[offset]

    def set(self, name, data):
        offset = YardRadioStructure.FIELDS.index(name)
        self._poke(YardRadioStructure.BASE_ADDRESS + offset, bytes([data]))
        if self._peek(YardRadioStructure.BASE_ADDRESS + offset, 1) == bytes([data]):
            self._memory = self._memory[:offset] + bytes([data]) + self._memory[offset+1:]
            return True
        return False

    def __repr__(self):
        out = ""
        for name in YardRadioStructure.FIELDS:
            out += name + " -> "+"{:02x}".format(self.get(name)) + "\n"
        return out


# Yard Registers
class YardMemoryRegisters(IntEnum):
    RFST = 0xDFE1

# Yard Clear Channel Assessment
class YardCCA(IntEnum):
    NO_CCA                      = 0
    CCA_RSSI_THRESHOLD          = 1
    CCA_PACKET                  = 2
    CCA_PACKET_RSSI_THRESHOLD   = 3

# Yard Frequency band and VCO transition points
class YardFrequencyTransitionPoints:

    # band transition points in Hz
    FREQ_EDGE_400 = 369000000
    FREQ_EDGE_900 = 615000000

    # VCO transition points in Hz
    FREQ_MID_300  = 318000000
    FREQ_MID_400  = 424000000
    FREQ_MID_900  = 848000000

# Yard Voltage Control Oscillator types
class YardVCOType:
    LOW_VCO = 0x0A
    HIGH_VCO = 0x2A
