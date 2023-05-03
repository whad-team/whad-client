"""
This module provides some constants used by WHAD to communicate with the APIMote.
"""
from enum import IntEnum,Enum
from dataclasses import dataclass


@dataclass
class RegisterMask:
    mask : int = 0
    offset : int = 0

class APIMoteId(IntEnum):
    APIMOTE_ID_VENDOR    = 0x0403
    APIMOTE_ID_PRODUCT   = 0x6015

# APIMote internal states
class APIMoteInternalStates(IntEnum):
    NONE                    = 0
    SNIFFING                = 1
    TRANSMITTING            = 2


class APIMoteRegisters(IntEnum):
    # Status registers: initiate the change of an internal state or mode
    SNOP            = 0x00        # No operation
    SXOSCON         = 0x01        # Crystal oscillator
    STXCAL          = 0x02        # Enable/calibrate frequency Synthesizer
    SRXON           = 0x03        # Enable RX
    STXON           = 0x04        # Enable TX
    STXONCCA        = 0x05        # Enable TX if CCA indicates a clear channel
    SRFOFF          = 0x06        # Disable RX/TX and frequency synthetiser
    SRXOSCOFF       = 0x07        # Turn off RF and crystal oscillator
    SFLUSHRX        = 0x08        # Flush RX fifo and reset demodulator
    SFLUSHTX        = 0x09        # Flush TX fifo
    SACK            = 0x0A        # Send Acknowledgment, with pending field cleared
    SACKPEND        = 0x0B        # Send Acknowledgment, with pending field set
    SRXDEC          = 0x0C        # Start RX fifo decryption / authentication
    STXENC          = 0x0D        # Start TX fifo encryption / authentication
    SAES            = 0x0E        # AES encryption strobe

    # Configuration registers
    MAIN            = 0x10        # Main Control Register
    MDMCTRL0        = 0x11        # Modem Control Register 0
    MDMCTRL1        = 0x12        # Modem Control Register 1
    RSSI            = 0x13        # RSSI and CCA Status and Control
    SYNCWORD        = 0x14        # Synchronisation word control register
    TXCTRL          = 0x15        # Transmit Control Register
    RXCTRL0         = 0x16        # Receive Control Register 0
    RXCTRL1         = 0x17        # Receive Control Register 1
    FSCTRL          = 0x18        # Frequency Synthesizer Control and Status Register
    SECCTRL0        = 0x19        # Security Control Register 0
    SECCTRL1        = 0x1A        # Security Control Register 1
    BATTMON         = 0x1B        # Battery Monitor Control and Status Register
    IOCFG0          = 0x1C        # Input / Output Control Register 0
    IOCFG1          = 0x1D        # Input / Output Control Register 1
    MANFIDL         = 0x1E        # Manufacturer ID, Low 16 bits
    MANFIDH         = 0x1F        # Manufacturer ID, High 16 bits
    FSMTC           = 0x20        # Finite State Machine Time Constants
    MANAND          = 0x21        # Manual signal AND override register
    MANOR           = 0x22        # Manual signal OR override register
    AGCCTRL         = 0x23        # AGC Control Register
    AGCTST0         = 0x24        # AGC Test Register 0
    AGCTST1         = 0x25        # AGC Test Register 1
    AGCTST2         = 0x26        # AGC Test Register 2
    FSTST0          = 0x27        # Frequency Synthesizer Test Register 0
    FSTST1          = 0x28        # Frequency Synthesizer Test Register 1
    FSTST2          = 0x29        # Frequency Synthesizer Test Register 2
    FSTST3          = 0x2A        # Frequency Synthesizer Test Register 3
    RXBPFTST        = 0x2B        # Receiver Bandpass Filter Test Register
    FSMSTATE        = 0x2C        # Finite State Machine State Status Register
    ADCTST          = 0x2D        # ADC Test Register
    DACTST          = 0x2E        # DAC Test Register
    TOPTST          = 0x2F        # Top Level Test Register
    RESERVED        = 0x30        # Reserved for future use control
    TXFIFO          = 0x3E        # Transmit FIFO Byte Register
    RXFIFO          = 0x3F        # Receiver FIFO Byte Register

class APIMoteRegistersMasks:

    class MCSM0:
        CLOSE_IN_RX = RegisterMask(mask=0b11, offset=0)
        FS_AUTOCAL = RegisterMask(mask=0b11, offset=4)

    class MCSM1:
        TX_OFF_MODE = RegisterMask(mask=0b11, offset=0)
        RX_OFF_MODE = RegisterMask(mask=0b11, offset=2)
        CCA_MODE = RegisterMask(mask=0b11, offset=4)

    class MDMCTRL0:
        PREAMBLE_LENGTH = RegisterMask(mask=0b1111, offset=0)
        AUTO_ACK = RegisterMask(mask=0b1, offset=4)
        AUTO_CRC = RegisterMask(mask=0b1, offset=5)
        CCA_MODE = RegisterMask(mask=0b11, offset=6)
        CCA_HYST = RegisterMask(mask=0b111, offset=8)
        ADR_DECODE = RegisterMask(mask=0b1, offset=11)
        PAN_COORDINATOR = RegisterMask(mask=0b1, offset=12)
        RESERVED_FRAME_MODE = RegisterMask(mask=0b1, offset=13)

    class MDMCTRL1:
        RX_MODE = RegisterMask(mask=0b11, offset=0)
        TX_MODE = RegisterMask(mask=0b11, offset=2)
        MODULATION_MODE = RegisterMask(mask=0b1, offset=4)
        DEMOD_AVG_MODE = RegisterMask(mask=0b1, offset=5)
        CORR_THR = RegisterMask(mask=0b11111, offset=6)

    class IOCFG0:
        FIFOP_THR = RegisterMask(mask=0b1111111, offset=0)
        CCA_POLARITY = RegisterMask(mask=0b1, offset=7)
        SFD_POLARITY = RegisterMask(mask=0b1, offset=8)
        FIFOP_POLARITY = RegisterMask(mask=0b1, offset=9)
        FIFO_POLARITY = RegisterMask(mask=0b1, offset=10)
        BCN_ACCEPT = RegisterMask(mask=0b1, offset=11)

    class SECCTRL0:
        SEC_MODE = RegisterMask(mask=0b11, offset=0)
        SEC_M = RegisterMask(mask=0b111, offset=2)
        SEC_RXKEYSEL = RegisterMask(mask=0b1, offset=5)
        SEC_TXKEYSEL = RegisterMask(mask=0b1, offset=6)
        SEC_SAKEYSEL = RegisterMask(mask=0b1, offset=7)
        SEC_CBC_HEAD = RegisterMask(mask=0b1, offset=8)
        RXFIFO_PROTECTION = RegisterMask(mask=0b1, offset=9)

    class FSCTRL:
        FREQ = RegisterMask(mask=0b1111111111, offset=0)
        LOCK_STATUS = RegisterMask(mask=0b1, offset=10)
        LOCK_LENGTH = RegisterMask(mask=0b1, offset=11)
        CAL_RUNNING = RegisterMask(mask=0b1, offset=12)
        CAL_DONE = RegisterMask(mask=0b1, offset=13)
        LOCK_THR = RegisterMask(mask=0b11, offset=14)
