"""
This module provides some constants used by WHAD to communicate with the APIMote.
"""
from enum import IntEnum

class APIMoteId(IntEnum):
    APIMOTE_ID_VENDOR    = 0x0403
    APIMOTE_ID_PRODUCT   = 0x6015

class APIMoteRegisters(IntEnum):
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
