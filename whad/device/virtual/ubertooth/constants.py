"""
This module provides some constants used by WHAD to communicate with the Ubertooth One.
"""
from enum import IntEnum

class UbertoothInternalState(IntEnum):
    NONE = 0
    ADVERTISEMENT_SNIFFING = 1
    NEW_CONNECTION_SNIFFING = 2
    EXISTING_CONNECTION_SNIFFING = 3
    ACCESS_ADDRESS_SNIFFING = 4

# USB device Identifiers
class UbertoothId(IntEnum):
    UBERTOOTH_ID_VENDOR         = 0x1D50
    UBERTOOTH_ID_PRODUCT        = 0x6002

# Input / Output constants
class UbertoothTransfers(IntEnum):
    CTRL_IN                     = 0xC0
    CTRL_OUT                    = 0x40


# Modulations
class UbertoothModulations(IntEnum):
    MOD_BT_BASIC_RATE           = 0
    MOD_BT_LOW_ENERGY           = 1
    MOD_80211_FHSS              = 2

# Commands (opcode)
class UbertoothCommands(IntEnum):
    UBERTOOTH_PING              = 0
    UBERTOOTH_RX_SYMBOLS        = 1
    UBERTOOTH_TX_SYMBOLS        = 2
    UBERTOOTH_GET_USRLED        = 3
    UBERTOOTH_SET_USRLED        = 4
    UBERTOOTH_GET_RXLED         = 5
    UBERTOOTH_SET_RXLED         = 6
    UBERTOOTH_GET_TXLED         = 7
    UBERTOOTH_SET_TXLED         = 8
    UBERTOOTH_GET_1V8           = 9
    UBERTOOTH_SET_1V8           = 10
    UBERTOOTH_GET_CHANNEL       = 11
    UBERTOOTH_SET_CHANNEL       = 12
    UBERTOOTH_RESET             = 13
    UBERTOOTH_GET_SERIAL        = 14
    UBERTOOTH_GET_PARTNUM       = 15
    UBERTOOTH_GET_PAEN          = 16
    UBERTOOTH_SET_PAEN          = 17
    UBERTOOTH_GET_HGM           = 18
    UBERTOOTH_SET_HGM           = 19
    UBERTOOTH_TX_TEST           = 20
    UBERTOOTH_STOP              = 21
    UBERTOOTH_GET_MOD           = 22
    UBERTOOTH_SET_MOD           = 23
    UBERTOOTH_SET_ISP           = 24
    UBERTOOTH_FLASH             = 25
    BOOTLOADER_FLASH            = 26
    UBERTOOTH_SPECAN            = 27
    UBERTOOTH_GET_PALEVEL       = 28
    UBERTOOTH_SET_PALEVEL       = 29
    UBERTOOTH_REPEATER          = 30
    UBERTOOTH_RANGE_TEST        = 31
    UBERTOOTH_RANGE_CHECK       = 32
    UBERTOOTH_GET_REV_NUM       = 33
    UBERTOOTH_LED_SPECAN        = 34
    UBERTOOTH_GET_BOARD_ID      = 35
    UBERTOOTH_SET_SQUELCH       = 36
    UBERTOOTH_GET_SQUELCH       = 37
    UBERTOOTH_SET_BDADDR        = 38
    UBERTOOTH_START_HOPPING     = 39
    UBERTOOTH_SET_CLOCK         = 40
    UBERTOOTH_GET_CLOCK         = 41
    UBERTOOTH_BTLE_SNIFFING     = 42
    UBERTOOTH_GET_ACCESS_ADDRESS= 43
    UBERTOOTH_SET_ACCESS_ADDRESS= 44
    UBERTOOTH_DO_SOMETHING      = 45
    UBERTOOTH_DO_SOMETHING_REPLY= 46
    UBERTOOTH_GET_CRC_VERIFY    = 47
    UBERTOOTH_SET_CRC_VERIFY    = 48
    UBERTOOTH_POLL              = 49
    UBERTOOTH_BTLE_PROMISC      = 50
    UBERTOOTH_SET_AFHMAP        = 51
    UBERTOOTH_CLEAR_AFHMAP      = 52
    UBERTOOTH_READ_REGISTER     = 53
    UBERTOOTH_BTLE_SLAVE        = 54
    UBERTOOTH_GET_COMPILE_INFO  = 55
    UBERTOOTH_BTLE_SET_TARGET   = 56
    UBERTOOTH_BTLE_PHY          = 57
    UBERTOOTH_WRITE_REGISTER    = 58
    UBERTOOTH_JAM_MODE          = 59
    UBERTOOTH_EGO               = 60
    UBERTOOTH_AFH               = 61
    UBERTOOTH_HOP               = 62
    UBERTOOTH_TRIM_CLOCK        = 63
    UBERTOOTH_WRITE_REGISTERS   = 65
    UBERTOOTH_READ_ALL_REGISTERS= 66
    UBERTOOTH_RX_GENERIC        = 67
    UBERTOOTH_TX_GENERIC_PACKET = 68
    UBERTOOTH_FIX_CLOCK_DRIFT   = 69
    UBERTOOTH_CANCEL_FOLLOW     = 70
    UBERTOOTH_LE_SET_ADV_DATA   = 71

# Modes
class UbertoothModes(IntEnum):
    MODE_IDLE                   = 0
    MODE_RX_SYMBOLS             = 1
    MODE_TX_SYMBOLS             = 2
    MODE_TX_TEST                = 3
    MODE_SPECAN                 = 4
    MODE_RANGE_TEST             = 5
    MODE_REPEATER               = 6
    MODE_LED_SPECAN             = 7
    MODE_BT_FOLLOW              = 8
    MODE_BT_FOLLOW_LE           = 9
    MODE_BT_PROMISC_LE          = 10
    MODE_RESET                  = 11
    MODE_BT_SLAVE_LE            = 12


# Jamming modes
class UbertoothJammingModes(IntEnum):
    JAM_NONE                    = 0
    JAM_ONCE                    = 1
    JAM_CONTINUOUS              = 2
