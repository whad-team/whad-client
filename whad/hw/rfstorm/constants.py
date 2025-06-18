"""
This module provides some constants used by WHAD to communicate with the RFStorm firmware.
"""
from enum import IntEnum

# RFStorm Internal states
class RFStormInternalStates(IntEnum):
    """Internal state constants.
    """
    NONE                            = 0
    SNIFFING                        = 1
    PROMISCUOUS_SNIFFING            = 2
    PROMISCUOUS_GENERIC_SNIFFING    = 3
    TRANSMITTING                    = 4
    GENERIC_TRANSMITTING            = 5

# USB identifiers
class RFStormId(IntEnum):
    """RFStorm USB ID contstants
    """
    RFSTORM_ID_VENDOR    = 0x1915
    RFSTORM_ID_PRODUCT   = 0x0102

# USB Endpoints
class RFStormEndPoints(IntEnum):
    """RFStorm USB endpoints numbers
    """
    RFSTORM_COMMAND_ENDPOINT     = 0x01
    RFSTORM_RESPONSE_ENDPOINT    = 0x81

# USB Commands
class RFStormCommands(IntEnum):
    """RFStorm commands
    """
    RFSTORM_CMD_TRANSMIT = 0x04
    RFSTORM_CMD_SNIFF = 0x05
    RFSTORM_CMD_PROMISCUOUS = 0x06
    RFSTORM_CMD_TONE    = 0x07
    RFSTORM_CMD_TRANSMIT_ACK = 0x08
    RFSTORM_CMD_SET_CHANNEL = 0x09
    RFSTORM_CMD_GET_CHANNEL = 0x0a
    RFSTORM_CMD_ENABLE_LNA = 0x0b
    RFSTORM_CMD_TRANSMIT_GENERIC = 0x0C
    RFSTORM_CMD_PROMISCUOUS_GENERIC = 0x0D
    RFSTORM_CMD_RECV = 0x12

# RF Datarates
class RFStormDataRate(IntEnum):
    """RFStorm datarate constants
    """
    RF_250KBPS = 0
    RF_1MBPS = 1
    RF_2MBPS = 2

# Supported domains
class RFStormDomains(IntEnum):
    """RFStorm supported domains
    """
    RFSTORM_RAW_ESB = 0
    RFSTORM_UNIFYING = 1
    RFSTORM_PHY = 2
