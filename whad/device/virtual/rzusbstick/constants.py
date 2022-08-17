"""
This module provides some constants used by WHAD to communicate with the RZUSBStick.
"""
from enum import IntEnum

# USB device reset
class RZUSBStickOSPrimitive(IntEnum):
    USBDEVFS_RESET = ord('U') << (4 * 2) | 20

# RZUSBStick Internal states
class RZUSBStickInternalStates(IntEnum):
    NONE                    = 0
    SNIFFING                = 1
    TRANSMITTING            = 2

# USB identifiers
class RZUSBStickId(IntEnum):
    RZUSBSTICK_ID_VENDOR    = 0x03eb
    RZUSBSTICK_ID_PRODUCT   = 0x210a

# USB Endpoints
class RZUSBStickEndPoints(IntEnum):
    RZ_COMMAND_ENDPOINT     = 0x02
    RZ_RESPONSE_ENDPOINT    = 0x84
    RZ_PACKET_ENDPOINT 	    = 0x81

# USB Commands
class RZUSBStickCommands(IntEnum):
    RZ_SET_MODE             = 0x07
    RZ_SET_CHANNEL          = 0x08
    RZ_OPEN_STREAM          = 0x09
    RZ_CLOSE_STREAM	        = 0x0A
    RZ_INJECT_FRAME         = 0x0D
    RZ_JAMMER_ON            = 0x0E
    RZ_JAMMER_OFF           = 0x0F

# USB Responses
class RZUSBStickResponses(IntEnum):
    RZ_RESP_SUCCESS         = 0x80
    RZ_AIRCAPTURE_DATA      = 0x50

# RZ Modes
class RZUSBStickModes(IntEnum):
    RZ_MODE_AIRCAPTURE      = 0x00
    RZ_MODE_NONE            = 0x04
