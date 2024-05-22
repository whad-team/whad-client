"""
Helpers for 802.15.4 MAC operations.
"""
import struct


def is_short_address(address):
    """
    Indicates if a given address uses the short address format (16-bit) or the extended one.
    """
    try:
        _ = struct.pack("H", address)
        return True
    except struct.error:
        return False
