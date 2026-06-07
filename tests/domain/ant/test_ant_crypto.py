"""ANT Network Keys and Synchronization Word Unit Tests

This script provides unit tests to validate the network key verification
algorithm and the synchronization word generation used for ANT sniffing.
"""
import pytest
from whad.ant.crypto import is_valid_network_key, generate_sync_from_network_key

ANT_PLUS_NETWORK_KEY = bytes.fromhex("45C372BDFB21A5B9")
ANT_FS_NETWORK_KEY = bytes.fromhex("C1635EF5B923A4A8")


def test_is_valid_network_key_ant_plus():
    """Checks that ANT_PLUS_NETWORK_KEY (ANT+ official key) is validated."""
    assert is_valid_network_key(ANT_PLUS_NETWORK_KEY) is True

def test_is_valid_network_key_ant_fs():
    """Checks that ANT_FS_NETWORK_KEY (ANT-FS official key) is validated."""
    assert is_valid_network_key(ANT_FS_NETWORK_KEY) is True

def test_is_valid_network_key_invalid():
    """Checks if an arbitrary incorrect key is not validated."""
    invalid_key = bytes.fromhex("0011223344556677")
    assert is_valid_network_key(invalid_key) is False

def test_generate_sync_from_network_key_ant_plus():
    """Checks if ANT+ key generates the expected sync word (0xA6C5)."""
    sync_word = generate_sync_from_network_key(ANT_PLUS_NETWORK_KEY)
    
    assert sync_word == 0xc5a6
    
def test_generate_sync_from_network_key_ant_fs():
    """Checks if ANT+ key generates the expected sync word (0x3BA3)."""
    sync_word = generate_sync_from_network_key(ANT_FS_NETWORK_KEY)
    
    assert sync_word == 0xa33b