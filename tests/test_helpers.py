from whad.helpers import bd_addr_to_bytes, asciiz, is_message_type, swap_bits
from whad.protocol.whad_pb2 import Message
from tests.sample_messages import DISCOVERY_SAMPLE_MESSAGES,GENERIC_SAMPLE_MESSAGES, BLE_SAMPLE_MESSAGES
from google.protobuf.text_format import Parse
import pytest

@pytest.mark.parametrize("test_input, expected", [
    ("11:22:33:44:55:66", b"\x66\x55\x44\x33\x22\x11"),
    ("aA:Bb:cC:dd:EE:fF", b"\xff\xee\xdd\xcc\xbb\xaa"),
    ("ff:ff:ff:FF:FF:FF", b"\xff\xff\xff\xff\xff\xff"),
    ("ff  :  ff : ff  :F F    :F  F:  F F", None),
    ("test", None),
    ("", None),
    (42, None)

])
def test_bd_addr_to_bytes(test_input, expected):
    assert bd_addr_to_bytes(test_input) == expected

@pytest.mark.parametrize("test_input, expected", [
    (b"\x41\x42\x43\x44", "ABCD"),
    (b"\x31\x62\x33\x64\x35\x66", "1b3d5f"),
    (b"", ""),
    (None, None),
    (42, None)
])
def test_asciiz(test_input, expected):
    assert asciiz(test_input) ==  expected

@pytest.mark.parametrize("test_input, expected",
    [((msg_type, "discovery", msg),True) for msg_type, msg in DISCOVERY_SAMPLE_MESSAGES.items()] +
    [((msg_type, "ble", msg),False) for msg_type, msg in DISCOVERY_SAMPLE_MESSAGES.items()] +
    [(("wrong_type", "discovery", msg),False) for msg_type, msg in DISCOVERY_SAMPLE_MESSAGES.items()] +
    [(("wrong_type", "ble", msg),False) for msg_type, msg in DISCOVERY_SAMPLE_MESSAGES.items()] +

    [((msg_type, "generic", msg),True) for msg_type, msg in GENERIC_SAMPLE_MESSAGES.items()] +
    [((msg_type, "discovery", msg),False) for msg_type, msg in GENERIC_SAMPLE_MESSAGES.items()] +
    [(("wrong_type", "generic", msg),False) for msg_type, msg in GENERIC_SAMPLE_MESSAGES.items()] +
    [(("wrong_type", "discovery", msg),False) for msg_type, msg in GENERIC_SAMPLE_MESSAGES.items()] +

    [((msg_type, "ble", msg),True) for msg_type, msg in BLE_SAMPLE_MESSAGES.items()] +
    [((msg_type, "generic", msg),False) for msg_type, msg in BLE_SAMPLE_MESSAGES.items()] +
    [(("wrong_type", "ble", msg),False) for msg_type, msg in BLE_SAMPLE_MESSAGES.items()] +
    [(("wrong_type", "generic", msg),False) for msg_type, msg in BLE_SAMPLE_MESSAGES.items()]

    )

def test_is_message_type(test_input, expected):
    msg_type, category, message = test_input
    msg = Message()
    Parse(message, msg)
    assert is_message_type(msg, category, msg_type) ==  expected

@pytest.mark.parametrize("test_input, expected", [
    (0x48, 0x12),
    (b"\xF0\xF0\xF0\xF0", b"\x0F\x0F\x0F\x0F"),
    (b"\x12\x34", b"\x48\x2c"),
    ("toto", None)
    ])
def test_swap_bits(test_input, expected):
    assert swap_bits(test_input) == expected

#TODO: message_filter test
#TODO: is_message_msg_type test
