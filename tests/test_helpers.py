from whad.helpers import bd_addr_to_bytes, asciiz
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

#TODO: message_filter test
#TODO: is_message_type test
