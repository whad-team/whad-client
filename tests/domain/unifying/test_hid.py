"""
Logitech Unifying HID unit tests.
"""
import pytest

from whad.common.converters.hid.exceptions import HIDCodeNotFound
from whad.scapy.layers.esb import ESB_Hdr
from whad.scapy.layers.unifying import Logitech_Unencrypted_Keystroke_Payload, Logitech_Unifying_Hdr
from whad.unifying.utils.analyzer import UnifyingKeystroke
from whad.unifying.hid import LogitechUnifyingKeystrokeConverter
from whad.unifying.hid.exceptions import InvalidHIDData

@pytest.mark.parametrize("hid, expected", [
    ((4, 2), 'A'),
    ((49, 0), '\\'),
    ((41, 0), 'ESCAPE'),
    ((36, 2), '&'),
])
def test_unencryted_payload_decoding(hid, expected):
    """Check unencrypted Logitech Unifying keystroke payload decoding."""
    # Build the corresponding Logitech Unifying packet
    code, mod = hid
    hid_data = bytes([mod, code, 0, 0, 0, 0, 0])

    # Parse keystroke
    key = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(hid_data, locale="us")
    assert key == expected


def test_bad_unencrypted_payload_decoding():
    """Check bad Logitech Unifying keystroke payload processing."""
    bad_payload = b"\x00"
    with pytest.raises(InvalidHIDData):
        _ = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(bad_payload)

def test_unknown_hid_keycode():
    """Check unknown keycodes raise HIDCodeNotFound exception."""
    unknown_key_payload = b"\x00\xff\x00\x00\x00\x00\x00"
    with pytest.raises(HIDCodeNotFound):
        _ = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(unknown_key_payload)

def test_unifying_unenc_keystroke_processing():
    """Check a valid Logitech Unifying packet is correctly converted into a keycode."""
    # Build a 'Q' keystroke (modifiers=SHIFT, key code Q for FR keyboard)
    keypress = ESB_Hdr()/Logitech_Unifying_Hdr()/Logitech_Unencrypted_Keystroke_Payload(
        hid_data=b"\x02\x04\x00\x00\x00\x00\x00"
    )
    keyrelease = ESB_Hdr()/Logitech_Unifying_Hdr()/Logitech_Unencrypted_Keystroke_Payload(
        hid_data=b"\x00\x00\x00\x00\x00\x00\x00"
    )

    analyzer = UnifyingKeystroke()
    analyzer.set_locale("fr")
    analyzer.process_packet(keypress)
    analyzer.process_packet(keyrelease)
    assert analyzer.triggered
    assert analyzer.completed
    assert analyzer.output["key"] == 'Q'

