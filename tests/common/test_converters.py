"""Common converters unit tests"""

import pytest

from whad.common.converters.hid import HIDConverter


def test_hidconverter_get_hid_code_from_key():
    code_fr = HIDConverter.get_hid_code_from_key("a")
    assert code_fr == (0x14, 0x00)
    code_us = HIDConverter.get_hid_code_from_key(
        "a", locale="us", shift=True, ctrl=True
    )
    assert code_us == (0x04, 0x03)


def test_hidconverter_get_key_from_hid_code():
    key_fr = HIDConverter.get_key_from_hid_code(0x14, 0x00)
    assert key_fr == "a"
    key_us = HIDConverter.get_key_from_hid_code(0x04, 0x03, locale="us")
    assert key_us == "CTRL+A"
