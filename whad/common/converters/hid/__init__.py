"""This module provides the `HIDConverter` class, an helper class to generate human-readable
keypress information from HID code/modifiers and a given locale, and to convert a specific
keycode into the corresponding HID code/modifiers for a given locale.
"""
from re import I
from whad.common.converters.hid.exceptions import (
    HIDCodeNotFound,
    HIDKeyNotFound,
    HIDLocaleNotFound,
)
from whad.common.converters.hid.mappings import HID_MAP, HID_SPECIALS


class HIDConverter:
    """
    This class provides a basic API to convert an HID code to an human friendly
    keystroke and vice versa.
    """

    @staticmethod
    def get_hid_code_from_key(
        key: str, alt=False, ctrl=False, shift=False, gui=False, locale: str = "fr"
    ) -> tuple[int, int]:
        """
        This function converts a key to a tuple composed of HID code and HID modifiers.

        :param key: main key to convert
        :param alt: alt key is pressed
        :param ctrl: ctrl key is pressed
        :param shift: shift key is pressed
        :param gui: gui key is pressed
        :param locale: Keyboard keymap to consider
        """
        if locale not in HID_MAP:
            raise HIDLocaleNotFound(locale)

        matching_codes = [m for m, k in HID_MAP[locale].items() if k == key]
        if not matching_codes:
            # Key was not found, try special keys
            matching_codes = [m for m, k in HID_SPECIALS.items() if k == key]
        if not matching_codes:
            # Key was not found in locale keymap and in special keys
            raise HIDKeyNotFound(key, alt, ctrl, shift, gui)
        # Consider first keycode found as keys are ordered from most common to rarest
        hid_code, modifiers = matching_codes[0]

        # If caller specified some modifiers, apply them
        modifier_keys = {"ALT": alt, "CTRL": ctrl, "SHIFT": shift, "GUI": gui}
        for keycode, pressed in modifier_keys.items():
            if pressed:
                mapping = [m for m, k in HID_SPECIALS.items() if k == keycode][0]
                modifiers += mapping[1]

        return (hid_code, modifiers)

    @staticmethod
    def get_key_from_hid_code(
        hid_code: int = 0, modifiers: int = 0, locale: str = "fr"
    ) -> str:
        """
        This function converts an HID code and HID modifiers to the corresponding keystroke.

        :param hid_code: HID code to convert
        :param modifiers: HID modifiers to convert
        :param locale: Keyboard keymap to consider
        """
        # Make sure the specified locale is valid
        if locale not in HID_MAP:
            raise HIDLocaleNotFound(locale)

        # Handle Ctrl, Alt and Gui keys
        if modifiers & 1:
            modifiers -= 1
            return "CTRL+" + HIDConverter.get_key_from_hid_code(hid_code, modifiers, locale)
        if modifiers & 4:
            modifiers -= 4
            return "LALT+" + HIDConverter.get_key_from_hid_code(hid_code, modifiers, locale)
        if modifiers & 8:
            modifiers -= 8
            return "GUI+" + HIDConverter.get_key_from_hid_code(hid_code, modifiers, locale)
        if modifiers & 16:
            modifiers -= 16
            return "CTRL+" + HIDConverter.get_key_from_hid_code(hid_code, modifiers, locale)
        if modifiers & 64:
            modifiers -= 64
            return "RALT+" + HIDConverter.get_key_from_hid_code(hid_code, modifiers, locale)
        if modifiers & 128:
            modifiers -= 128
            return "RGUI+" + HIDConverter.get_key_from_hid_code(hid_code, modifiers, locale)

        # Map Right-SHIFT modifier to Left-SHIFT modifier
        if modifiers & 32:
            modifiers -= 32
            if not modifiers & 2:
                modifiers += 2

        if (hid_code, modifiers) in HID_MAP[locale]:
            return HID_MAP[locale][(hid_code, modifiers)]
        if (hid_code, modifiers) in HID_SPECIALS:
            return HID_SPECIALS[(hid_code, modifiers)]
        raise HIDCodeNotFound(hid_code, modifiers)
