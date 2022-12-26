from whad.common.converters.hid.mappings import HID_SPECIALS, HID_MAP
from whad.common.converters.hid.exceptions import HIDKeyNotFound, HIDLocaleNotFound, HIDCodeNotFound

class HIDConverter:
    '''
    This class provides a basic API to convert an HID code to an human friendly keystroke and vice versa.
    '''
    @classmethod
    def get_hid_code_from_key(self, key, alt=False, ctrl=False, shift=False, gui=False, locale="fr"):
        '''
        This function converts a key to a tuple composed of HID code and HID modifiers.

        :param key: main key to convert
        :param alt: alt key is pressed
        :param ctrl: ctrl key is pressed
        :param shift: shift key is pressed
        :param gui: gui key is pressed

        '''
        if locale not in HID_MAP:
            raise HIDLocaleNotFound(locale)

        if key in HID_MAP[locale]:
            hid_code, modifiers = HID_MAP[locale][key]
        elif key in HID_SPECIALS:
            hid_code, modifiers = HID_SPECIALS[key]
        else:
            raise HIDKeyNotFound(key, alt, ctrl, shift, gui)

        special_keys = {
            "ALT": alt,
            "CTRL" : ctrl,
            "SHIFT" : shift,
            "GUI" : gui
        }

        for special_key, pressed in special_keys.items():
            if pressed:
                modifiers += HID_SPECIALS[special_key][1]

        return (hid_code, modifiers)

    @classmethod
    def get_key_from_hid_code(self, hid_code = 0, modifiers = 0, locale="fr"):
        '''
        This function converts an HID code and HID modifiers to the corresponding keystroke.

        :param hid_code: HID code to convert
        :param hid_modifiers: HID modifiers to convert
        '''

        for key, value in HID_MAP[locale].items():
            if value == (hid_code, modifiers):
                return key

        for key, value in HID_SPECIALS.items():
            if value == (hid_code, modifiers):
                return key

        raise HIDCodeNotFound(hid_code, modifiers)
