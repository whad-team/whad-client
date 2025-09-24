import locale
import logging

from whad.common.analyzer import TrafficAnalyzer
from whad.common.converters.hid.mappings import HID_MAP
from whad.unifying.stack.constants import ClickType
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter
from whad.scapy.layers.unifying import Logitech_Mouse_Payload, Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload
from whad.unifying.hid import LogitechUnifyingKeystrokeConverter, HIDCodeNotFound, InvalidHIDData
from whad.unifying.crypto import LogitechUnifyingKeyDerivation

logger = logging.getLogger(__name__)

def get_default_kb_locale() -> str:
    """ Retrieve the current keyboard locale. """
    # Identify current locale based on system config.
    try:
        cur_locale = locale.getlocale()
        if cur_locale is not None:
            sys_locale, _ = cur_locale
            if sys_locale is not None and '_' in sys_locale:
                hid_locale = sys_locale.split('_')[1].lower()
                if hid_locale in HID_MAP:
                    return hid_locale

            # Display warning
            logger.warning("cannot detect system locale, default to 'fr'")

    except Exception:
        logger.warning("cannot detect system locale, default to 'fr'")
        pass

    # Return French locale if locale cannot be identified
    return "fr"

class UnifyingMouseMovement(TrafficAnalyzer):
        def reset(self):
            super().reset()
            self.x = None
            self.y = None
            self.wheel_x = None
            self.wheel_y = None
            self.button = None

        @property
        def output(self):
            return {
                "x" : self.x,
                "y" : self.y,
                "wheel_x" : self.wheel_x,
                "wheel_y" : self.wheel_y,
                "button" : self.button
            }

        def process_packet(self, packet):
            if Logitech_Mouse_Payload in packet:
                self.trigger()
                self.mark_packet(packet)
                converter = LogitechUnifyingMouseMovementConverter()
                self.x, self.y = converter.get_coordinates_from_hid_data(packet.movement)
                self.wheel_x, self.wheel_y = packet.wheel_x, packet.wheel_y
                self.button = ClickType(packet.button_mask)
                self.complete()


class UnifyingKeystroke(TrafficAnalyzer):
    """
    Logitech Unifying keystroke analyzer.

    This specific traffic analyzer parses captured Logitech Unifying
    PDUs, identifies unencrypted or decrypted keystrokes and extract
    the corresponding key based on the configured locale.
    """
    PARAMETERS = {
        "locale": get_default_kb_locale(),
    }

    def set_locale(self, locale: str):
        """
        Change locale to the specified `locale`.

        :param locale: New locale to use.
        :type  locale: str
        """
        self.set_param("locale", locale)
        self.__locale = locale

    @property
    def output(self):
        return {
            "key" :self.key
        }

    def process_packet(self, packet):
        hid_data = None
        if Logitech_Unencrypted_Keystroke_Payload in packet:
            self.trigger()
            self.mark_packet(packet)
            hid_data = packet.hid_data

        if Logitech_Encrypted_Keystroke_Payload in packet:
            self.trigger()
            self.mark_packet(packet)
            if hasattr(packet, "decrypted") and packet.decrypted is not None:
                hid_data = packet.decrypted.hid_data
            else:
                hid_data = packet.hid_data

        if hid_data is not None:
            if hid_data == b"\x00" * 7:
                self.key = None
            else:
                try:
                    key = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(hid_data, locale=self.__locale)
                    if key != self.key:
                        self.key = key
                        if len(self.key) > 1:
                            self.key = " [{}] ".format(self.key)
                        self.complete()
                except (HIDCodeNotFound, InvalidHIDData):
                    pass

    def reset(self):
        super().reset()
        self.__locale = self.get_param("locale")
        self.key = None


analyzers = {
    "pairing_cracking" : LogitechUnifyingKeyDerivation,
    "mouse" : UnifyingMouseMovement,
    "keystroke" : UnifyingKeystroke
}
