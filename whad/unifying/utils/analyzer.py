"""
This module provides two classes to analyze Logitech Unifying communications:
- :class:`whad.unifying.utils.analyzer.UnifyingMouseMovement` that recovers mouse movements from wireless traffic;
- :class:`whad.unifying.utils.analyzer.UnifyingKeystroke` that recovers keystrokes from plaintext and decrypted wireless traffic.
"""
import locale
import logging

from scapy.packet import Packet

from whad.common.analyzer import TrafficAnalyzer, InvalidParameter
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

    def __init__(self, **kwargs):
        """Initialize Unifying keystroke analyzer."""
        super().__init__(**kwargs)

        # save pending keystrokes and recovered keystrokes
        self.__pending_keys = None
        self.__keys = None

    def set_locale(self, locale: str):
        """
        Change locale to the specified `locale`.

        :param locale: New locale to use.
        :type  locale: str
        :raise: InvalidParameter
        """
        # First, make sure the locale is valid
        if locale in HID_MAP:
            self.set_param("locale", locale)
            self.__locale = locale
        else:
            raise InvalidParameter("locale", locale)

    @property
    def output(self):
        return {
            "key" :self.__keys
        }

    def process_packet(self, packet: Packet):
        """Process an incoming packet.

        :param packet: Incoming packet to process.
        :type  packet: scapy.packet.Packet
        """
        # Extract HID data from packet, if any
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

        # Process found HID data
        if hid_data is not None:
            # Empty HID report ?
            if hid_data == b"\x00" * 7:
                # Got an empty HID report, send pending keystroke if any.
                if self.__pending_keys is not None:
                    self.__keys = self.__pending_keys
                    self.__pending_keys = None
                    self.complete()
            else:
                try:
                    # Non-empty report, recover pressed key based on HID scan code and locale
                    key = LogitechUnifyingKeystrokeConverter.get_key_from_hid_data(hid_data, locale=self.__locale)
                    if len(key) > 1:
                        key = " [{}] ".format(key)

                    # If pending keystroke and a detected keystroke are different, we must report
                    # the pending keystroke as we may have missed an event (key release).
                    if self.__pending_keys is not None and key != self.__pending_keys:
                        self.__keys = self.__pending_keys
                        self.__pending_keys = None
                        self.complete()

                    # Keep pending keystroke in memory.
                    self.__pending_keys = key
                except (HIDCodeNotFound, InvalidHIDData):
                    pass

    def reset(self):
        """
        Reset this analyzer.

        :raise: InvalidParameter
        """
        super().reset()

        # Reload locale from paramater and make sure it is valid
        locale = self.get_param("locale")
        if locale in HID_MAP:
            self.__locale = locale
        else:
            raise InvalidParameter("locale", locale)

        # Reset current keypress
        self.__keys = None


analyzers = {
    "pairing_cracking" : LogitechUnifyingKeyDerivation,
    "mouse" : UnifyingMouseMovement,
    "keystroke" : UnifyingKeystroke
}

