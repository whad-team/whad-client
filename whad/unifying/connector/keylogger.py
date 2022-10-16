from whad.unifying.connector import Sniffer
from whad.unifying.hid import LogitechUnifyingKeystrokeConverter
from whad.scapy.layers.unifying import Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload

class Keylogger(Sniffer):
    """
    Logitech Unifying Keylogger interface for compatible WHAD device.
    """

    def __init__(self, device):
        super().__init__(device)
        self.__locale = "fr"

    @property
    def locale(self):
        return self.__locale

    @locale.setter
    def locale(self, locale):
        self.__locale = locale

    def sniff(self):
        for packet in super().sniff():
            hid_data = None
            if Logitech_Unencrypted_Keystroke_Payload in packet:
                hid_data = packet.hid_data

            if Logitech_Encrypted_Keystroke_Payload in packet:
                if hasattr(packet, "decrypted") and packet.decrypted is not None:
                    hid_data = packet.decrypted.hid_data

            if hid_data is not None:
                converter = LogitechUnifyingKeystrokeConverter(self.__locale)
                key = converter.get_key_from_hid_data(hid_data)
                if len(key) > 1:
                    key = " [{}] ".format(key)
                yield key
