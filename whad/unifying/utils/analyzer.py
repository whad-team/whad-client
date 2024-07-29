from whad.common.analyzer import TrafficAnalyzer
from whad.unifying.stack.constants import ClickType
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter
from whad.scapy.layers.unifying import Logitech_Mouse_Payload, Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload
from whad.unifying.hid import LogitechUnifyingKeystrokeConverter, HIDCodeNotFound, InvalidHIDData
from whad.unifying.crypto import LogitechUnifyingKeyDerivation

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
            self.__locale = "fr"
            self.key = None


analyzers = {
    "pairing_cracking" : LogitechUnifyingKeyDerivation,
    "mouse" : UnifyingMouseMovement,
    "keystroke" : UnifyingKeystroke
}
