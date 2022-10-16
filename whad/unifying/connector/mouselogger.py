from whad.unifying.connector import Sniffer
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter
from whad.scapy.layers.unifying import Logitech_Mouse_Payload

class Mouselogger(Sniffer):
    """
    Logitech Unifying Mouse logger interface for compatible WHAD device.
    """

    def __init__(self, device):
        super().__init__(device)

    def sniff(self):
        for packet in super().sniff():
            hid_data = None
            if Logitech_Mouse_Payload in packet:
                movement = packet.movement

                converter = LogitechUnifyingMouseMovementConverter()
                x, y = converter.get_coordinates_from_hid_data(movement)

                button_mask = packet.button_mask
                if button_mask == 1:
                    button = "left"
                elif button_mask == 2:
                    button = "right"
                elif button_mask == 4:
                    button = "center"
                else:
                    button = None

                yield ((x,y), button)
