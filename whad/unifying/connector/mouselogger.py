from whad.unifying.connector import Sniffer
from whad.unifying.stack.constants import ClickType
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter
from whad.scapy.layers.unifying import Logitech_Mouse_Payload

class Mouselogger(Sniffer):
    """
    Logitech Unifying Mouse logger interface for compatible WHAD device.
    """

    def __init__(self, device):
        super().__init__(device)

    def stream(self):
        for packet in super().sniff():
            hid_data = None
            if Logitech_Mouse_Payload in packet:
                movement = packet.movement

                converter = LogitechUnifyingMouseMovementConverter()
                x, y = converter.get_coordinates_from_hid_data(movement)
                button = ClickType(packet.button_mask)

                yield ((x,y), (packet.wheel_x, packet.wheel_y), button)
