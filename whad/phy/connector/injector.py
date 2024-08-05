from queue import Queue

from whad.exceptions import WhadDeviceDisconnected
from whad.phy.connector import Phy
from whad.phy import Endianness
from whad.phy.exceptions import NoModulation
from whad.exceptions import UnsupportedCapability

# TODO: every sniffer is broken (sniff() method does not catch packets, we
#       have to catch them in on_packet() and put them in a queue)

class Injector(Phy):
    """
    Phy Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device):
        Phy.__init__(self, device)

        # Check if device can perform injection
        if not self.can_send():
            raise UnsupportedCapability("Inject")

        self.configure()

    def configure(self):
        self.set_frequency(433920000)
        self.set_packet_size(250)

        self.set_datarate(4000)
        self.set_ask()
        self.set_endianness(
            Endianness.BIG
        )

        self.set_sync_word(b"")
        self.start()

    def inject(self, packet):
        super().send(packet)
