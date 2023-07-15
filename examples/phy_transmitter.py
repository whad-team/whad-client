from whad.phy import Phy, Endianness
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.phy.utils.helpers import get_physical_layers_by_domain
from time import time,sleep
import sys

if __name__ == '__main__':
    # Connect to target device and performs discovery
    try:
        def show_packet(pkt):
            print(repr(pkt.metadata))
            pkt.show()

        dev = WhadDevice.create("uart0")
        sniffer1 = Phy(dev)

        sniffer1.attach_callback(show_packet)

        print(sniffer1.get_supported_frequencies())

        sniffer1.set_frequency(2402000000)
        sniffer1.set_packet_size(30)
        sniffer1.set_datarate(2000000)
        sniffer1.set_gfsk(deviation=500000)
        sniffer1.set_endianness(Endianness.LITTLE)
        sniffer1.set_sync_word(bytes.fromhex("aabbccdd"))
        sniffer1.start()


        while True:
            sniffer1.send(bytes.fromhex("01020304050607080910"))
            input()



    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
