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

        dev = WhadDevice.create("yardstickone")
        sniffer1 = Phy(dev)

        sniffer1.attach_callback(show_packet)

        print(sniffer1.get_supported_frequencies())
        '''
        sniffer1.set_frequency(2402000000)
        sniffer1.set_packet_size(250)
        sniffer1.set_datarate(2000000)
        sniffer1.set_gfsk(deviation=500000)
        sniffer1.set_endianness(Endianness.BIG)
        sniffer1.set_sync_word(bytes.fromhex("aa"))
        '''
        # https://fsec404.github.io/blog/Shanon-entropy/
        sniffer1.set_frequency(433920000)
        sniffer1.set_packet_size(250)
        sniffer1.set_datarate(10000) # 4800
        sniffer1.set_ask()
        #sniffer1.set_4fsk(1950)
        sniffer1.set_endianness(Endianness.BIG)
        sniffer1.set_sync_word(b"")

        #print(sniffer1.set_physical_layer(get_physical_layers_by_domain("esb")["ESB-2M"]))
        sniffer1.sniff_phy()
        sniffer1.start()
        while True:
            input()



    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
