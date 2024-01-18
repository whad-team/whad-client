from whad.phy import Phy, Endianness, OOKModulationScheme, PhysicalLayer, TXPower
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.phy.utils.helpers import get_physical_layers_by_domain
from whad.helpers import swap_bits
from time import time,sleep
import sys

def descrambling(packet):
    last_byte = 0
    out = b""
    for descrambling_in in packet:
        descrambling_in = swap_bits(descrambling_in)
        reg = (descrambling_in << 8) | last_byte
        reg2 = reg ^ (reg >> 3) ^ (reg >> 7)
        descrambling_out = 0xFF & reg2
        out += bytes([descrambling_out])
        last_byte = descrambling_in
    return out

if __name__ == '__main__':
    # Connect to target device and performs discovery
    try:
        def show_packet(pkt):
            print(repr(pkt.metadata))
            pkt.show()
            print(descrambling(bytes(pkt)))

        dev = WhadDevice.create("uart0")
        sniffer1 = Phy(dev)

        sniffer1.attach_callback(show_packet)

        bs = 2412000000 - 1000000 # small offset for FSK
        sniffer1.set_packet_size(200)
        sniffer1.set_datarate(1000000)
        sniffer1.set_gfsk(deviation=250000)
        sniffer1.set_endianness(Endianness.BIG)
        sniffer1.set_sync_word(bytes.fromhex("05ae4701"))

        sniffer1.set_frequency(bs)
        sniffer1.sniff_phy()
        while True:
            sniffer1.start()
            input()



    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
