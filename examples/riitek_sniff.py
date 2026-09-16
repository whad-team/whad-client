from whad.phy.connector import Sniffer, Endianness
from whad.phy.sniffing import SnifferConfiguration, FSKConfiguration
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys
from time import sleep


def receive_callback(pkt):
    #print(repr(pkt))
    if b"\x00\x00\x00" in bytes(pkt):
        print("\t", bytes(pkt).hex())
        print(hex(bytes(pkt)[9]))

if __name__ == '__main__':
    if len(sys.argv) >= 3:
        # Retrieve target interface
        interface = sys.argv[1]
        channel = int(sys.argv[2])
        # Create the WHAD Device
        dev = WhadDevice.create(interface)
        sniffer = Sniffer(dev)

        sniffer.attach_callback(receive_callback)
        channel = 42
        try:
            while True:
                    print(channel)
                    channel = channel + 1 if channel < 80 else 0
                    config = SnifferConfiguration()
                    config.frequency = 2400000000 + channel * 1000000
                    config.datarate = 1000000
                    config.endianness = Endianness.BIG
                    config.packet_size = 26
                    config.gfsk = True
                    config.fsk_configuration = FSKConfiguration()
                    config.fsk_configuration.deviation = 250000
                    config.sync_word = bytes.fromhex("aa02035c")#[::-1]
                    sniffer.configuration = config
                    sniffer.start()
                    sleep(0.2)
                    #for i in sniffer.sniff():
                    #    print(repr(i))

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
