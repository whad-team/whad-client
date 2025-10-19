from whad.ant import ANT
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.channel import ChannelDirection
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys

from time import sleep

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the sniffer ANT connector
            sniffer = ANT(dev)
            #print(sniffer.list_channels())
            #print(sniffer.list_networks())
            '''
            print(sniffer.sniff_ant(
                device_type = 0, 
                device_number = 0,
                transmission_type = 0
            ))
            '''
            sniffer.set_network_key(0, ANT_PLUS_NETWORK_KEY)
            sniffer.set_device_number(0,7912)
            sniffer.set_device_type(0,120)
            sniffer.set_transmission_type(0,1)
            sniffer.set_channel_period(0,32768)
            sniffer.assign_channel(0, 0, shared=False, direction=ChannelDirection.RX, unidirectional=False)
            sniffer.set_rf_channel(0,57)
            sniffer.open_channel(0)

            sniffer.start()

            # Start the sniffer and iterate over packets

            while True:
                input()
                p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"ABCDEF")#b"SLAAVE")
                p.broadcast = 1
                p.count = 0
                p.slot = 0
                p.end = 0
                print(sniffer.send(p))

                p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"GHIJKL")#b"SLAAVE")
                p.broadcast = 1
                p.count = 1
                p.slot = 0
                p.end = 1
                print(sniffer.send(p))
                input()

                p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"SLAAVE")#b"SLAAVE")
                p.broadcast = 1
                p.slot = 0
                p.end = 1
                print(sniffer.send(p))

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
