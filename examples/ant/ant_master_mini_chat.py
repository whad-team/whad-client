from whad.ant import Master
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.stack.app.profiles import AntProfile
from whad.ant.channel import ChannelDirection
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys

import logging
logging.getLogger("whad.device.antstick").setLevel(logging.DEBUG)
#logging.basicConfig(level=logging.DEBUG)

from time import sleep


class MyProfile(AntProfile):


    DEVICE_NUMBER = 0xABCD
    DEVICE_TYPE = 1
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0
    DEFAULT_RF_CHANNEL = 50
    NETWORK_KEY = ANT_PLUS_NETWORK_KEY    

    def on_ack_burst(self, ack_burst):
        try:
            print(ack_burst.load.split(b"\n")[0].decode('ascii'))
        except:
            pass
        
        
def rx(pkt):
    pkt.show()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            mini_app = MyProfile()
            mini_app.start()

            # Create the master ANT connector
            master = Master(dev, profile=mini_app)
            #master.attach_callback(rx)

            print("Available channels: ", master.list_channels())
            print("Available networks: ", master.list_networks())
            channel = master.create_channel()
            print(channel)

            # Start the master and iterate over packets

            while channel.is_opened():
                message = input()
                mini_app.burst(message.encode('ascii') + b"\n")


            '''
            p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"MASTER")
            p.broadcast = 0
            print(sniffer.send(p))

            while True:
                input()
                p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"ABCDEF")#b"SLAAVE")
                p.broadcast = 1
                p.count = 0
                p.end = 0
                print(sniffer.send(p))

                p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"GHIJKL")#b"SLAAVE")
                p.broadcast = 1
                p.count = 1
                p.slot = 0
                p.end = 0
                print(sniffer.send(p))

                p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"MNOPQR")#b"SLAAVE")
                p.broadcast = 1
                p.count = 0
                p.slot = 0
                p.end = 1
                print(sniffer.send(p))
                input()
                p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"MASTER")#b"SLAAVE")
                p.broadcast = 1
                p.end = 1
                print(sniffer.send(p))
            '''


            
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
