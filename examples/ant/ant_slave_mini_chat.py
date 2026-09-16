from whad.ant import Slave
from whad.ant.stack.app.profiles import AntProfile
from whad.scapy.layers.ant import ANT_Hdr
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


    DEVICE_NUMBER = 1234
    DEVICE_TYPE = 1
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0
    DEFAULT_RF_CHANNEL = 50
    NETWORK_KEY = ANT_PLUS_NETWORK_KEY    

    count = 0

    def on_ack_burst(self, ack_burst):
        try:
            print(ack_burst.load.split(b"\n")[0].decode('ascii'))
        except:
            pass

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            mini_app = MyProfile()
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the slave ANT connector
            slave = Slave(dev, profile=mini_app)
            mini_app.start()
            #slave.start()
            channel = slave.search_channel()
            #slave.attach_callback(rx)
            print("Available channels: ", slave.list_channels())
            print("Available networks: ", slave.list_networks())
            last_count = None
            while channel.is_opened():
                message = input()
                mini_app.burst(message.encode('ascii')+ b"\n")
            '''
            while channel.is_opened():
                print(mini_app.burst(b"Coucou"*10))
            '''
            '''
            channel = slave.search_channel(
                7912,
                120,
                1,
                rf_channel = 57,
                network_key = ANT_PLUS_NETWORK_KEY,
            )
            '''
            '''
            slave.set_network_key(0, ANT_PLUS_NETWORK_KEY)
            slave.set_device_number(0,7912)
            slave.set_device_type(0,120)
            slave.set_transmission_type(0,1)
            
            slave.assign_channel(0, 0, shared=False, direction=ChannelDirection.TX, unidirectional=False)
            slave.set_rf_channel(0,57)
            slave.set_channel_period(0,32768//4)
            slave.open_channel(0)
            '''
            # Start the slave and iterate over packets
            '''
            for i in range(200):
                channel.app.ack(b"Slave #"+bytes([i]))
                sleep(1)
            '''
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
