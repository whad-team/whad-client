from whad.ant import ANT, Master
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.channel import ChannelDirection
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ant.stack.app.profiles.antplus.hrm import HeartRateMonitor
from whad.scapy.layers.ant import *
import sys

from time import sleep
from random import randint

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the  ANT master
            
            # Create the slave ANT connector
            profile = HeartRateMonitor()

            master = Master(dev)#, profile=hrmprofile)
            channel = master.create_channel(1234, 120, 1, channel_period=8070)
            channel.app.set_profile(profile)

            print("Chann: ", channel)
            profile.start()
            while True:
                profile.computed_heart_rate = randint(120,130)
                sleep(0.5)
            #p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"MASTER")
            #p.broadcast = 0
            #print(master.send(p))
            print(channel.app.broadcast(
                b"\xAA\xBB\xCC\xDD\xAA\xBB\xCC"
            ))

            input()
            while True:
                print(channel.app.burst(
                    b"\xAA\xBB\xCC\xDD\xAA\xBB\xCC\xDD\xCC\xDD\x11\x22\x33\x44"
                ))
                input()
            channel.close()
            

            #print(master.list_channels())
            #print(master.list_networks())
            
            input()
            '''
            print(sniffer.sniff_ant(
                device_type = 0, 
                device_number = 0,
                transmission_type = 0
            ))
            '''
            sniffer.set_network_key(0, ANT_PLUS_NETWORK_KEY)
            sniffer.set_device_number(0,1234)
            sniffer.set_device_type(0,120)
            sniffer.set_transmission_type(0,1)
            
            sniffer.assign_channel(0, 0, shared=False, direction=ChannelDirection.TX, unidirectional=False)
            sniffer.set_rf_channel(0,57)
            sniffer.set_channel_period(0,32768//8)
            sniffer.open_channel(0)


            # Start the sniffer and iterate over packets
            sniffer.start()
            p = ANT_Hdr(bytes.fromhex("a6c5e81e78010aFFFF")+ b"MASTER")
            p.broadcast = 0
            print(sniffer.send(p))
            #sniffer.send(pkt)
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



            
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
