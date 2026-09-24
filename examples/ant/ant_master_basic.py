from whad.ant import Master
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.stack.app.profiles import AntProfile
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys

from time import sleep


class MyProfile(AntProfile):


    DEVICE_NUMBER = 0xABCD
    DEVICE_TYPE = 1
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0
    DEFAULT_RF_CHANNEL = 50
    NETWORK_KEY = ANT_PLUS_NETWORK_KEY    


    def on_broadcast(self, broadcast):
        print("Received broadcast: ")
        print(repr(broadcast))

    def on_ack_burst(self, ack_burst):
        print("Received ack / burst: ")
        print(repr(ack_burst))
        
def rx(pkt):
    pkt.show()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            profile = MyProfile()
            profile.start()

            # Create the master ANT connector
            master = Master(dev, profile=mini_app)
            #master.attach_callback(rx)

            print("Available channels: ", master.list_channels())
            print("Available networks: ", master.list_networks())
            channel = master.create_channel()
            print(channel)

            # Start the master and iterate over packets
            if channel is not None:
                while channel.is_opened():
                    # Send a broadcast packet 
                    profile.broadcast("Hello")
                    input()
                    # Send an acked packet 
                    acked = profile.ack("World")
                    input()
                    # Send a burst packet
                    profile.burst(b"A" * 30)


            
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
