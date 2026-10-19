from whad.ant import Master
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys

from time import sleep

        
def rx(pkt):
    pkt.show()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the master ANT connector
            master = Master(dev)
            
            master.start()
            channel = master.create_channel(
                device_number = 0xABCD, 
                device_type = 1, 
                transmission_type = 1,
                channel_period = 8070,
                rf_channel = 57, 
                network_key = ANT_PLUS_NETWORK_KEY,
                unidirectional = False, 
                shared = False, 
                background = False
            )
            # Start the master and iterate over packets
            if channel is not None:
                channel.on_broadcast = lambda p:p.show()
                channel.on_ack_burst = lambda p:p.show()

                while channel.is_opened():
                    # Send a broadcast packet 
                    channel.broadcast(b"Hello")
                    input()
                    # Send an acked packet 
                    acked = channel.ack(b"World")
                    input()
                    # Send a burst packet
                    channel.burst(b"A" * 30)


            
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
