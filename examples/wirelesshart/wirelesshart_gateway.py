from whad.device import WhadDevice
from whad.wirelesshart.connector import Sniffer
from whad.common.monitors import WiresharkMonitor
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.wirelesshart import Dot15d4
from scapy.compat import raw
from random import randint
import sys
from time import sleep

ts = None
asn = None
def get_info(pkt):
    global ts, asn
    if hasattr(pkt, "asn"):
        ts = pkt.metadata.timestamp
        asn = pkt.asn

    print("Channel:", pkt.metadata.channel)
    print("ASN:", ts)
    #if (pkt.metadata.channel != 25): 
    print(repr(pkt))
    print()
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            #monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)
            # Instantiate a sniffer
            sniffer = Sniffer(dev)
            sniffer.channel = 23
            # Attach & start the wireshark monitor
            #monitor.attach(sniffer)
            #monitor.start()

            sniffer.start()
            sniffer.attach_callback(get_info)

            #pkt = Dot15d4(bytes.fromhex("41c836cd04010068d33200000d17001740f936040000f98000170d000032d368010000000a69ddbdc9c7c1822caf8d36fdd633d20ac188eea650acac"))
            #pkt.show()
            input()
            '''if ts is not None:
                # Synchronize the sniffer
                print("SYNC !!!!!!!!!!!!")
                sniffer.synchronize(ts, asn)'''
            while True:
                sleep(1)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
