from whad.ble import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from scapy.layers.bluetooth import EIR_Hdr
from scapy.layers.bluetooth4LE import BTLE_ADV
from whad.scapy.layers.bt_mesh import *
import sys

def bt_mesh_filter(packet, ignore_regular_adv):
    if BTLE_ADV in packet:
        if hasattr(packet, "data"):
            if (EIR_Hdr in packet and
                (any([i.type in (0x29, 0x2a, 0x2b) for i in packet.data]) or
                any(h in [[0x1827], [0x1828]] for h in [i.svc_uuids for i in packet.data if hasattr(i,"svc_uuids") and not ignore_regular_adv]))
            ):
                return True


        return False

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:

            def show_packet(pkt):
                pkt.show()

            ignore_regular_adv = True

            dev = WhadDevice.create(interface)
            sniffer = Sniffer(dev)
            sniffer.channel = 37
            sniffer.configure(advertisements=True, connection=False)
            sniffer.start()
            for i in sniffer.sniff():
                if bt_mesh_filter(i, ignore_regular_adv):
                    i.show()
                    print(bytes(i).hex())



        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
