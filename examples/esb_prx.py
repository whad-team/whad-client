from whad.esb import ESB, PRX, PTX
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr
from scapy.compat import raw
import sys

def show(pkt):
    if hasattr(pkt, "metadata"):
        print(pkt.metadata, bytes(pkt).hex(), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            dev = WhadDevice.create(interface)
            connector = PRX(dev)
            connector.address = "ca:e9:06:ec:a4"
            connector.channel = 8
            connector.start()
            for pkt in connector.stream():
                pkt.show()
                if ((bytes(pkt)[3] % 5) == 0):
                    connector.prepare_acknowledgment(b"PRX")

            connector.stop()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
