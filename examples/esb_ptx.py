from whad.esb import ESB, PRX, PTX
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr
from scapy.compat import raw
import sys

def show(pkt):
    if hasattr(pkt, "metadata"):
        print(pkt.metadata)
    print(bytes(pkt).hex(), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)
            connector = PTX(dev)
            connector.address = "ca:e9:06:ec:a4"
            connector.channel = 5
            #connector.synchronize()
            connector.attach_callback(show)
            connector.start()

            for i in range(100):
                input()
                ack = connector.send_data(b"PTX"+bytes([i]), waiting_ack=True)
                if ack is not None:
                    ack.show()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
