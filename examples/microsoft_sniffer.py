from whad.esb import ESB, Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr
from scapy.compat import raw
import sys, time
from whad.scapy.layers.microsoft import Microsoft_Hdr, bind

bind()

def show(pkt):

    if hasattr(pkt, "metadata"):
        print(pkt.metadata)
    pkt.show()
    #print(repr(pkt))

    #pkt.show()


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            connector = Sniffer(dev)
            #connector.address = #"c0:b0:cd:c0:66"#"ee:19:9e:25:10" # mouse
            connector.address = "a9:e4:85:84:6d" # keyboard
            connector.channel = 46
            connector.start()
            for i in connector.sniff():
                show(i)

            while True:
                    #èpkt = ESB_Hdr(address="c0:b0:cd:c0:66", pid=1)/ESB_Payload_Hdr()/Microsoft_Hdr(device_class="mouse", packet_type=0x38, model_id=0x18, unknown=1, bytes.fromhex("08901801ad01188b400001000000000000000001"))
                    print(raw(pkt))
                    connector.send(pkt)
                    connector.channel = None
                    input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
