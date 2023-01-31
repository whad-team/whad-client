from whad.unifying import Keylogger, Mouselogger
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys,time

def show(pkt):
    print(repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            connector = Mouselogger(dev)
            connector.address = "ca:e9:06:ec:a4"#"9b:0a:90:42:96"
            connector.scanning = True
            connector.decrypt = True

            #connector.add_key(bytes.fromhex("08f59b42d06fd3bdc588cd4d1c244018"))
            connector.start()
            out = ""
            for i in connector.sniff():
                print(i)
                #key_stream():
                #out += i
                #print(out)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
