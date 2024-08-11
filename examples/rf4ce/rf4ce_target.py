from whad.device import WhadDevice
from whad.rf4ce import Target
from whad.rf4ce.stack.apl.profiles import MSOProfile
from whad.dot15d4.address import Dot15d4Address
from whad.common.monitors import WiresharkMonitor
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from whad.scapy.layers.rf4ce import RF4CE_Vendor_MSO_Hdr, \
    RF4CE_Vendor_MSO_Get_Attribute_Response, RF4CE_Vendor_MSO_Check_Validation_Response

from random import randint
import sys
import logging

def show(pkt):
    print(repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            # Create a wireshark monitor
            monitor = WiresharkMonitor()

            # Create the WHAD device
            dev = WhadDevice.create(interface)

            # Use the default MSO profile
            mso = MSOProfile()
            # Create a RF4CE target using the MSO profile
            target = Target(dev, profiles=[mso])
            target.set_channel(15)

            # Attach a callback to monitor traffic
            target.attach_callback(show, on_transmission=True, on_reception=True)
            # Attach & start the wireshark monitor
            monitor.attach(target)
            monitor.start()

            # Start the target
            target.start()

            # Wait for a binding
            reference = mso.wait_for_binding()

            if reference is None:
                print("Pairing failure...")
            else:
                print("Pairing success !")
                print("Reference:", reference)

            if mso.wait_for_validation_code(1234)):
                print("Validation code successful, accepting validation")
                mso.accept_validation()

                # Save audio file to /tmp/out.wav
                mso.save_audio("/tmp/out.wav")
            else:
                print("Bad validation code, denying validation")
                mso.deny_validation()

            input()
            print("Terminating target")
            target.stop()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
