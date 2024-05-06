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
    if hasattr(pkt, "metadata"):
        print("< ", repr(pkt))
    else:
        print("> ", repr(pkt))


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)

            mso = MSOProfile()
            target = Target(dev, profiles=[mso])
            target.set_channel(15)

            target.attach_callback(show, on_transmission=True, on_reception=True)
            monitor.attach(target)
            monitor.start()
            target.start()

            #target.auto_discovery()
            reference = mso.wait_for_binding()

            if reference is None:
                print("pairing failure...")
            else:
                print(reference)

            success = True
            print(mso.wait_for_validation_code(1234))
            if success:
                print("ACCEPT !")
                mso.accept_validation()

                #mso.save_audio("/tmp/out.wav")
                mso.live_audio()
            else:
                print("DENY !")
                mso.deny_validation()


            while True:

                input()
                '''
                print('success')
                while not target.stack.get_layer('nwk').get_service('data').data(
                    RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Check_Validation_Response(
                        check_validation_status=0
                    ),
                    pairing_reference = 0,
                    profile_id = 0xc0,
                    vendor_id = 4417,
                    tx_options = (
                     0 | (1 << 1) | (0 << 2) | (1 << 3) | (0 << 4)| (0 << 5) | (1 << 6)
                    )
                ):
                    pass

                input()
                '''
            #target.discovery_response(True, destination_address="C4:19:D1:AE:35:0D:70:02")
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
