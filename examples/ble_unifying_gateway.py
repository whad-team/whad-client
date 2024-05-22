from whad.ble import Peripheral
from whad.ble.profile.advdata import AdvCompleteLocalName, \
                                     AdvDataFieldList, AdvFlagsField
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile, \
    ReadAccess, WriteAccess, Authentication, Encryption, Authorization, ReportReferenceDescriptor
from whad.device import WhadDevice
from random import randint
from whad.ble.exceptions import HookReturnAuthorRequired, HookReturnValue
from whad.ble.profile import read, written, subscribed
from struct import pack, unpack
from whad.ble.stack.smp import Pairing, IOCAP_KEYBD_ONLY, IOCAP_NOINPUT_NOOUTPUT, CryptographicDatabase
from whad.common.converters.hid import HIDConverter
from whad.unifying import Dongle
import time
from prompt_toolkit import print_formatted_text, HTML

import logging

# Parameters of the BLE / Unifying gateway
ble_device_name = b'WHADUnifyingBLEGateway'
ble_device_address = "94:e2:3c:62:c0:40"
unifying_device_address = "9b:0a:90:42:b2"
unifying_aes_key = bytes.fromhex("08f59b42a06fee0e2588fa4d063c4096")
unifying_rf_channel = 8

# HID Profile definition
class HIDOverGATT(GenericProfile):

    service1 = PrimaryService(
        uuid=UUID.from_name("Generic Access"),
        device_name=Characteristic(
            uuid=UUID.from_name("Device Name"),
            permissions=['read', 'write'],
            value=ble_device_name
        ),
        manufacturer_name=Characteristic(
            uuid=UUID.from_name("Manufacturer Name String"),
            permissions=['read', 'write'],
            value=ble_device_name
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

# GATT server instantiation
gatt_hid_profile = HIDOverGATT()

# Function allowing to forward keystrokes from Unifying keyboard to BLE HID over GATT
def forward_key(key):
    global gatt_hid_profile
    print_formatted_text(
        HTML("<b>[i] Keystroke received from Unifying keyboard:</b> <ansicyan>%s</ansicyan>" % str(key))
    )
    print_formatted_text(HTML("<b>[i]Converting and forwarding to BLE:</b>"))

    hid_code, modifiers = HIDConverter.get_hid_code_from_key(key.lower(), locale="us")
    gatt_keypress_value = bytes.fromhex("00") + bytes([modifiers, hid_code])+ bytes.fromhex("0000000000")
    gatt_keyrelease_value = bytes.fromhex("0000000000000000")
    print_formatted_text(
        HTML('  | <ansicyan>Key press:</ansicyan> <b>%s</b>' % gatt_keypress_value.hex())
    )
    print_formatted_text(
        HTML('  | <ansicyan>Key release:</ansicyan> <b>%s</b>' % gatt_keyrelease_value.hex())
    )
    gatt_hid_profile.service3.report.value = gatt_keypress_value
    gatt_hid_profile.service3.report.value = gatt_keyrelease_value

    return False

if __name__ == '__main__':
    # Load unifying interface
    dev = WhadDevice.create("uart0")

    # Instantiation of dongle connector
    connector = Dongle(dev, on_keystroke=forward_key)

    # Setup our parameters
    connector.address = unifying_device_address
    connector.key = unifying_aes_key
    connector.channel = unifying_rf_channel

    # Phase 1: start the connector and wait for unifying synchronization
    connector.start()

    print_formatted_text(HTML("<b>[i] Waiting for Unifying synchronization...</b>"))
    connector.wait_synchronization()
    print_formatted_text(HTML("<b>[i] Unifying keyboard synchronized:</b> %s" % str(connector.address)))

    # Phase 2: configure Just Works BLE pairing and instantiate a new HID over GATT BLE peripheral
    pairing = Pairing(
        lesc=False,
        mitm=False,
        bonding=True,
    )
    print_formatted_text(
        HTML(
            "<b>[i] Advertising new HID over GATT keyboard:</b> %s (%s)" % (
                ble_device_address,
                ble_device_name.decode()
            )
        )
    )
    periph = Peripheral(
        WhadDevice.create('hci0'),
        profile=my_profile,
        pairing=pairing,
        bd_address=ble_device_address
    )

    periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
        AdvCompleteLocalName(ble_device_name),
        AdvFlagsField()
    ))
    # Wait for a connection over BLE
    while not periph.is_connected():
        time.sleep(1)
    print_formatted_text(HTML("<b>[i] New device connected !</b>"))

    # Phase 3: go idle while keystrokes are forwarded by the gateway
    while True:
        time.sleep(1)
