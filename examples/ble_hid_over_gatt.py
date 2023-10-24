from whad.ble import Peripheral
from whad.ble.profile.advdata import AdvCompleteLocalName, \
                                     AdvDataFieldList, AdvFlagsField
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile, \
    ReadAccess, WriteAccess, Authentication, Encryption, Authorization
from whad.device import WhadDevice
from random import randint
from whad.ble.exceptions import HookReturnAuthorRequired, HookReturnValue
from whad.ble.profile import read, written, subscribed
from struct import pack, unpack
from whad.ble.stack.smp import Pairing, IOCAP_KEYBD_ONLY, IOCAP_NOINPUT_NOOUTPUT, CryptographicDatabase

import logging
logging.basicConfig(level=logging.WARNING)
logging.getLogger('whad.ble.stack.ll').setLevel(logging.INFO)
logging.getLogger('whad.ble.stack.smp').setLevel(logging.INFO)

class HIDOverGATT(GenericProfile):

    device = PrimaryService(
        uuid=UUID.from_name("Generic Access"),
        device_name=Characteristic(
            uuid=UUID.from_name("Device Name"),
            permissions=['read', 'write'],
            notify=True,
            value=bytes('EvilKeyboard', 'utf-8')
        ),
    )

if __name__ == '__main__':
    my_profile = HIDOverGATT() #GenericProfile(from_json="lightbulb2.json")
    pairing = Pairing(
        lesc=True,
        mitm=True,
        bonding=True,
    )
    periph = Peripheral(WhadDevice.create('hci0'), profile=my_profile, pairing=pairing)
    #periph.attach_callback(callback=show)
    periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
        AdvCompleteLocalName(b'EvilKeyboard'),
        AdvFlagsField()
    ))

    print('Press a key to trigger a pairing')
    input()
    periph.pairing(pairing=pairing)
    while True:
        pass
