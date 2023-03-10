from whad.ble import Peripheral
from whad.ble.profile.advdata import AdvCompleteLocalName, \
                                     AdvDataFieldList, AdvFlagsField
from whad.ble.profile.attribute import UUID
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile
from whad.device import WhadDevice
from random import randint
from whad.ble.exceptions import HookReturnAuthorRequired, HookReturnValue
from whad.ble.profile import read, written, subscribed
from struct import pack, unpack

import logging
logging.basicConfig(level=logging.INFO)

NAME = 'WHAT BLE Peripheral Guess Demo'


class MyPeripheral(GenericProfile):

    device = PrimaryService(
        uuid=UUID(0x1800),
        device_name=Characteristic(
            uuid=UUID(0x2A00),
            permissions=['read', 'write'],
            notify=True,
            value=bytes(NAME, 'utf-8')
        ),
    )

    # create a custom service
    custom = PrimaryService(
        uuid=UUID('abcdabcd-0001-0001-0001-000100020000'),
        msg=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-000100020001'),
            permissions=['read'],
            notify=True,
            value=b'Guess the number!'
        ),
        guess=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-000100020002'),
            permissions=['write'],
            notify=False,
        ),
        number=Characteristic(
            uuid=UUID('abcdabcd-0001-0001-0001-000100020003'),
            permissions=['read'],
            notify=True,
            value=b'Default'
        ),
    )

    @written(custom.guess)
    def on_guess_written(self, offset, value, without_response):
        print(f'offset={offset} value={value} '
              'without_response={without_response}')

        # pick a random number if not already done
        if self.custom.number.value == b'Default':
            self.custom.number.value = pack('B', randint(0, 20))

        # convert to integers
        to_guess = unpack('B', self.custom.number.value)[0]
        provided = unpack('B', value)[0]
        print(f'to_guess={to_guess} provided={provided}')

        if provided == to_guess:
            self.custom.msg.value = b'Congrats!'
        elif provided > to_guess:
            self.custom.msg.value = b'My number is smaller'
        else:
            self.custom.msg.value = b'My number is bigger'

    @read(custom.number)
    def on_number_read(self, offset, mtu):
        print(f'offset={offset} mtu={mtu}')
        if self.custom.msg.value == b'Congrats!':
            raise HookReturnValue(self.custom.number.value)
        else:
            # no cheating! you can't read this!
            raise HookReturnAuthorRequired()

    @subscribed(custom.number)
    def on_number_subscribed(self, notification, indication):
        print(f'notif={notification} ind={indication}')


def show(packet):
    print(packet.metadata, repr(packet))


def update_number():
    print('Press a key to modify the number to guess')
    input()
    my_profile.custom.number.value = pack('B', 15)


if __name__ == '__main__':
    print(f'======== {NAME} ===========')
    my_profile = MyPeripheral()
    periph = Peripheral(WhadDevice.create('hci1'), profile=my_profile)
    periph.attach_callback(callback=show)
    periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
        AdvCompleteLocalName(b'Guess Me!'),
        AdvFlagsField()
    ))

    update_number()
    print('Press a key to QUIT')
    input()
