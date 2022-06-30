from xml.dom.minidom import CharacterData
#from whad.domain.ble.device import ServiceModel, DeviceModel
from whad.domain.ble.characteristic import UUID
from whad.domain.ble.model import PrimaryService, Characteristic, DeviceModel, SecondaryService

class MonDevice(DeviceModel):

    second_service = SecondaryService(
        uuid=UUID(0x4567)
    )

    premier_service = PrimaryService(
        uuid=UUID(0x1234),

        premiere_carac = Characteristic(
            uuid=UUID(0x2A00),
            permissions = ['read', 'write'],
            notify=True,
            value=b'This is a test'
        ),

        seconde_carac = Characteristic(
            uuid=UUID(0x2B00),
            permissions = ['read']
        )
    )

    def on_read(self, service, characteristic):
        if service.uuid == self.premier_service.uuid:
            return characteristic.value
        else:
            return None


    def on_write(self, service, characteristic, data):
        characteristic.value = data

class OtherDevice(MonDevice):
    troisieme_service = PrimaryService(
        uuid=UUID(0x7777)
    )

a = MonDevice()
print(a.premier_service)
print(a.premier_service.premiere_carac.value)
a.premier_service.premiere_carac.value = b'Something else'
print(a.premier_service.premiere_carac.value)
b = OtherDevice()

print(b.second_service.handle)
print(b.premier_service.handle)
print(b.troisieme_service.handle)
print(OtherDevice.__bases__[0])
