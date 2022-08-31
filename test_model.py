from whad.ble.characteristic import UUID, ClientCharacteristicConfig
from whad.ble.profile import PrimaryService, Characteristic, GenericProfile, SecondaryService

class MonDevice(GenericProfile):

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
print(a)
model_export = a.export_json()
print(model_export)

# try to create a new model
class ImportedDevice(GenericProfile):
    def __init__(self, from_json):
        super().__init__(from_json=from_json)

b = ImportedDevice(model_export)
print(b)