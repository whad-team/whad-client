"""
BT Mesh Provisioner Profile

Used to interact and create the Provisioner of a Mesh network
"""

from whad.ble.profile import GenericProfile, PrimaryService, UUID, Characteristic
from whad.bt_mesh.crypto import ProvisioningBearerAdvCryptoManagerProvisioner

class ProvisionerProfile(GenericProfile):
    device = PrimaryService(
        uuid=UUID(0x1800),

        device_name = Characteristic(
            uuid=UUID(0x2A00),
            permissions = ['read', 'write'],
            notify=True,
            value=b'TestDeviceProvisioner'
        ),
    )
    


crypto_manager = ProvisioningBearerAdvCryptoManagerProvisioner()
