"""BLE GATT helpers
"""

from whad.ble.utils.att import UUID
from whad.ble.stack.gatt.constants import CHARACS_UUID, SERVICES_UUID

def get_alias_uuid(alias: str):
    """Get 16-bit UUID from alias.
    """
    for uuid, name in SERVICES_UUID.items():
        if alias == name:
            return UUID(uuid)

    for uuid, name in CHARACS_UUID.items():
        if alias == name:
            return UUID(uuid)

    return None

def get_uuid_alias(uuid: UUID):
    """Get UUID alias for 16-bit UUID
    """
    if uuid.type == UUID.TYPE_16:
        uuid_val = int(uuid.uuid, 16)
        if uuid.type == UUID.TYPE_16:
            if uuid_val in SERVICES_UUID:
                return SERVICES_UUID[uuid_val]
            elif uuid_val in CHARACS_UUID:
                return CHARACS_UUID[uuid_val]
