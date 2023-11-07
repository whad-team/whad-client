from enum import IntEnum

# Supported domains
class QEMUNrfDomains(IntEnum):
    QEMU_RAW_ESB = 0
    QEMU_UNIFYING = 1
    QEMU_BLE = 2
