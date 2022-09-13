from enum import IntEnum

class Dot15d4Phy(IntEnum):
    OQPSK = 0

SYMBOL_DURATION = {
    Dot15d4Phy.OQPSK : (4/250000)
}
