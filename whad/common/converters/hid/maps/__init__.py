"""
International HID keymaps
"""

from .be import HID_MAP as BE_MAP
from .ca import HID_MAP as CA_MAP
from .ch import HID_MAP as CH_MAP
from .de import HID_MAP as DE_MAP
from .dk import HID_MAP as DK_MAP
from .es import HID_MAP as ES_MAP
from .fi import HID_MAP as FI_MAP
from .fr import HID_MAP as FR_MAP
from .gb import HID_MAP as GB_MAP
from .hr import HID_MAP as HR_MAP
from .it import HID_MAP as IT_MAP
from .no import HID_MAP as NO_MAP
from .pt import HID_MAP as PT_MAP
from .ru import HID_MAP as RU_MAP
from .sl import HID_MAP as SL_MAP
from .sv import HID_MAP as SV_MAP
from .tr import HID_MAP as TR_MAP
from .us import HID_MAP as US_MAP

HID_MAP = {
    'be': BE_MAP,
    'ca': CA_MAP,
    'ch': CH_MAP,
    'de': DE_MAP,
    'dk': DK_MAP,
    'es': ES_MAP,
    'fi': FI_MAP,
    'fr': FR_MAP,
    'gb': GB_MAP,
    'hr': HR_MAP,
    'it': IT_MAP,
    'no': NO_MAP,
    'pt': PT_MAP,
    'ru': RU_MAP,
    'sl': SL_MAP,
    'sv': SV_MAP,
    'tr': TR_MAP,
    'us': US_MAP,
}

__all__ = [
    "HID_MAP",
    "BE_MAP",
    "CA_MAP",
    "CH_MAP",
    "DE_MAP",
    "DK_MAP",
    "ES_MAP",
    "FI_MAP",
    "FR_MAP",
    "GB_MAP",
    "HR_MAP",
    "IT_MAP",
    "NO_MAP",
    "PT_MAP",
    "RU_MAP",
    "SL_MAP",
    "SV_MAP",
    "TR_MAP",
    "US_MAP",
]
