from whad.helpers import list_domains
from whad.protocol.phy.phy_pb2 import SF7, SF8, SF9, SF10, SF11, SF12, \
    CR45, CR46, CR47, CR48
from whad.phy.exceptions import InvalidParameter

LORA_SF_MAP = {
    7: SF7,
    8: SF8,
    9: SF9,
    10: SF10,
    11: SF11,
    12: SF12
}

LORA_CR_MAP = {
    45: CR45,
    46: CR46,
    47: CR47,
    48: CR48
}

def get_physical_layers_by_domain(domain):
    '''
    Returns physical layer of a specific domain. Returns None if no physical layer found.
    '''
    try:
        phys = __import__("whad.{}".format(domain),  globals(), locals(), ["PHYS"])
        return vars(phys)["PHYS"]
    except (ImportError, KeyError):
        return None
    
def get_all_physical_layers():
    '''
    Returns all available physical layers.
    '''
    available_phys = {}
    for domain in list_domains():
        phys = get_physical_layers_by_domain(domain)
        if phys is not None:
            available_phys.update(phys)
    return available_phys

def lora_sf(sf: int=7):
    '''
    Convert LoRa spreading factor value into WHAD compatible constant
    '''
    if sf in LORA_SF_MAP:
        return LORA_SF_MAP[sf]
    else:
        raise InvalidParameter('spreading factor')
    
def lora_cr(cr: int=45):
    '''
    Convert LoRa coding rate value into WHAD compatible constant
    '''
    if cr in LORA_CR_MAP:
        return LORA_CR_MAP[cr]
    else:
        raise InvalidParameter('coding rate')

