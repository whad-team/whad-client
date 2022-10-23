from whad.helpers import list_domains

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
