def message_filter(category, message):
    return lambda x: x.WhichOneof('msg') == category and getattr(x, category).WhichOneof('msg')==message

def is_message_type(message, category, message_type):
    if message.WhichOneof('msg') == category:
        return (hasattr(message, category) and getattr(message, category).WhichOneof('msg') == message_type)
    else:
        return False

def bd_addr_to_bytes(bd_addr):
    """
    Convert BD address to bytes
    """
    if not isinstance(bd_addr,str):
        return None

    # Clean BD address
    bd_addr_b = []
    bd_addr = bd_addr.replace(':','').lower()
    if len(bd_addr) == 12:
        for i in range(6):
            bd_addr_b.append(int(bd_addr[i*2:(i+1)*2], 16))
        return bytes(bd_addr_b[::-1])
    else:
        return None

def asciiz(s):
    """Convert a bytes buffer into ascii
    """
    if not isinstance(s,bytes):
        return None

    out=''
    for c in s:
        if s!=0:
            out += chr(c)
    return out
