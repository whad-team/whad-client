from dataclasses import dataclass, field

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a Logitech Unifying communication.

    :param channel: select the channel to sniff (c)
    :param address: provide address to sniff (f)
    :param scanning: enable scanning mode (s)
    :param acknowledgements: enable acknowledgements sniffing (a)
    :param pairing: sniff pairing procedure (p)
    :param decrypt: indicate if decryption is enabled (d)
    :param keys: provide decryption keys (k)

    """
    channel : int = 0
    address : str = "FF:FF:FF:FF:FF"
    scanning : bool = False
    acknowledgements : bool = False
    pairing : bool = False
    decrypt : bool = False
    keys : list = field(default_factory=lambda: [])
