from dataclasses import dataclass, field

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a RF4CE communication.

    :param channel: select the channel to sniff (c)
    :param decrypt: indicate if decryption is enabled (d)
    :param keys: provide decryption keys (k)

    """
    channel : int = 15
    decrypt : bool = False
    keys : list = field(default_factory=lambda: [])
