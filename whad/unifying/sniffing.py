from dataclasses import dataclass, field
from whad.common.sniffing import SniffingEvent

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a Logitech Unifying communication.

    :param channel: select the channel to sniff (c)
    :param address: provide address to sniff (f)
    :param scanning: enable scanning mode (s)
    :param acknowledgements: enable acknowledgements sniffing (a)
    :param pairing: sniff pairing procedure and break key if possible (p)
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


class KeyExtractedEvent(SniffingEvent):
    """Event indicating that a key has been extracted from pairing
    """
    def __init__(self, key):
        super().__init__("Key extracted")
        self.key = key

    @property
    def message(self):
        return "key={}".format(self.key.hex())
