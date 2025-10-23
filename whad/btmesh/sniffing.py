from dataclasses import dataclass, field
from whad.common.sniffing import SniffingEvent


@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing BTMesh

    :param decrypt: indicate if decryption is enabled (d)
    :param whitelist_addresses: filter on AdVA addresses (w)
    :param net_keys: provide decryption keys for the network layer (n)
    :param app_keys: provide decryption keys for the application layer (a)
    :param iv_indexes: list of iv_index for each net_key, in the same order (x)
    :param channel: select the channel to sniff - default to channel hopping (c)
    :param use_rpl: indicate if cache on network layer activated (r)


    TODO : network cache fix

    """

    decrypt: bool = False
    whitelist_addresses: list = field(default_factory=lambda: []) # not used yet
    net_keys: list = field(default_factory=lambda: ["f7a2a44f8e8a8029064f173ddc1e2b00"])
    app_keys: list = field(default_factory=lambda: ["63964771734fbd76e3b40519d1d94a48"])
    iv_indexes: list = field(default_factory=lambda: ["00000000"])
    channel: int = None
    use_network_cache: bool = True # Not used yet
