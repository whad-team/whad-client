from whad.domain.zigbee.crypto import NetworkLayerCryptoManager
from scapy.compat import raw
import pytest

@pytest.mark.parametrize("test_input, expected", [
(("ad8ebbc4f96ae7000506d3fcd1627fb8", "618864472400008a5c480200008a5c1e5d28e1000000013ce801008d150001ea59de1f960eea8aee185a11893096414e05a243"), "618864472400008a5c480200008a5c1e5d28e1000000013ce801008d150001000112000401016218c30a5500210100ac4c76af"),
])
def test_NetworkLayerCryptoManager(test_input, expected):
    key, ciphertext = test_input
    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)
    expected = bytes.fromhex(expected)
    nlcm = NetworkLayerCryptoManager(key)
    decrypted, valid_mic = nlcm.decrypt(ciphertext)
    assert raw(decrypted) == expected and valid_mic
