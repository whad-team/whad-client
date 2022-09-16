from whad.zigbee.crypto import NetworkLayerCryptoManager, ApplicationSubLayerCryptoManager
from scapy.compat import raw
import pytest

@pytest.mark.parametrize("test_input, expected", [
(("ad8ebbc4f96ae7000506d3fcd1627fb8", "618864472400008a5c480200008a5c1e5d28e1000000013ce801008d150001ea59de1f960eea8aee185a11893096414e05a243"), "618864472400008a5c480200008a5c1e5d28e1000000013ce801008d150001000112000401016218c30a5500210100ac4c76af"),
(("44819751b602049181dc8bc2714df09d", "6188f73acb73e523ed480273e523ed1e7228a3b2890283b6a90101881700007657e59a7002fac5e9b7315bf67d5f9afc"), "6188f73acb73e523ed480273e523ed1e7228a3b2890283b6a9010188170000000b0800040140a300860000002e22fb48"),

])
def test_NetworkLayerCryptoManager(test_input, expected):
    key, ciphertext = test_input
    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)
    expected = bytes.fromhex(expected)
    nlcm = NetworkLayerCryptoManager(key)
    decrypted, valid_mic = nlcm.decrypt(ciphertext)
    ciphertext_generated = nlcm.encrypt(expected)

    decryption_ok = raw(decrypted) == expected and valid_mic
    encryption_ok = raw(ciphertext_generated) == ciphertext
    assert  decryption_ok and encryption_ok

@pytest.mark.parametrize("test_input, expected", [
(("814286865dc1c8b2c8cbc52e5d65d1b8", "61887c803104000100080004000100013521b83001000200ce99430501881700f47c78a38c74072b1380763ae007df4346c92f7f127eba41be454ebdbe106c37ae161efe4d3718"), "61887c803104000100080004000100013521b83001000200ce99430501881700050102398409245156e31d98a92157a8a66f0033d1b90401881700ffffffffffffffff2a117c60"),
])
def test_ApplicationSubLayerCryptoManager(test_input, expected):
    key, ciphertext = test_input
    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)
    expected = bytes.fromhex(expected)
    aslcm = ApplicationSubLayerCryptoManager(key, 0)
    decrypted, valid_mic = aslcm.decrypt(ciphertext)
    ciphertext_generated = aslcm.encrypt(expected)

    decryption_ok = raw(decrypted) == expected and valid_mic
    encryption_ok = raw(ciphertext_generated) == ciphertext
    assert  decryption_ok and encryption_ok
