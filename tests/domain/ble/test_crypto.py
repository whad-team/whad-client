from whad.domain.ble.crypto import e,em1
import pytest

@pytest.mark.parametrize("test_input, expected", [
(("6fd5a34b151b814a6862123af5042986", "30750bfc537ed6e8b8760ba26e7e449c"), "58df56e513175d4b07574c7a086a8656"),
(("9ca466f44746c248b927ce560fda193b", "3b35320801d9856370a187a656d3f0bb"), "dd47561145876763399faa5bd754a158"),
(("6cfc2cef0223f09cba54cf7b3b33fb95", "b8999a4416f94f1fa57e7b5241aaced4"), "b74e17ce871415db00673966a60eecec"),
(("322273368519469301eac5413d0a1de6", "2903731f15dccbf76b98cc3f0fc2b919"), "3d568db509849a25702db86d23e32092"),
(("08198d61b823fd1bfeda87a396f4a900", "6603eda45dc692ce9cdca524eda0a04c"), "f383ed04fe333f8667aa45029592be32"),
(("7883d312733ccba73f8a1648ef1d4526", "8976d5c92982ce1ed6571d9b69579dcd"), "ba91936e028ce2df622350b2af3117e0"),
(("5d929e0a4081f121f8b54318e3cca84d", "7aeaeaa73225b41e1c8b2d3a984b70a9"), "0050ef9db7c03800354006b9b3c62462"),
(("8c3787b82492473e727a84e9edf08c53", "a8c275cd9731efd8e91d76986397bb28"), "c74ed96598d48892ab304d390f481a04"),
(("0033830c789f926aba80f7974a4dbc0e", "36bdf03acc8d8bd05028290a4b03a1ae"), "a266343238cebf3f8ff0c8d0176dad0f"),
(("333972e93cc4329a76aa037dea552d1f", "15186f2fab06273734e4cf594aaa2ce8"), "cf77435cb569f7e0e98f4936c10eef24"),
])
def test_e(test_input, expected):
    key, plaintext = test_input
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    expected = bytes.fromhex(expected)
    assert e(key,plaintext) == expected


@pytest.mark.parametrize("test_input, expected", [
(("6fd5a34b151b814a6862123af5042986","58df56e513175d4b07574c7a086a8656"),"30750bfc537ed6e8b8760ba26e7e449c"),
(("9ca466f44746c248b927ce560fda193b","dd47561145876763399faa5bd754a158"),"3b35320801d9856370a187a656d3f0bb"),
(("6cfc2cef0223f09cba54cf7b3b33fb95","b74e17ce871415db00673966a60eecec"),"b8999a4416f94f1fa57e7b5241aaced4"),
(("322273368519469301eac5413d0a1de6","3d568db509849a25702db86d23e32092"),"2903731f15dccbf76b98cc3f0fc2b919"),
(("08198d61b823fd1bfeda87a396f4a900","f383ed04fe333f8667aa45029592be32"),"6603eda45dc692ce9cdca524eda0a04c"),
(("7883d312733ccba73f8a1648ef1d4526","ba91936e028ce2df622350b2af3117e0"),"8976d5c92982ce1ed6571d9b69579dcd"),
(("5d929e0a4081f121f8b54318e3cca84d","0050ef9db7c03800354006b9b3c62462"),"7aeaeaa73225b41e1c8b2d3a984b70a9"),
(("8c3787b82492473e727a84e9edf08c53","c74ed96598d48892ab304d390f481a04"),"a8c275cd9731efd8e91d76986397bb28"),
(("0033830c789f926aba80f7974a4dbc0e","a266343238cebf3f8ff0c8d0176dad0f"),"36bdf03acc8d8bd05028290a4b03a1ae"),
(("333972e93cc4329a76aa037dea552d1f","cf77435cb569f7e0e98f4936c10eef24"),"15186f2fab06273734e4cf594aaa2ce8"),
])
def test_em1(test_input, expected):
    key, ciphertext = test_input
    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)
    expected = bytes.fromhex(expected)
    assert em1(key,ciphertext) == expected
