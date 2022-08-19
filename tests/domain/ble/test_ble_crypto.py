from whad.ble.crypto import e,em1,s1,aes_cmac,xor,c1,c1m1,ah,f4,f5,f6,g2,h6,h7,LinkLayerCryptoManager
from whad.protocol.ble.ble_pb2 import BleDirection
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

@pytest.mark.parametrize("test_input, expected", [
(("00000000000000000000000000000000", "000F0E0D0C0B0A091122334455667788", "010203040506070899AABBCCDDEEFF00"), "9a1fe1f0e8b0f49b5b4216ae796da062")
])
def test_s1(test_input, expected):
    key, r1, r2 = test_input
    key = bytes.fromhex(key)
    r1,r2 = bytes.fromhex(r1), bytes.fromhex(r2)
    expected = bytes.fromhex(expected)
    assert s1(key,r1,r2) == expected



@pytest.mark.parametrize("test_input, expected", [
(("2b7e151628aed2a6abf7158809cf4f3c", ""), "bb1d6929e95937287fa37d129b756746"),
(("2b7e151628aed2a6abf7158809cf4f3c","6bc1bee22e409f96e93d7e117393172a"), "070a16b46b4d4144f79bdd9dd04a287c"),
(("2b7e151628aed2a6abf7158809cf4f3c","6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"), "dfa66747de9ae63030ca32611497c827"),
(("2b7e151628aed2a6abf7158809cf4f3c","6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"), "51f0bebf7e3b9d92fc49741779363cfe")

])
def test_aes_cmac(test_input, expected):
    key, m = test_input
    key = bytes.fromhex(key)
    m = bytes.fromhex(m)
    expected = bytes.fromhex(expected)
    assert aes_cmac(key,m) == expected



@pytest.mark.parametrize("test_input, expected", [
(("00", "00"), "00"),
(("FF", "00"), "FF"),
(("FF", "FF"), "00"),
(("55", "AA"), "FF"),
(("55", "55"), "00"),
(("00"*8, "00"*8), "00"*8),
(("FF"*8, "00"*8), "FF"*8),
(("FF"*8, "FF"*8), "00"*8),
(("55"*8, "AA"*8), "FF"*8),
(("55"*8, "55"*8), "00"*8),

])
def test_xor(test_input, expected):
    a,b = test_input
    a,b = bytes.fromhex(a),bytes.fromhex(b)
    expected = bytes.fromhex(expected)
    assert xor(a,b) == expected

@pytest.mark.parametrize("test_input, expected", [
(
    (
        "00000000000000000000000000000000", # key
        "5783D52156AD6F0E6388274EC6702EE0", # r
        "05000800000302", # pres
        "07071000000101", # preq
        "01", # iat
        "A1A2A3A4A5A6", # ia
        "00", # rat
        "B1B2B3B4B5B6" # ra
    ),
    "1E1E3FEF878988EAD2A74DC5BEF13B86"
)

])
def test_c1(test_input, expected):
    key, r, pres, preq, iat, ia, rat, ra = [bytes.fromhex(i) for i in test_input]
    expected = bytes.fromhex(expected)
    assert c1(key,r,pres,preq,iat,ia,rat,ra) == expected


@pytest.mark.parametrize("test_input, expected", [
(
    (
        "00000000000000000000000000000000", # key
        "1E1E3FEF878988EAD2A74DC5BEF13B86", # confirm
        "05000800000302", # pres
        "07071000000101", # preq
        "01", # iat
        "A1A2A3A4A5A6", # ia
        "00", # rat
        "B1B2B3B4B5B6" # ra
    ),
    "5783D52156AD6F0E6388274EC6702EE0"
)

])
def test_c1m1(test_input, expected):
    key, confirm, pres, preq, iat, ia, rat, ra = [bytes.fromhex(i) for i in test_input]
    expected = bytes.fromhex(expected)
    assert c1m1(key,confirm,pres,preq,iat,ia,rat,ra) == expected

@pytest.mark.parametrize("test_input, expected", [
(("ec0234a357c8ad05341010a60a397d9b", "708194"), "0dfbaa"),
])
def test_ah(test_input, expected):
    key, r = test_input
    key = bytes.fromhex(key)
    r = bytes.fromhex(r)
    expected = bytes.fromhex(expected)
    assert ah(key,r) == expected


@pytest.mark.parametrize("test_input, expected", [
(
    (
        "20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6", # U
        "55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd", # V
        "d5cb8454d177733effffb2ec712baeab", # X
        "00" # Z
    ),
    "f2c916f107a9bd1cf1eda1bea974872d"
)
])
def test_f4(test_input, expected):
    U,V,X,Z = [bytes.fromhex(i) for i in test_input]
    expected = bytes.fromhex(expected)
    assert f4(U,V,X,Z) == expected


@pytest.mark.parametrize("test_input, expected", [
(
    (
        "ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698", # W
        "d5cb8454d177733effffb2ec712baeab", # N1
        "a6e8e7cc25a75f6e216583f7ff3dc4cf", # N2
        "0056123737bfce", # A1
        "00a713702dcfc1" # A2

    ),
    "6986791169d7cd23980522b594750a382965f176a1084a02fd3f6a20ce636e20"
)
])
def test_f5(test_input, expected):
    W,N1,N2,A1,A2 = [bytes.fromhex(i) for i in test_input]
    expected = bytes.fromhex(expected)
    assert f5(W,N1,N2,A1,A2) == expected

@pytest.mark.parametrize("test_input, expected", [
(
    (
        "2965f176a1084a02fd3f6a20ce636e20", # W
        "d5cb8454d177733effffb2ec712baeab", # N1
        "a6e8e7cc25a75f6e216583f7ff3dc4cf", # N2
        "12a3343bb453bb5408da42d20c2d0fc8", # R
        "010102", # IOcap
        "0056123737bfce", # A1
        "00a713702dcfc1" # A2

    ),
    "e3c473989cd0e8c5d26c0b09da958f61"
)
])
def test_f6(test_input, expected):
    W,N1,N2,R,IOcap,A1,A2 = [bytes.fromhex(i) for i in test_input]
    expected = bytes.fromhex(expected)
    assert f6(W,N1,N2,R,IOcap,A1,A2) == expected


@pytest.mark.parametrize("test_input, expected", [
(
    (
        "20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6", # U
        "55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd", # V
        "d5cb8454d177733effffb2ec712baeab", # X
        "a6e8e7cc25a75f6e216583f7ff3dc4cf", # Y

    ),
    "2f9ed5ba"
)
])
def test_g2(test_input, expected):
    U,V,X,Y = [bytes.fromhex(i) for i in test_input]
    expected = bytes.fromhex(expected)
    assert g2(U,V,X,Y) == expected

@pytest.mark.parametrize("test_input, expected", [
(("ec0234a357c8ad05341010a60a397d9b", "6c656272"), "2d9ae102e76dc91ce8d3a9e280b16399"),
])
def test_h6(test_input, expected):
    key, keyID = test_input
    key = bytes.fromhex(key)
    keyID = bytes.fromhex(keyID)
    expected = bytes.fromhex(expected)
    assert h6(key,keyID) == expected

@pytest.mark.parametrize("test_input, expected", [
(("000000000000000000000000746D7031", "ec0234a357c8ad05341010a60a397d9b"), "fb173597c6a3c0ecd2998c2a75a57011"),
])
def test_h7(test_input, expected):
    salt, key = test_input
    salt = bytes.fromhex(salt)
    key = bytes.fromhex(key)
    expected = bytes.fromhex(expected)
    assert h7(salt,key) == expected

@pytest.mark.parametrize("test_input, expected", [
(("07055dda30af9a", BleDirection.MASTER_TO_SLAVE, (0,1)), "070506"),
(("0e0f7118215ebe5761a4e59e079b37fe1e", BleDirection.SLAVE_TO_MASTER, (0,1)), "0e0f07000400080100ffff002a"),
(("0e0fc083c929376c15a38f2a4c16d728f8", BleDirection.SLAVE_TO_MASTER, (0,2)), "0e0f07000400080100ffff002a"),
(("020f6c32ce799316ffe768f26afb446522", BleDirection.SLAVE_TO_MASTER, (0,3)), "020f07000400080100ffff002a"),
(("0a1dc096d431e348c0b7387f3ea4c0033fda0829493c907295e2f96859e006", BleDirection.MASTER_TO_SLAVE, (3,4)), "0a1d1500040009130300544920424c452053656e736f7220546167"),

])
def test_LinkLayerCryptoManager(test_input, expected):
    ltk = bytes.fromhex("7f62c053f104a5bbe68b1d896a2ed49c")
    master_skd = 0x7d027501426377a9
    master_iv = 0x6c71f00a
    slave_skd = 0x102c2869b542e91c
    slave_iv = 0xcd59cff4
    llcm = LinkLayerCryptoManager(ltk, master_skd, master_iv, slave_skd,slave_iv)
    ciphertext, direction, (master_counter, slave_counter) = test_input
    ciphertext = bytes.fromhex(ciphertext)
    expected = bytes.fromhex(expected)
    llcm.update_master_counter(master_counter)
    llcm.update_slave_counter(slave_counter)
    result,valid = llcm.decrypt(ciphertext,direction)
    llcm_ciphertext = llcm.encrypt(result,direction)
    assert valid and result == expected and llcm_ciphertext == ciphertext
