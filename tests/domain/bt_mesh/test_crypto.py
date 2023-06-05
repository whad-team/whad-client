from whad.bt_mesh.crypto import s1, k1, k2, k3, k4
import pytest

@pytest.mark.parametrize("test_input, expected", [
("74657374", "b73cefbd641ef2ea598c2b6efb62f79c"),
])
def test_s1(test_input, expected):
    in_data = bytes.fromhex(test_input)
    expected = bytes.fromhex(expected)
    assert s1(in_data) == expected

@pytest.mark.parametrize("test_input, expected", [
(("3216d1509884b533248541792b877f98", "2ba14ffa0df84a2831938d57d276cab4", "5a09d60797eeb4478aada59db3352a0d"), "f6ed15a8934afbe7d83e8dcb57fcf5d7"),
])
def test_k1(test_input, expected):
    n, salt, p = test_input
    n = bytes.fromhex(n)
    salt = bytes.fromhex(salt)
    p = bytes.fromhex(p)
    expected = bytes.fromhex(expected)
    assert k1(n, salt, p) == expected

@pytest.mark.parametrize("test_input, expected", [
(("f7a2a44f8e8a8029064f173ddc1e2b00", "00"), "7f9f589181a0f50de73c8070c7a6d27f464c715bd4a64b938f99b453351653124f"),
(("f7a2a44f8e8a8029064f173ddc1e2b00", "010203040506070809"), "7311efec0642774992510fb5929646df49d4d7cc0dfa772d836a8df9df5510d7a7"),
])
def test_k2(test_input, expected):
    n, p = test_input
    n = bytes.fromhex(n)
    p = bytes.fromhex(p)
    expected = bytes.fromhex(expected)
    assert k2(n, p) == expected


@pytest.mark.parametrize("test_input, expected", [
("f7a2a44f8e8a8029064f173ddc1e2b00", "3527c5985f0c05ccff046958233db014"),
])
def test_k3(test_input, expected):
    n = test_input
    n = bytes.fromhex(n)
    expected = bytes.fromhex(expected)
    assert k3(n) == expected

@pytest.mark.parametrize("test_input, expected", [
("3216d1509884b533248541792b877f98", "1431ea1afeb05224ab892a0217ccab38"),
])
def test_k4(test_input, expected):
    n = test_input
    n = bytes.fromhex(n)
    expected = bytes.fromhex(expected)
    assert k4(n) == expected
