from whad.bt_mesh.crypto import s1, k1, k2, k3, k4, ProvisioningBearerAdvCryptoManager
import pytest


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("test", "b73cefbd641ef2ea598c2b6efb62f79c"),
    ],
)
def test_s1(test_input, expected):
    m = bytes(test_input, "ascii")
    expected = bytes.fromhex(expected)
    assert s1(m) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        (
            (
                "3216d1509884b533248541792b877f98",
                "2ba14ffa0df84a2831938d57d276cab4",
                "5a09d60797eeb4478aada59db3352a0d",
            ),
            "f6ed15a8934afbe7d83e8dcb57fcf5d7",
        ),
        (
            (
                "7dd7364cd842ad18c17c2b820c84c3d6",
                "f8795a1aabf182e4f163d86e245e19f4",
                "696431323801",
            ),
            "84396c435ac48560b5965385253e210c",
        ),
        (
            (
                "7dd7364cd842ad18c17c2b820c84c3d6",
                "2c24619ab793c1233f6e226738393dec",
                "696431323801",
            ),
            "5423d967da639a99cb02231a83f7d254",
        ),
        (
            (
                "3bbb6f1fbd53e157417f308ce7aec58f",
                "2c8b71fb5d95e86cfb753bfee3ab934f",
                "696431323801",
            ),
            "ca478cdac626b7a8522d7272dd124f26",
        ),
    ],
)
def test_k1(test_input, expected):
    n, salt, p = test_input
    n = bytes.fromhex(n)
    salt = bytes.fromhex(salt)
    p = bytes.fromhex(p)
    expected = bytes.fromhex(expected)
    assert k1(n, salt, p) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        (
            ("f7a2a44f8e8a8029064f173ddc1e2b00", "00"),
            "7f9f589181a0f50de73c8070c7a6d27f464c715bd4a64b938f99b453351653124f",
        ),
        (
            ("f7a2a44f8e8a8029064f173ddc1e2b00", "010203040506070809"),
            "7311efec0642774992510fb5929646df49d4d7cc0dfa772d836a8df9df5510d7a7",
        ),
        (
            ("7dd7364cd842ad18c17c2b820c84c3d6", "00"),
            "680953fa93e7caac9638f58820220a398e8b84eedec100067d670971dd2aa700cf",
        ),
        (
            ("7dd7364cd842ad18c17c2b820c84c3d6", "01120123450000072f"),
            "5ebe635105434859f484fc798e043ce40e5d396d4b54d3cbafe943e051fe9a4eb8",
        ),
        (
            ("7dd7364cd842ad18c17c2b820c84c3d6", "02"),
            "0db47a02c6cc9b4ac4cb9b88e765c9ade49bf7ab5a5ad415fbd77e07bb808f4865",
        ),
    ],
)
def test_k2(test_input, expected):
    n, p = test_input
    n = bytes.fromhex(n)
    p = bytes.fromhex(p)
    expected = bytes.fromhex(expected)
    assert k2(n, p) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("f7a2a44f8e8a8029064f173ddc1e2b00", "ff046958233db014"),
        ("7dd7364cd842ad18c17c2b820c84c3d6", "3ecaff672f673370"),
    ],
)
def test_k3(test_input, expected):
    n = test_input
    n = bytes.fromhex(n)
    expected = bytes.fromhex(expected)
    assert k3(n) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("3216d1509884b533248541792b877f98", "38"),
        ("63964771734fbd76e3b40519d1d94a48", "26"),
    ],
)
def test_k4(test_input, expected):
    n = test_input
    n = bytes.fromhex(n)
    expected = bytes.fromhex(expected)
    assert k4(n) == expected


"""
For new test values, copy this dict, fill it with values, and add it in the params of the fixture crypto_manager_setup below, it should use it
"""

_BTM_ECDH_P256_CMAC_AES128_AES_CCM_values = dict(
    test_input=dict(
        alg="BTM_ECDH_P256_CMAC_AES128_AES_CCM",
        private_key_provisioner=bytes.fromhex(
            "06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663"
        ),
        private_key_device=None,
        public_key_coord_device=(
            bytes.fromhex(
                "f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc"
            ),
            bytes.fromhex(
                "0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279"
            ),
        ),
        public_key_coord_provisioner=(
            bytes.fromhex(
                "2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"
            ),
            bytes.fromhex(
                "919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f"
            ),
        ),
        rand_provisioner=bytes.fromhex("8b19ac31d58b124c946209b5db1021b9"),
        rand_device=bytes.fromhex("55a2a2bca04cd32ff6f346bd0a0c1a3a"),
        auth_value=bytes.fromhex("00000000000000000000000000000000"),
    ),
    test_pdu_values=dict(
        provisioning_invite_pdu=bytes.fromhex("00"),
        provisioning_capabilities_pdu=bytes.fromhex("0100010000000000000000"),
        provisioning_start_pdu=bytes.fromhex("0000000000"),
    ),
    expected=dict(
        ecdh_secret=bytes.fromhex(
            "ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69"
        ),
        confirmation_salt=bytes.fromhex("5faabe187337c71cc6c973369dcaa79a"),
        confirmation_key=bytes.fromhex("e31fe046c68ec339c425fc6629f0336f"),
        confirmation_provisioner=bytes.fromhex("b38a114dfdca1fe153bd2c1e0dc46ac2"),
        confirmation_device=bytes.fromhex("eeba521c196b52cc2e37aa40329f554e"),
        provisioning_salt=bytes.fromhex("a21c7d45f201cf9489a2fb57145015b4"),
        session_key=bytes.fromhex("c80253af86b33dfa450bbdb2a191fea3"),
        session_nonce=bytes.fromhex("da7ddbe78b5f62b81d6847487e"),
        cipher=bytes.fromhex(
            "d0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec2973e0ec50783b10c7"
        ),
        plaintext=bytes.fromhex("efb2255e6422d330088e09bb015ed707056700010203040b0c"),
    ),
)

_BTM_ECDH_P256_HMAC_SHA256_AES_CCM_values = dict(
    test_input=dict(
        alg="BTM_ECDH_P256_HMAC_SHA256_AES_CCM",
        private_key_provisioner=None,
        private_key_device=bytes.fromhex(
            "529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba"
        ),
        public_key_coord_device=(
            bytes.fromhex(
                "f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc"
            ),
            bytes.fromhex(
                "0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279"
            ),
        ),
        public_key_coord_provisioner=(
            bytes.fromhex(
                "2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"
            ),
            bytes.fromhex(
                "919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f"
            ),
        ),
        rand_provisioner=bytes.fromhex(
            "36f968b94a13000e64b223576390db6bcc6d62f02617c369ee3f5b3e89df7e1f"
        ),
        rand_device=bytes.fromhex(
            "5b9b1fc6a64b2de8bece53187ee989c6566db1fc7dc8580a73dafdd6211d56a5"
        ),
        auth_value=bytes.fromhex(
            "906d73a3c7a7cb3ff730dca68a46b9c18d673f50e078202311473ebbe253669f"
        ),
    ),
    test_pdu_values=dict(
        provisioning_invite_pdu=bytes.fromhex("00"),
        provisioning_capabilities_pdu=bytes.fromhex("0100030001000000000000"),
        provisioning_start_pdu=bytes.fromhex("0100010000"),
    ),
    expected=dict(
        ecdh_secret=bytes.fromhex(
            "ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69"
        ),
        confirmation_salt=bytes.fromhex(
            "a71141ba8cb6b40f4f52b622e1c091614c73fc308f871b78ca775e769bc3ae69"
        ),
        confirmation_key=bytes.fromhex(
            "210c3c448152e8d59ef742aa7d22ee5ba59a38648bda6bf05c74f3e46fc2c0bb"
        ),
        confirmation_provisioner=bytes.fromhex(
            "c99b54617ae646f5f32cf7e1ea6fcc49fd69066078eba9580fa6c7031833e6c8"
        ),
        confirmation_device=bytes.fromhex(
            "56e3722d291373d38c995d6f942c02928c96abb015c233557d7974b6e2df662b"
        ),
        provisioning_salt=bytes.fromhex("d1cb10ad8d51286067e348fc4b692122"),
        session_key=bytes.fromhex("df4a494da3d45405e402f1d6a6cea338"),
        session_nonce=bytes.fromhex("11b987db2ae41fbb9e96b80446"),
        cipher=bytes.fromhex(
            "f9df98cbb736be1f600659ac4c37821a82db31e410a03de7693a2a0428fbdaf321"
        ),
        plaintext=bytes.fromhex("efb2255e6422d330088e09bb015ed707056700010203040b0c"),
    ),
)


@pytest.fixture(
    scope="class",
    params=[
        _BTM_ECDH_P256_CMAC_AES128_AES_CCM_values,
        _BTM_ECDH_P256_HMAC_SHA256_AES_CCM_values,
    ],
)
def crypto_manager_setup(request):
    test_values = request.param
    test_input = test_values["test_input"]
    test_pdu_values = test_values["test_pdu_values"]
    crypto_manager = ProvisioningBearerAdvCryptoManager(**test_input, test=True)

    crypto_manager.compute_confirmation_salt(**test_pdu_values)

    return (crypto_manager, test_values["expected"])


class TestProvisioningBearerAdvCryptoManager(object):
    def test_ECDH(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        assert crypto_manager.ecdh_secret == expected["ecdh_secret"]

    def test_confirmation_salt(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        assert crypto_manager.confirmation_salt == expected["confirmation_salt"]

    def test_confirmation_key(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        crypto_manager.compute_confirmation_key()
        assert crypto_manager.confirmation_key == expected["confirmation_key"]

    def test_confirmation_provisioner(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        crypto_manager.compute_confirmation_provisioner()
        assert (
            crypto_manager.confirmation_provisioner
            == expected["confirmation_provisioner"]
        )

    def test_confirmation_device(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        crypto_manager.compute_confirmation_device()
        assert crypto_manager.confirmation_device == expected["confirmation_device"]

    def test_provisioning_salt(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        crypto_manager.compute_provisioning_salt()
        assert crypto_manager.provisioning_salt == expected["provisioning_salt"]

    def test_session_key(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        crypto_manager.compute_session_key()
        assert crypto_manager.session_key == expected["session_key"]

    def test_session_nonce(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        crypto_manager.compute_session_nonce()
        assert crypto_manager.session_nonce == expected["session_nonce"]

    def test_decrypt(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        cipher = expected["cipher"][:-8]
        mic = expected["cipher"][-8:]
        assert crypto_manager.decrypt(cipher, mic) == (expected["plaintext"], True)

    def test_encrypt(self, crypto_manager_setup):
        crypto_manager, expected = crypto_manager_setup
        plaintext = expected["plaintext"]
        cipher, mic = crypto_manager.encrypt(plaintext)
        assert cipher + mic == expected["cipher"]
