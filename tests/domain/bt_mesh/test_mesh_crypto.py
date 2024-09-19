from whad.bt_mesh.crypto import (
    s1,
    k1,
    k2,
    k3,
    k4,
    ProvisioningBearerAdvCryptoManager,
    NetworkLayerCryptoManager,
    UpperTransportLayerAppKeyCryptoManager,
    UpperTransportLayerDevKeyCryptoManager,
)
from whad.scapy.layers.bt_mesh import (
    BTMesh_Obfuscated_Network_PDU,
    BTMesh_Network_PDU,
    BTMesh_Lower_Transport_Control_Message,
    BTMesh_Secure_Network_Beacon,
    BTMesh_Private_Beacon,
    BTMesh_Obfuscated_Private_Beacon,
)
from scapy.all import raw
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
For new test values, copy this dict, fill it with values, and add it in the params of the fixture pbadv_crypto_manager_setup below, it should use it
"""

_BTM_ECDH_P256_CMAC_AES128_AES_CCM_values = dict(
    test_input=dict(
        alg="BTM_ECDH_P256_CMAC_AES128_AES_CCM",
        private_key_provisioner=bytes.fromhex(
            "06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663"
        ),
        private_key_provisionee=None,
        public_key_coord_provisionee=(
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
        rand_provisionee=bytes.fromhex("55a2a2bca04cd32ff6f346bd0a0c1a3a"),
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
        confirmation_provisionee=bytes.fromhex("eeba521c196b52cc2e37aa40329f554e"),
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
        private_key_provisionee=bytes.fromhex(
            "529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba"
        ),
        public_key_coord_provisionee=(
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
        rand_provisionee=bytes.fromhex(
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
        confirmation_provisionee=bytes.fromhex(
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
def pbadv_crypto_manager_setup(request):
    test_values = request.param
    test_input = test_values["test_input"]
    test_pdu_values = test_values["test_pdu_values"]
    crypto_manager = ProvisioningBearerAdvCryptoManager(**test_input, test=True)

    crypto_manager.compute_confirmation_salt(**test_pdu_values)

    return (crypto_manager, test_values["expected"])


class TestProvisioningBearerAdvCryptoManager(object):
    def test_ECDH(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        assert crypto_manager.ecdh_secret == expected["ecdh_secret"]

    def test_confirmation_salt(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        assert crypto_manager.confirmation_salt == expected["confirmation_salt"]

    def test_confirmation_key(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        crypto_manager.compute_confirmation_key()
        assert crypto_manager.confirmation_key == expected["confirmation_key"]

    def test_confirmation_provisioner(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        crypto_manager.compute_confirmation_provisioner()
        assert (
            crypto_manager.confirmation_provisioner
            == expected["confirmation_provisioner"]
        )

    def test_confirmation_provisionee(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        crypto_manager.compute_confirmation_provisionee()
        assert (
            crypto_manager.confirmation_provisionee
            == expected["confirmation_provisionee"]
        )

    def test_provisioning_salt(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        crypto_manager.compute_provisioning_salt()
        assert crypto_manager.provisioning_salt == expected["provisioning_salt"]

    def test_session_key(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        crypto_manager.compute_session_key()
        assert crypto_manager.session_key == expected["session_key"]

    def test_session_nonce(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        crypto_manager.compute_session_nonce()
        assert crypto_manager.session_nonce == expected["session_nonce"]

    def test_decrypt(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        cipher = expected["cipher"][:-8]
        mic = expected["cipher"][-8:]
        assert crypto_manager.decrypt(cipher, mic) == (expected["plaintext"], True)

    def test_encrypt(self, pbadv_crypto_manager_setup):
        crypto_manager, expected = pbadv_crypto_manager_setup
        plaintext = expected["plaintext"]
        cipher, mic = crypto_manager.encrypt(plaintext)
        assert cipher + mic == expected["cipher"]


"""
Network Layer Crypto Tests
"""

_NETKEY_INPUT1 = dict(
    net_key=bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6"),
    pdus=dict(
        obf_net_pdu=(
            BTMesh_Obfuscated_Network_PDU(
                bytes.fromhex(
                    "68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df"
                )
            )
        ),
        not_obf_net_pdu=BTMesh_Network_PDU(
            ivi=0,
            nid=0x68,
            network_ctl=1,
            ttl=0,
            seq_number=1,
            src_addr=0x1201,
            enc_dst_enc_transport_pdu_mic=bytes.fromhex(
                "b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df"
            ),
        ),
        lower_transport_pdu=BTMesh_Lower_Transport_Control_Message(
            bytes.fromhex("034b50057e400000010000")
        ),
        secure_net_beacon=BTMesh_Secure_Network_Beacon(
            bytes.fromhex("003ecaff672f673370123456788ea261582f364f6f"),
        ),
    ),
    expected=dict(
        iv_index=bytes.fromhex("12345678"),  # not expected but input...
        nid=bytes.fromhex("68"),
        enc_key=bytes.fromhex("0953fa93e7caac9638f58820220a398e"),
        privacy_key=bytes.fromhex("8b84eedec100067d670971dd2aa700cf"),
        network_id=bytes.fromhex("3ecaff672f673370"),
        identity_key=bytes.fromhex("84396c435ac48560b5965385253e210c"),
        beacon_key=bytes.fromhex("5423d967da639a99cb02231a83f7d254"),
        clear_dst_addr=bytes.fromhex("fffd"),
    ),
)


@pytest.fixture(
    scope="class",
    params=[_NETKEY_INPUT1],
)
def network_crypto_manager_setup(request):
    test_values = request.param
    crypto_manager = NetworkLayerCryptoManager(
        key_index=0x00, net_key=test_values["net_key"]
    )

    return (crypto_manager, test_values["expected"], test_values["pdus"])


class TestNetworkLayerCryptoManager(object):
    def test_nid(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        assert crypto_manager.nid.to_bytes(1, "big") == expected["nid"]

    def test_enc_key(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        assert crypto_manager.enc_key == expected["enc_key"]

    def test_privacy_key(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        assert crypto_manager.privacy_key == expected["privacy_key"]

    def test_network_id(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        assert crypto_manager.network_id == expected["network_id"]

    def test_identity_key(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        assert crypto_manager.identity_key == expected["identity_key"]

    def test_beacon_key(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        assert crypto_manager.beacon_key == expected["beacon_key"]

    def test_net_deobfuscation(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        net_pdu = pdus["obf_net_pdu"]
        result = crypto_manager.deobfuscate_net_pdu(net_pdu, expected["iv_index"])
        network_ctl = (result[0]) >> 7
        ttl = result[0] & 0x7F
        seq_number = result[1:4]
        src_addr = result[4:6]
        assert raw(
            BTMesh_Network_PDU(
                ivi=expected["iv_index"][0] & 0b01,
                nid=crypto_manager.nid,
                network_ctl=network_ctl,
                ttl=ttl,
                seq_number=int.from_bytes(seq_number, "big"),
                src_addr=int.from_bytes(src_addr, "big"),
                enc_dst_enc_transport_pdu_mic=net_pdu.enc_dst_enc_transport_pdu_mic,
            )
        ) == raw(pdus["not_obf_net_pdu"])

    def test_net_obfuscation(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        obfuscated_data = crypto_manager.obfuscate_net_pdu(
            pdus["not_obf_net_pdu"], expected["iv_index"]
        )
        assert obfuscated_data == pdus["obf_net_pdu"].obfuscated_data

    def test_net_decrypt(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        net_pdu = pdus["not_obf_net_pdu"]
        plaintext, is_auth_tag_valid = crypto_manager.decrypt(
            net_pdu, expected["iv_index"]
        )
        dst_addr = plaintext[:2]
        lower_transport_pdu = BTMesh_Lower_Transport_Control_Message(plaintext[2:])
        assert (
            dst_addr == expected["clear_dst_addr"]
            and raw(lower_transport_pdu) == raw(pdus["lower_transport_pdu"])
            and is_auth_tag_valid
        )

    def test_net_encrypt(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        lower_transport_pdu = pdus["lower_transport_pdu"]
        # Need the information in the net PDU to encrypt, like address and seq_number. encrypted value not used (we dont have it in theory ...)
        net_pdu = pdus["not_obf_net_pdu"]
        enc_transport = crypto_manager.encrypt(
            raw(lower_transport_pdu),
            expected["clear_dst_addr"],
            net_pdu,
            expected["iv_index"],
        )
        assert enc_transport == net_pdu.enc_dst_enc_transport_pdu_mic

    def test_secure_net_beacon_auth_check(self, network_crypto_manager_setup):
        crypto_manager, expected, pdus = network_crypto_manager_setup
        secure_net_beacon = pdus["secure_net_beacon"]
        assert crypto_manager.check_secure_beacon_auth_value(secure_net_beacon)


"""
Mesh Private Beacon Tests (part of Network Layer crypto)
Seperated because sample data alwayes uses different net_key for this ...
"""


_PRIVATE_BEACON_INPUT1 = dict(
    net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
    iv_index=bytes.fromhex("12345679"),
    obf_private_beacon=BTMesh_Obfuscated_Private_Beacon(
        bytes.fromhex("435f18f85cf78a3121f58478a561e488e7cbf3174f022a514741")
    ),
    expected=dict(
        private_beacon_key=bytes.fromhex("6be76842460b2d3a5850d4698409f1bb"),
        private_beacon=BTMesh_Private_Beacon(
            random=bytes.fromhex("435f18f85cf78a3121f58478a5"),
            key_refresh_flag=0,
            iv_update_flag=1,
            ivi=0x1010ABCD,
            authentication_tag=bytes.fromhex("F3174F022A514741"),
        ),
    ),
)


@pytest.fixture(
    scope="class",
    params=[_PRIVATE_BEACON_INPUT1],
)
def network_crypto_manager_setup_private_beacon(request):
    test_values = request.param
    crypto_manager = NetworkLayerCryptoManager(
        key_index=0x00, net_key=test_values["net_key"]
    )

    return (crypto_manager, test_values["expected"], test_values["obf_private_beacon"])


class TestNetworkLayerCryptoManagerPrivateBeacon:
    def test_private_beacon_key(self, network_crypto_manager_setup_private_beacon):
        crypto_manager, expected, obf_private_beacon = (
            network_crypto_manager_setup_private_beacon
        )
        assert expected["private_beacon_key"] == crypto_manager.private_beacon_key

    def test_private_beacon_deobfuscate(
        self, network_crypto_manager_setup_private_beacon
    ):
        crypto_manager, expected, obf_private_beacon = (
            network_crypto_manager_setup_private_beacon
        )
        private_beacon_data, is_auth_tag_valid = (
            crypto_manager.deobfuscate_private_beacon(obf_private_beacon)
        )
        result_packet = BTMesh_Private_Beacon(
            random=obf_private_beacon.random,
            key_refresh_flag=private_beacon_data[0] & 0b01,
            iv_update_flag=(private_beacon_data[0] >> 1) & 0b01,
            ivi=int.from_bytes(private_beacon_data[1:], "big"),
            authentication_tag=obf_private_beacon.authentication_tag,
        )
        assert (
            raw(result_packet) == raw(expected["private_beacon"]) and is_auth_tag_valid
        )

    def test_private_beacon_obfuscation(
        self, network_crypto_manager_setup_private_beacon
    ):
        crypto_manager, expected, obf_private_beacon = (
            network_crypto_manager_setup_private_beacon
        )
        clear_private_beacon = expected["private_beacon"]
        random, obfuscated_private_data, authentication_tag = (
            crypto_manager.obfuscate_private_beacon(
                clear_private_beacon, random=clear_private_beacon.random
            )
        )
        private_beacon = BTMesh_Obfuscated_Private_Beacon(
            random=random,
            obfuscated_private_beacon_data=obfuscated_private_data,
            authentication_tag=authentication_tag,
        )
        assert obf_private_beacon == private_beacon


"""
UpperLayerAppKeyCrypto Tests
One input = one app key and one message with associated data
Input is encrypted -> plaintext but since we do it in both direction it's just a convention.
Expected is just raw plaintext
"""


__APP_KEY_INPUT1 = dict(
    # Mesh Spec Section 8.3.18
    app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
    test_input=dict(
        enc_data=bytes.fromhex("5a8bde6d9106ea078a"),
        iv_index=bytes.fromhex("12345678"),
        seq_number=bytes.fromhex("000007"),
        src_addr=bytes.fromhex("1201"),
        dst_addr=bytes.fromhex("ffff"),
        aszmic=bytes.fromhex("00"),
        # first one is the one we want to match in the list
        label_uuid=None,
    ),
    expected=bytes.fromhex("0400000000"),
)
__APP_KEY_INPUT2 = dict(
    # Mesh Spec Section 8.3.23
    app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
    test_input=dict(
        enc_data=bytes.fromhex("2456db5e3100eef65daa7a38"),
        iv_index=bytes.fromhex("12345677"),
        seq_number=bytes.fromhex("07080c"),
        src_addr=bytes.fromhex("1234"),
        dst_addr=bytes.fromhex("9736"),
        aszmic=bytes.fromhex("00"),
        # first one is the one we want to match in the list
        label_uuid=[bytes.fromhex("f4a002c7fb1e4ca0a469a021de0db875")],
    ),
    expected=bytes.fromhex("d50a0048656c6c6f"),
)


@pytest.fixture(
    scope="class",
    params=[__APP_KEY_INPUT1, __APP_KEY_INPUT2],
)
def upper_layer_app_key_setup_crypto_manager(request):
    test_values = request.param
    crypto_manager = UpperTransportLayerAppKeyCryptoManager(
        app_key=test_values["app_key"]
    )

    return (crypto_manager, test_values["test_input"], test_values["expected"])


class TestUpperLayerAppKeyCryptoManager:
    def test_decrypt(self, upper_layer_app_key_setup_crypto_manager):
        crypto_manager, test_input, expected = upper_layer_app_key_setup_crypto_manager
        plaintext, is_mic_ok, label_uuid = crypto_manager.decrypt(
            test_input["enc_data"],
            test_input["aszmic"],
            test_input["seq_number"],
            test_input["src_addr"],
            test_input["dst_addr"],
            test_input["iv_index"],
            test_input["label_uuid"],
        )
        if test_input["label_uuid"] is not None:
            assert (plaintext, is_mic_ok, label_uuid) == (
                expected,
                True,
                test_input["label_uuid"][0],
            )
        else:
            assert (plaintext, is_mic_ok, label_uuid) == (expected, True, None)

    def test_encrypt(self, upper_layer_app_key_setup_crypto_manager):
        crypto_manager, test_input, expected = upper_layer_app_key_setup_crypto_manager
        if test_input["label_uuid"] is not None:
            enc_data, seq_auth = crypto_manager.encrypt(
                expected,
                test_input["aszmic"],
                test_input["seq_number"],
                test_input["src_addr"],
                test_input["dst_addr"],
                test_input["iv_index"],
                test_input["label_uuid"][0],
            )
        else:
            enc_data, seq_auth = crypto_manager.encrypt(
                expected,
                test_input["aszmic"],
                test_input["seq_number"],
                test_input["src_addr"],
                test_input["dst_addr"],
                test_input["iv_index"],
            )
        assert enc_data == test_input["enc_data"]


__DEV_KEY_INPUT1 = dict(
    # Mesh Spec Section 8.12.1
    device_key=bytes.fromhex("9d6dd0e96eb25dc19a40ed9914f8f03f"),
    test_input=dict(
        enc_data=bytes.fromhex("18b0b6618b2b"),
        iv_index=bytes.fromhex("12345678"),
        seq_number=bytes.fromhex("df0410"),
        src_addr=bytes.fromhex("0405"),
        dst_addr=bytes.fromhex("0607"),
        aszmic=bytes.fromhex("00"),
    ),
    expected=bytes.fromhex("80b1"),
)


@pytest.fixture(
    scope="class",
    params=[__DEV_KEY_INPUT1],
)
def upper_layer_dev_key_setup_crypto_manager(request):
    test_values = request.param
    crypto_manager = UpperTransportLayerDevKeyCryptoManager(
        device_key=test_values["device_key"]
    )

    return (crypto_manager, test_values["test_input"], test_values["expected"])


class TestUpperLayerDevKeyCryptoManager:
    def test_decrypt(self, upper_layer_dev_key_setup_crypto_manager):
        crypto_manager, test_input, expected = upper_layer_dev_key_setup_crypto_manager
        plaintext, is_mic_ok = crypto_manager.decrypt(
            test_input["enc_data"],
            test_input["aszmic"],
            test_input["seq_number"],
            test_input["src_addr"],
            test_input["dst_addr"],
            test_input["iv_index"],
        )
        assert (plaintext, is_mic_ok) == (expected, True)

    def test_encrypt(self, upper_layer_dev_key_setup_crypto_manager):
        crypto_manager, test_input, expected = upper_layer_dev_key_setup_crypto_manager
        enc_data, seq_auth = crypto_manager.encrypt(
            expected,
            test_input["aszmic"],
            test_input["seq_number"],
            test_input["src_addr"],
            test_input["dst_addr"],
            test_input["iv_index"],
        )
        assert enc_data == test_input["enc_data"]
