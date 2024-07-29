from whad.bt_mesh.crypto import *
from Cryptodome.Cipher import AES

from whad.scapy.layers.bt_mesh import BTMesh_Mesh_Message, BTMesh_Lower_Transport_PDU
from whad.bt_mesh.crypto import ProvisioningBearerAdvCryptoManager
from whad.ble.crypto import generate_public_key_from_coordinates
from struct import pack


"""
network_key = bytes.fromhex("89C9EEB8937937E1AD6E22B1563B38D0")
app_key = bytes.fromhex("7445ECB9476F8940801A236098AE4107")

bt_mesh_message1 = bytes.fromhex("16dab328c2307e0562cac96062d309f0865d892620a4")
output = k2(network_key, bytes.fromhex("00"))
print(output.hex())
print()

nid, enc_key, privacy_key = output[0], output[1:17], output[17:]


def deobfuscate(encrypted_message, privacy_key, iv_index=bytes.fromhex("00000000")):
    privacy_random = encrypted_message[7 : 7 + 7]
    privacy_plaintext = b"\x00" * 5 + iv_index + privacy_random
    pecb = e(privacy_key, privacy_plaintext)
    obfuscated_random = encrypted_message[1:7]
    return bytes([pecb[i] ^ obfuscated_random[i] for i in range(6)])


def generate_network_nonce(unobfuscated_header, iv_index):
    return b"\x00" + unobfuscated_header + b"\x00\x00" + iv_index


def generate_application_nonce(network_header, iv_index, segmented=False):
    nonce = b"\x01" + pack("B", (int(segmented) << 7)) + network_header + iv_index
    print(nonce.hex())
    return nonce


def network_decrypt(message, unobfuscated_header, iv_index, encryption_key):
    ciphertext, mic = message[:-4], message[-4:]
    print(ciphertext.hex(), mic.hex())
    cipher = AES.new(
        encryption_key,
        AES.MODE_CCM,
        nonce=generate_network_nonce(unobfuscated_header, iv_index),
        mac_len=4,
        # assoc_len=len(header)
    )
    # cipher.update(header)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext.hex())
    try:
        cipher.verify(mic)
        return True, plaintext
    except ValueError:
        return False, plaintext


def application_decrypt(message, iv_index, network_header, app_key):
    ciphertext, mic = message[:-4], message[-4:]
    cipher = AES.new(
        app_key,
        AES.MODE_CCM,
        nonce=generate_application_nonce(network_header, iv_index),
        mac_len=4,
    )
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(mic)
        return True, plaintext
    except ValueError:
        return False, plaintext


deobfuscate1 = deobfuscate(bt_mesh_message1, privacy_key)
print(deobfuscate1.hex())
ok, plaintext1 = network_decrypt(
    bt_mesh_message1[7:], deobfuscate1, bytes.fromhex("00000000"), enc_key
)
if ok:
    print(
        "decrypt1",
        (
            bt_mesh_message1[0:1] + deobfuscate1 + plaintext1 + bt_mesh_message1[-4:]
        ).hex(),
    )

    app_encrypted1 = plaintext1[2:][1:]
    ok, app_plaintext1 = application_decrypt(
        app_encrypted1,
        bytes.fromhex("00000000"),
        (deobfuscate1 + plaintext1)[1 : 1 + 7],
        app_key,
    )
    if ok:
        decrypted_pkt1 = (
            bt_mesh_message1[0:1]
            + deobfuscate1
            + plaintext1[:3]
            + app_plaintext1
            + plaintext1[-4:]
            + bt_mesh_message1[-4:]
        )
        print("> ", decrypted_pkt1.hex())

        pkt1 = BTMesh_Mesh_Message(decrypted_pkt1)
        pkt1.show()
    # print("app_plaintext:", (plaintext1[2:][0:1] + app_plaintext1).hex())


    #lower_transport_pdu = BTMesh_Mesh_Message(
    #    bt_mesh_message1[0:1] + deobfuscate1 + plaintext1 + bt_mesh_message1[-4:]
    #) / BTMesh_Lower_Transport_PDU(plaintext1[2:][0:1] + app_plaintext1)
    #lower_transport_pdu.show()
"""

"""
Provisioning Decrypt Test
From Model Prototol Specification, p. 705, Section 8.7
Using BTM_ECDH_P256_CMAC_AES128_AES_CCM
"""

prov_private_key = bytes.fromhex(
    "06a516693c9aa31a6084545d0c5db641b48572b97203ddffb7ac73f7d0457663"
)
prov_public_key_coord = (
    bytes.fromhex("2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd"),
    bytes.fromhex("919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f"),
)
device_private_key_coord = bytes.fromhex(
    "529aa0670d72cd6497502ed473502b037e8803b5c60829a5a3caa219505530ba"
)
device_public_key_coord = (
    bytes.fromhex("f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc"),
    bytes.fromhex("0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279"),
)

# Using P256R1 curve
device_public_key = generate_public_key_from_coordinates(
    int.from_bytes(device_public_key_coord[0], "big"),
    int.from_bytes(device_public_key_coord[1], "big"),
)

prov_public_key = generate_public_key_from_coordinates(
    int.from_bytes(prov_public_key_coord[0], "big"),
    int.from_bytes(prov_public_key_coord[1], "big"),
)


prov_random = bytes.fromhex("8b19ac31d58b124c946209b5db1021b9")
device_random = bytes.fromhex("55a2a2bca04cd32ff6f346bd0a0c1a3a")
auth_value = bytes.fromhex("00000000000000000000000000000000")


invite_pdu_value = bytes.fromhex("00")
capabilities_pdu_value = bytes.fromhex("0100010000000000000000")
start_pdu_value = bytes.fromhex("0000000000")
expected_confirmation_inputs = bytes.fromhex(
    "00010001000000000000000000000000002c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4ff465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279"
)
expected_confirmation_salt = bytes.fromhex("5faabe187337c71cc6c973369dcaa79a")
expected_ecdh_secret = bytes.fromhex(
    "ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69"
)
expected_provisioning_salt = bytes.fromhex("a21c7d45f201cf9489a2fb57145015b4")
expected_confirmation_key = bytes.fromhex("e31fe046c68ec339c425fc6629f0336f")
expected_confirmation_provisioner = bytes.fromhex("b38a114dfdca1fe153bd2c1e0dc46ac2")
expected_confirmation_device = bytes.fromhex("eeba521c196b52cc2e37aa40329f554e")


expected_session_key = bytes.fromhex("c80253af86b33dfa450bbdb2a191fea3")
expected_session_nonce = bytes.fromhex("da7ddbe78b5f62b81d6847487e")


# data + mic
ciphered_prov_data = bytes.fromhex(
    "d0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec2973e0ec50783b10c7"
)
plaintext_prov_data = bytes.fromhex(
    "efb2255e6422d330088e09bb015ed707056700010203040b0c"
)

crypto_manager = ProvisioningBearerAdvCryptoManager(
    alg="BTM_ECDH_P256_CMAC_AES128_AES_CCM",
    private_key_provisioner=prov_private_key,
    public_key_coord_device=device_public_key_coord,
    public_key_coord_provisioner=prov_public_key_coord,
    rand_provisioner=prov_random,
    rand_device=device_random,
    auth_value=auth_value,
)

crypto_manager.compute_confirmation_salt(
    invite_pdu_value, capabilities_pdu_value, start_pdu_value
)

print("Expected ECDH secret : " + expected_ecdh_secret.hex())
print("Computed ECDH secret : " + crypto_manager.ecdh_secret.hex())

print("Expected confirmation salt : " + expected_confirmation_salt.hex())
print("Computed confirmation salt : " + crypto_manager.confirmation_salt.hex())

crypto_manager.compute_confirmation_key()

print("Expected confirmation key : " + expected_confirmation_key.hex())
print("Computed confirmation key : " + crypto_manager.confirmation_key.hex())

crypto_manager.compute_confirmation_provisioner()

print("Expected confirmation provisioner : " + expected_confirmation_provisioner.hex())
print(
    "Computed confirmation provisioner : "
    + crypto_manager.confirmation_provisioner.hex()
)

crypto_manager.compute_confirmation_device()

print("Expected confirmation device : " + expected_confirmation_device.hex())
print("Computed confirmation device : " + crypto_manager.confirmation_device.hex())

crypto_manager.compute_provisioning_salt()

print("Expected Provisioning salt : " + expected_provisioning_salt.hex())
print("Computed Provisioning salt : " + crypto_manager.provisioning_salt.hex())

crypto_manager.compute_session_key()

print("Expected Session key : " + expected_session_key.hex())
print("Computed Session key : " + crypto_manager.session_key.hex())

crypto_manager.compute_session_nonce()

print("Expected Session nonce : " + expected_session_nonce.hex())
print("Computed Session nonce : " + crypto_manager.session_nonce.hex())


comptuted_plaintext, verification_mic = crypto_manager.decrypt(ciphered_prov_data)
comptuted_cipher = crypto_manager.encrypt(plaintext_prov_data)

print("Expected cipher : " + ciphered_prov_data.hex())
print("Computed cipher : " + comptuted_cipher.hex())
print("Has passed mic verif ? : " + str(verification_mic))

print("Expected plaintext : " + plaintext_prov_data.hex())
print("Computed plaintext : " + comptuted_plaintext.hex())
