from whad.bt_mesh.crypto import *
from Cryptodome.Cipher import AES

from whad.scapy.layers.bt_mesh import BTMesh_Mesh_Message, BTMesh_Lower_Transport_PDU
from struct import pack

network_key = bytes.fromhex("89C9EEB8937937E1AD6E22B1563B38D0")
app_key = bytes.fromhex("7445ECB9476F8940801A236098AE4107")

bt_mesh_message1 = bytes.fromhex("16dab328c2307e0562cac96062d309f0865d892620a4")
output = k2(network_key, bytes.fromhex("00"))
print(output.hex())
print()

nid, enc_key, privacy_key = output[0], output[1:17], output[17:]
def deobfuscate(encrypted_message, privacy_key, iv_index=bytes.fromhex("00000000")):
    privacy_random = encrypted_message[7:7+7]
    privacy_plaintext = b"\x00" * 5 + iv_index +  privacy_random
    pecb = e(privacy_key,privacy_plaintext)
    obfuscated_random = encrypted_message[1:7]
    return bytes([pecb[i] ^ obfuscated_random[i] for i in range(6)])


def generate_network_nonce(unobfuscated_header, iv_index):
    return b"\x00" + unobfuscated_header + b"\x00\x00" + iv_index

def generate_application_nonce(network_header, iv_index, segmented=False):
    nonce = b"\x01" + pack('B', (int(segmented) << 7)) + network_header + iv_index
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
        #assoc_len=len(header)
    )
    #cipher.update(header)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext.hex())
    try:
        cipher.verify(mic)
        return True, plaintext
    except ValueError:
        return False, plaintext

def application_decrypt(message,iv_index, network_header, app_key):
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
ok, plaintext1 = network_decrypt(bt_mesh_message1[7:], deobfuscate1, bytes.fromhex("00000000"), enc_key)
if ok:
    print("decrypt1",(bt_mesh_message1[0:1] + deobfuscate1 + plaintext1 + bt_mesh_message1[-4:]).hex())

    app_encrypted1 = plaintext1[2:][1:]
    ok, app_plaintext1 = application_decrypt(app_encrypted1, bytes.fromhex("00000000"), (deobfuscate1 + plaintext1)[1:1+7], app_key)
    if ok:
        decrypted_pkt1 = bt_mesh_message1[0:1] + deobfuscate1 + plaintext1[:3] + app_plaintext1 + plaintext1[-4:] + bt_mesh_message1[-4:]
        print("> ", decrypted_pkt1.hex())

        pkt1 = BTMesh_Mesh_Message(decrypted_pkt1)
        pkt1.show()
    #print("app_plaintext:", (plaintext1[2:][0:1] + app_plaintext1).hex())
    '''
    lower_transport_pdu = BTMesh_Mesh_Message(
        bt_mesh_message1[0:1] + deobfuscate1 + plaintext1 + bt_mesh_message1[-4:]
    ) / BTMesh_Lower_Transport_PDU(plaintext1[2:][0:1] + app_plaintext1)
    lower_transport_pdu.show()
    '''
