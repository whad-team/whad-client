import binascii
from struct import pack
from Cryptodome.Cipher import AES
from whad.scapy.layers.wirelesshart import (
    WirelessHart_DataLink_Hdr, 
    WirelessHart_Network_Hdr, 
    WirelessHart_Network_Security_SubLayer_Hdr
)

# Configuration du paquet
b"\\xfd\x1dm,\\xa8N\\x96\x057\x1fD\\xc3\ny\\xdc\x0"
hdr = "3f017d121b0001fffff98000010009ffffffff000441fdf5a19de3104e4b1517aec7a9ffa6760ac1e9194faf756bca"
pkt = WirelessHart_DataLink_Hdr(bytes.fromhex(hdr))
key_broadcast = binascii.unhexlify("695e027941b1ad9158f3c30083de8ccc")

def decrypt_nwk_corrected(pkt, key, full_asn):
    # 1. Extraction du MIC (Little Endian pour WirelessHART)
    mic = pack("<I", pkt.nwk_mic)
    
    # 2. Préparation de l'Auth Data (AAD)
    auth_pkt = pkt.copy()
    auth_pkt.ttl = 0  
    auth_pkt.nwk_mic = 0 
    # L'AAD couvre le NWK Header et le SEC Header (sans le MIC)
    auth_data = bytes(auth_pkt[WirelessHart_Network_Hdr])[:15] 

    # 3. Payload chiffré
    encrypted_payload = bytes(pkt[WirelessHart_Network_Security_SubLayer_Hdr].payload)

    # 4. Construction du Nonce (13 octets)
    # Format: Addr(2) + ASN(5) + Counter(1) + Padding(5)
    nonce = bytearray(13)
    nonce[0:2] = pack('<H', pkt.nwk_src_addr) 
    nonce[2:7] = pack('<Q', full_asn)[:5]      
    nonce[7] = pkt.counter                     
    
    try:
        cipher = AES.new(key, AES.MODE_CCM, nonce=bytes(nonce), mac_len=4)
        cipher.update(auth_data)
        decrypted = cipher.decrypt_and_verify(encrypted_payload, mic)
        return decrypted
    except ValueError:
        return None

# --- BOUCLE DE BRUTE-FORCE ---
# On boucle sur les 3 octets de poids forts possibles (2^24)
# Le full_asn est : (i << 16) | snippet
snippet = 0x121b
print(f"🚀 Début du brute-force ASN pour le snippet {hex(snippet)}...")

for i in range(0x1000000): # 2^24
    current_asn = (i << 16) | snippet
    res = decrypt_nwk_corrected(pkt, key_broadcast, current_asn)
    
    if res:
        print("\n" + "="*40)
        print(f"🎯 MATCH TROUVÉ !")
        print(f"ASN complet : {hex(current_asn)} (Décimal: {current_asn})")
        print(f"Payload déchiffré : {res.hex()}")
        print("="*40)
        break
    
    # Indicateur de progression tous les 100 000 tests
    if i % 100000 == 0:
        print(f"⏳ Test en cours... Poids forts actuels: {hex(i)}")
# 1. On sépare Dot15d4 de Zigbee (on casse la liaison par défaut)
# Cela empêche l'apparition des couches "Zigbee Network Layer"
split_layers(Dot15d4Data, WirelessHart_DataLink_Hdr)

# 2. On lie Dot15d4 explicitement à WirelessHART
bind_layers(Dot15d4Data, WirelessHart_DataLink_Hdr)

# 3. Maintenant, on parse le paquet



addr = 0xf980
start_byte = b"\x00"
counter = 4
'''
if pkt.nwk_mic == 0x5e1e025c:
    counter = (((3 + 128 - pkt.counter) & 0xFFFFFF) << 8) | pkt.counter
'''
nonce = start_byte + pack('>I', counter) + pack('>Q', addr)

print(nonce)
print(len(b'i^\x02yA\xb1\xad\x91X\xf3\xc3\x00\x83\xde\x8c\xcc'))
"""WirelessHartDecryptor>

  Join Key       : b'ABCDABCDABCDABCD'

  Network Key    : b'9*\xed\xc7\xedVi\xf4\xa2\xde\xfc\x15\x9b\x9a|\xa4'

  Unicast Sessions Keys:

    id1=9, id2=63872, nonce=9 -> b'\x19t\xe1\xd3/U\xfbP\xd2\x13Q\xbf\xd7\xe0pe'

    id1=63873, id2=9, nonce=4 -> b'\x14h\x8dRf#\xe4\xf8\xe5\xa9\xf4"\x06Nt6'

  Broadcast Sessions Keys:

    id1=65535, id2=63872, nonce=4 -> b'i^\x02yA\xb1\xad\x91X\xf3\xc3\x00\x83\xde\x8c\xcc'

    id1=65535, id2=63873, nonce=1 -> b'\x12\xdf=\x8d\xf7\xf7\x90\x12\x12\xe7h\xa1U\xe2yH'

  Join Sessions Keys:

    (empty) """
pkt = "418844cd04ffff09003f017d121b0001fffff98000010009ffffffff000441fdf5a19de3104e4b1517aec7a9ffa6760ac1e9194faf756bca"
pkt = Dot15d4FCS(bytes.fromhex(pkt))
#pkt.show()

def decrypt_nwk2(pkt, key):
    mic = pack(">I", pkt.nwk_mic)
    
    encrypted_pkt = copy(pkt)
    encrypted_pkt.counter = 0
    encrypted_pkt.ttl = 0
    encrypted_pkt.nwk_mic = 0
    
    auth = bytes(encrypted_pkt[WirelessHart_Network_Hdr])
    encrypted_payload = bytes(encrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr][1:])
    auth = auth[:len(auth) - len(encrypted_payload)]
    
    try:
        if pkt.security_types == 1:
            if pkt.nwk_src_addr == 0xf980:
                addr = pkt.nwk_dest_addr
                start_byte = b"\x01"
            else:
                addr = pkt.nwk_src_addr
                start_byte = b"\x00"
            nonce = start_byte + pack('>I', pkt.counter) + pack('>Q', addr)
        else:

            addr = pkt.nwk_src_addr
            start_byte = b"\x00"
            #addr = pkt.nwk_src_addr
            #start_byte = b"\x00"
            nonce = start_byte + pack('>I', pkt.counter) + pack('>Q', addr)

        '''
        print("[i] Decryption (NWK)")
        print("    * key  : ", key.hex())
        print("    * data : ", encrypted_payload.hex())
        print("    * auth : ", auth.hex())
        print("    * nonce: ", nonce.hex())
        '''
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(auth)
        decrypted = cipher.decrypt_and_verify(encrypted_payload, received_mac_tag=mic)

        print("[i] Decryption success ! ({})".format(key.hex()))
        print("    * decr:  ", decrypted.hex())
        print()

        return decrypted
    except ValueError:
        #print("[e] Decryption failure - incorrect MIC (recv:", mic.hex(), ")")
        #print(  repr(pkt))
        return None
    


""""""