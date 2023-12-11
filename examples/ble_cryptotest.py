from whad.ble.crypto import LinkLayerCryptoManager, BleDirection
from whad.common.pcap import PCAPReader
from scapy.all import BTLE_DATA, BTLE, BTLE_ADV, BTLE_CONNECT_REQ
from whad.ble.crypto import EncryptedSessionInitialization, LegacyPairingCracking

from Cryptodome.Cipher import AES

'''
random = bytes.fromhex("abb692ebfd4601f4aad3aea40f7da5fc")[::-1]
pairingRequest = bytes.fromhex("01030005100001")[::-1]
pairingResponse = bytes.fromhex("02000005100001")[::-1]
initiatorAddress = "08:3E:8E:E1:0B:3E"
initiatorAddressType = b"\x00"
responderAddress = "78:C5:E5:6E:DD:E8"
responderAddressType = b"\x00"

xor = lambda a1,b1 : bytes([a ^ b for a, b in zip(a1,b1)])
confirm = bytes.fromhex("febb983ed78020e13d685bc8418d2c5d")[::-1]
#tk = pack(">IIII", 0,0,0,i)
#print(tk.hex())
tk = b"\x00"*16
p1 = pairingResponse + pairingRequest + (responderAddressType + initiatorAddressType
    #(b"\x01" if responderAddress.is_random() else b"\x00") +
    #(b"\x01" if initiatorAddress.is_random() else b"\x00")
)
#print(self.initiator.value.hex(), self.responder.value.hex())
p2 = b"\x00\x00\x00\x00" + bytes.fromhex(initiatorAddress.replace(":", ""))  + bytes.fromhex(responderAddress.replace(":", ""))
print("p1", p1.hex(), "p2", p2.hex())

a = xor(p1, random)
aes = AES.new(tk, AES.MODE_ECB)
res1 = aes.encrypt(a)
b = xor(res1, p2)
res2 = aes.encrypt(b)
print(res2.hex(), confirm[::-1].hex())
if res2 == confirm:
    print("success", 0)
    #break

#exit()
'''
reader = PCAPReader("ressources/pcaps/pairing.pcap")
c = LegacyPairingCracking()
for pkt in reader.packets(accurate=False):
    if c.ready:
        print(c.key)
        break
    if BTLE_DATA in pkt and pkt[BTLE_DATA].len != 0:
        print(repr(pkt[BTLE_DATA]))
        c.process_packet(pkt)
    elif BTLE_ADV in pkt:
        print(repr(pkt[BTLE_ADV]))
        c.process_packet(pkt)


'''
t = EncryptedSessionInitialization()
d = BLEDecryptor(bytes.fromhex("0e0596ef16cf17cc48357ee19da96728"))
reader = PCAPReader("ressources/pcaps/comm.pcap")
for pkt in reader.packets():
    #print(repr(pkt[BTLE]))
    if BTLE_DATA in pkt and pkt[BTLE_DATA].len != 0:
        print(repr(pkt[BTLE_DATA]))
        t.process_packet(pkt[BTLE_DATA])
        if t.encryption:
            d.add_crypto_material(*t.crypto_material)
            decrypted, success = d.attempt_to_decrypt(pkt[BTLE])
            pkt.decrypted = decrypted
            print("Decrypted: ", pkt.decrypted)
'''
'''
traffic = [
(("0305a312e94e96", BleDirection.SLAVE_TO_MASTER, (0,0)), "030506"),
(("0b059eec5f7e46", BleDirection.MASTER_TO_SLAVE, (0,0)), "0b0506"),
(("061968e902ed48929443786d310f3615ac89eba52480351effdfc0", BleDirection.MASTER_TO_SLAVE, (1,1)), "0619110006000653c3a27f513832bcbc54c4f2ff50c002"),

]
for test_input, expected in traffic:

    ltk = bytes.fromhex("0faebfbf3146fb8edbc3a33a01cceee9")
    master_skd = 0x2e811dd81866c7f4#0x7d027501426377a9
    master_iv = 0x0eaf61c4
    slave_skd = 0xecec425cf357d6d1#0x102c2869b542e91c
    slave_iv = 0x24bb0a5e
    llcm = LinkLayerCryptoManager(ltk, master_skd, master_iv, slave_skd,slave_iv)
    ciphertext, direction, (master_counter, slave_counter) = test_input
    ciphertext = bytes.fromhex(ciphertext)
    expected = bytes.fromhex(expected)
    llcm.update_master_counter(master_counter)
    llcm.update_slave_counter(slave_counter)
    result,valid = llcm.decrypt(ciphertext,direction)
    print(result.hex(), result == expected, valid)
    llcm_ciphertext = llcm.encrypt(result,direction)
    print(">", llcm_ciphertext.hex())
    #assert valid and result == expected and llcm_ciphertext == ciphertext
'''
