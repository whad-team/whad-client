from whad.ble.crypto import LinkLayerCryptoManager, BleDirection
from whad.common.pcap import PCAPReader
from scapy.all import BTLE_DATA, BTLE

reader = PCAPReader("pcaps/comm.pcap")
for pkt in reader.packets():
    if BTLE_DATA in pkt and pkt[BTLE_DATA].len != 0:
        print(repr(pkt[BTLE]))

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
