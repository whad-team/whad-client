"""LoRaWAN 1.0 cryptographic primitives

This module provides multiple cryptographic primitives as specified
in the LoRaWAN 1.0 specifications, including various MIC computations,
key derivation and frame encryption/decryption.
"""
from struct import pack, unpack
from scapy.packet import Raw
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from whad.scapy.layers.lorawan import PHYPayload, MACPayloadDownlink, MACPayloadUplink
from whad.lorawan.exceptions import BadMICError, MissingKeyError

def MIC(key : bytes, buffer : bytes) -> bytes:
    """Compute LoRaWAN MIC for PHY layer

    :param key: 128-bit key to use for MIC computation
    :type key: bytes
    :returns: 
    """
    c = CMAC.new(key, ciphermod=AES)
    c.update(buffer)
    return c.digest()[:4]


def MIC_Uplink(key : bytes, dev_addr : int, fcnt : int, frame : bytes) -> bytes:
    """Compute uplink frame MIC

    :param key: Encryption key (depends on external conditions)
    :type key: bytes
    :param dev_addr: Device network address
    :type dev_addr: int
    :param fcnt: Current uplink frame counter
    :type fcnt: int
    :param frame: Frame used to generate the corresponding MIC
    :type frame: bytes
    :return: 4-byte message integrity code
    :rtype: bytes
    """
    b0 = pack('<BIBIIBB', 0x49, 0, 0, dev_addr, fcnt, 0, len(frame))
    return MIC(key, b0 + frame)

def MIC_Downlink(key : bytes, dev_addr : int, fcnt : int, frame : bytes) -> bytes:
    """Compute downlink frame MIC

    :param key: Encryption key (depends on external conditions)
    :type key: bytes
    :param dev_addr: Device network address
    :type dev_addr: int
    :param fcnt: Current downlink frame counter
    :type fcnt: int
    :param frame: Frame used to generate the corresponding MIC
    :type frame: bytes
    :return: 4-byte message integrity code
    :rtype: bytes
    """
    b0 = pack('<BIBIIBB', 0x49, 0, 1, dev_addr, fcnt, 0, len(frame))
    return MIC(key, b0 + frame)


def pad16(data : bytes) -> bytes:
    """Pad data to fit 16-byte multiple length.

    :param data: Data to pad
    :type data: bytes
    :return: 16-byte padded data
    :rtype: bytes
    """
    r = len(data)%16
    if r > 0:
        return data + b'\x00'*(16 - r)
    else:
        return data


def derive_nwkskey(appkey : bytes, join_nonce : int, netid : int, dev_nonce : int) -> bytes:
    """Derive NwkSKey from AppKey, Join and Dev nonces, Network ID

    :param appkey: Application Key
    :type appkey: bytes
    :param join_nonce: Join nonce
    :type join_nonce: int
    :param netid: Network ID
    :type netid: int
    :param dev_nonce: Device nonce
    :type dev_nonce: int
    :return: Derived network session encryption key
    :rtype: bytes
    """
    c = AES.new(appkey, mode=AES.MODE_ECB)
    buffer = b'\x01' + pack('<BHBHH', join_nonce&0xff, (join_nonce>>8)&0xffff, netid&0xff, (netid>>8)&0xffff , dev_nonce)
    return c.encrypt(pad16(buffer))



def derive_appskey(appkey : bytes, join_nonce : int, netid : int, dev_nonce : int) -> bytes:
    """Derive AppSKey from AppKey, Join and Dev nonces, Network ID

    :param appkey: Application Key
    :type appkey: bytes
    :param join_nonce: Join nonce
    :type join_nonce: int
    :param netid: Network ID
    :type netid: int
    :param dev_nonce: Device nonce
    :type dev_nonce: int
    :return: Derived application session key
    :rtype: bytes
    """
    c = AES.new(appkey, mode=AES.MODE_ECB)
    buffer = b'\x02' + pack('<BHBHH', join_nonce&0xff, (join_nonce>>8)&0xffff, netid&0xff, (netid>>8)&0xffff , dev_nonce)
    return c.encrypt(pad16(buffer))


def encrypt_frame(key : bytes, dev_addr : int, fcnt : int, frame : bytes, uplink : bool = True) -> bytes:
    """Encrypt a MAC frame with the provided key.

    :param key: Encryption/decryption key.
    :type key: bytes
    :param dev_addr: Device address
    :type dev_addr: int
    :param fcnt: Frame counter
    :type fcnt: int
    :param frame: Frame to encrypt or decrypt
    :type frame: bytes
    :param uplink: Uplink frame if True, downlink frame otherwise
    :type uplink: bool

    :return: Encrypted or decrypted frame
    :rtype: bytes
    """
    # Compute number of Ai blocks to generate
    frame_length = len(frame)
    nb_blocks = int(frame_length / 16)
    if frame_length % 16 > 0:
        nb_blocks += 1

    # Generate Ai blocks
    ai_blocks = []
    for i in range(nb_blocks):
        ai_blocks.append(pack('<BIBIIBB', 1, 0, 0 if uplink else 1, dev_addr,
                              fcnt, 0, i+1))
    
    # Generate our keystream
    c = AES.new(key,mode=AES.MODE_ECB)
    ks = b''
    for ai in ai_blocks:
        ks += c.encrypt(ai)

    # XOR our frame with our keystream
    output = b''
    for i in range(frame_length):
        output += bytes([frame[i] ^ ks[i]])
    
    # Return the result
    return output

def encrypt_fopts(key : bytes, dev_addr : int, fcnt : int, fopts : bytes, uplink : bool = True) -> bytes:
    """Encrypt a MAC frame with the provided key.

    :param key: Encryption/decryption key.
    :type key: bytes
    :param dev_addr: Device address
    :type dev_addr: int
    :param fcnt: Frame counter
    :type fcnt: int
    :param frame: Frame to encrypt or decrypt
    :type frame: bytes
    :param uplink: Uplink frame if True, downlink frame otherwise
    :type uplink: bool

    :return: Encrypted or decrypted frame options
    :rtype: bytes
    """

    # Generate A block
    ai_block = pack('<BIBIIBB', 1, 0, 0 if uplink else 1, dev_addr, fcnt, 0, 0)
    
    # Generate our keystream
    c = AES.new(key,mode=AES.MODE_ECB)
    ks = c.encrypt(ai_block)

    # XOR our frame with our keystream
    output = b''
    for i in range(len(fopts)):
        output += bytes([fopts[i] ^ ks[i]])
    
    # Return the result
    return output    

def decrypt_packet(packet : PHYPayload, appkey=None, appskey=None, nwkskey=None) -> PHYPayload:
    """Decrypt a LoRaWAN PHY payload given the provided keys.

    :param packet: LoRaWAN packet to decrypt
    :type packet: PHYPayload
    :param appkey: LoRaWAN Application Key
    :type appkey: bytes
    :param appskey: LoRaWAN Application Session Key
    :type appskey: bytes
    :param nwkskey: LoRaWAN Network Session Key

    :raises BadMICError: Incorrect MIC detected
    :raises MissingKeyError: A required encryption key is missing

    :return: decrypted LoRaWAN PHY packet
    :rtype: PHYPayload
    """
    if packet.mtype == 0x01:
        # Join Accept packet is encrypted with the appkey
        if appkey is not None:
            # First decrypt data
            phy_payload = bytes(packet)[1:]
            c = AES.new(appkey, mode=AES.MODE_ECB)
            dec_ja = c.encrypt(phy_payload)

            # Check MIC
            ja_data = bytes(packet)[0:1] + dec_ja[:-4]
            exp_mic = MIC(appkey, ja_data)
            mic = dec_ja[-4:]
            if exp_mic == mic:
                # MIC is ok, return decrypted packet
                return PHYPayload(ja_data + mic)
            else:
                raise BadMICError
        else:
            raise MissingKeyError('APPKey')
        
    elif packet.mtype == 0x02 or packet.mtype == 0x04:
        if nwkskey is not None and appskey is not None:
            # Decrypt uplink frame
            phy = bytes(packet)[:-4]
            mic = bytes(packet)[-4:]
            mac = packet.getlayer(MACPayloadUplink)
            exp_mic = MIC_Uplink(nwkskey, mac.dev_addr, mac.fcnt, phy)
            if exp_mic == mic:
                # decrypt mac commands
                dec_fopts = encrypt_fopts(appskey, mac.dev_addr, mac.fcnt, bytes(mac.fopts))
                mac.fopts = dec_fopts

                # decrypt payload
                if mac.fport == 0:
                    dec_payload = encrypt_frame(nwkskey, mac.dev_addr, mac.fcnt, bytes(mac.payload))
                else:
                    dec_payload = encrypt_frame(appskey, mac.dev_addr, mac.fcnt, bytes(mac.payload))
                    mac.payload = Raw(dec_payload)
                return packet
            else:
                raise BadMICError()
        else:
            if nwkskey is None:
                raise MissingKeyError('NwkSKey')
            if appskey is None:
                raise MissingKeyError('APPSKey')
    
    elif packet.mtype == 0x03 or packet.mtype == 0x05:
        if nwkskey is not None and appskey is not None:
            # Decrypt uplink frame
            phy = bytes(packet)[:-4]
            mic = bytes(packet)[-4:]
            mac = packet.getlayer(MACPayloadUplink)
            exp_mic = MIC_Downlink(nwkskey, mac.dev_addr, mac.fcnt, phy)
            if exp_mic == mic:
                # decrypt mac commands
                dec_fopts = encrypt_fopts(appskey, mac.dev_addr, mac.fcnt, bytes(mac.fopts), uplink=False)
                mac.fopts = dec_fopts
                
                if mac.fport == 0:
                    dec_payload = encrypt_frame(nwkskey, mac.dev_addr, mac.fcnt, bytes(mac.payload), uplink=False)
                else:
                    dec_payload = encrypt_frame(appskey, mac.dev_addr, mac.fcnt, bytes(mac.payload), uplink=False)
                mac.payload = Raw(dec_payload)
                return packet
            else:
                raise BadMICError
        else:
            if nwkskey is None:
                raise MissingKeyError('NwkSKey')
            if appskey is None:
                raise MissingKeyError('APPSKey')
    else:
        # not supported yet
        return packet

def encrypt_packet(packet : PHYPayload, appkey=None, appskey=None, nwkskey=None) -> PHYPayload:
    """Encrypt LoRaWAN packet.
    
    :param packet: LoRaWAN packet to decrypt
    :type packet: PHYPayload
    :param appkey: LoRaWAN Application Key
    :type appkey: bytes
    :param appskey: LoRaWAN Application Session Key
    :type appskey: bytes
    :param nwkskey: LoRaWAN Network Session Key

    :raises MissingKeyError: A required encryption key is missing

    :return: Encrypted LoRaWAN PHY packet
    :rtype: PHYPayload
    """
    if packet.mtype == 0x01:
        # Join Accept packet is encrypted with the appkey
        if appkey is not None:
            # Compute MIC before encrypting
            ja_data = bytes(packet)[:-4]
            mic = MIC(appkey, ja_data)

            # Encrypt join accept + mic
            ja_and_mic = bytes(packet)[1:-4] + mic
            c = AES.new(appkey, mode=AES.MODE_ECB)
            enc_ja = c.decrypt(ja_and_mic)
            enc_phy = b'\x20' + enc_ja

            # MIC is ok, return decrypted packet
            return PHYPayload(enc_phy)
        else:
            raise MissingKeyError('APPKey')
        
    elif packet.mtype == 0x02 or packet.mtype == 0x04:
        if nwkskey is not None and appskey is not None:
            # Encrypt uplink frame
            mac = packet.getlayer(MACPayloadUplink)

            # Encrypt Fopts
            enc_fopts = encrypt_fopts(appskey, mac.dev_addr, mac.fcnt, bytes(mac.fopts))
            mac.fopts = enc_fopts

            # Encrypt payload
            if mac.fport == 0:
                enc_payload = encrypt_frame(nwkskey, mac.dev_addr, mac.fcnt, bytes(mac.payload))
            else:
                enc_payload = encrypt_frame(appskey, mac.dev_addr, mac.fcnt, bytes(mac.payload))
            mac.payload = Raw(enc_payload)

            # Compute MIC
            phy = bytes(packet)[:-4]
            packet.mic = unpack('<I', MIC_Uplink(nwkskey, mac.dev_addr, mac.fcnt, phy))[0]
            return packet
        else:
            if nwkskey is None:
                raise MissingKeyError('NwkSKey')
            if appskey is None:
                raise MissingKeyError('APPSKey')
    elif packet.mtype == 0x03 or packet.mtype == 0x05:
        if nwkskey is not None and appskey is not None:
             # Encrypt downlink frame
            mac = packet.getlayer(MACPayloadDownlink)

            # Encrypt Fopts
            enc_fopts = encrypt_fopts(appskey, mac.dev_addr, mac.fcnt, bytes(mac.fopts), uplink=False)
            mac.fopts = enc_fopts

            # Encrypt payload
            if mac.fport == 0:
                enc_payload = encrypt_frame(nwkskey, mac.dev_addr, mac.fcnt, bytes(mac.payload), uplink=False)
            else:
                enc_payload = encrypt_frame(appskey, mac.dev_addr, mac.fcnt, bytes(mac.payload), uplink=False)
            mac.payload = Raw(enc_payload)

            # Compute MIC
            phy = bytes(packet)[:-4]
            packet.mic = unpack('<I', MIC_Downlink(nwkskey, mac.dev_addr, mac.fcnt, phy))[0]
            return packet
        else:
            if nwkskey is None:
                raise MissingKeyError('NwkSKey')
            if appskey is None:
                raise MissingKeyError('APPSKey')
    else:
        # not supported yet
        return packet