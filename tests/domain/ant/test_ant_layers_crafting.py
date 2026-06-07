"""ANT Scapy layers crafting unit tests

This script provides different unit tests to ensure our ANT_Hdr scapy layer
works as expected.

The following tests are performed:
- Checks that ANT frame preamble is correctly set to ANT+ or ANT-FS expected one
- Checks that building an ANT frame generates correctly packed device informations
- Checks that building an ANT frame generates correcly packed header flags
- Checks the correctness of the CRC appended (or not) to the packet
- Checks that building an ANT+ default page is correctly built  
"""
from struct import pack
from whad.scapy.layers.ant import compute_crc, ANT_Hdr, ANT_Plus_Header_Hdr, \
    ANT_Plus_HR_Header_Hdr, ANT_HR_Default_Data_Page, ANT_FS_Header_Hdr, \
    ANT_FS_Type_Hdr, ANT_FS_Beacon_Packet

def build_ant_frame(preamble=0xc5a6, dev_num=0, dev_type=0, tx_type=0, flags=0, payload=b'', crc_present=True):
    """Build an ANT frame manually to use as a ground-truth for tests.
    """
    # Build the header: preamble (2 bits), dev_num (2 bits), dev_type (1 bits),
    # tx_type (1 bits), flags (1 bits)
    hdr = pack("<HHBBB", preamble, dev_num, dev_type, tx_type, flags)
    
    if crc_present:
        # compute_crc acts on the header and payload combined
        crc = compute_crc(hdr + payload)
        # Pack CRC as little-endian short
        return hdr + payload + pack("<H", crc)
    else:
        return hdr + payload

def test_ant_frame_preamble_ant_plus():
    """Build an ANT frame and check default ANT+ preamble (0xc5a6)
    """
    packet = ANT_Hdr(
        device_number=0,
        device_type=0,
        transmission_type=0,
        crc_present=0
    )  / ANT_Plus_Header_Hdr() / ANT_Plus_HR_Header_Hdr(
        toggle_bit=1,
        data_page_number=0
    ) / ANT_HR_Default_Data_Page(
        reserved=0x112233
    )
    
    # 0xc5a6 in little-endian should be \xa6\xc5
    assert bytes(packet)[:2] == b'\xa6\xc5'

def test_ant_frame_preamble_ant_fs():
    """Build an ANT frame and check default ANT-FS preamble (0xa33b)
    """
    packet = ANT_Hdr(
        device_number=0,
        device_type=0,
        transmission_type=0,
        crc_present=0
    ) / ANT_FS_Header_Hdr() / ANT_FS_Type_Hdr() /  ANT_FS_Beacon_Packet(
        data=0,
        upload=0,
        pairing=0,
        period=1,
        state=0x00 # link
    )

    # 0xa33b in little-endian should be \x3b\xa3
    assert bytes(packet)[:2] == b'\x3b\xa3'

def test_ant_frame_device_info():
    """Build an ANT frame and check device_number, device_type and transmission_type encoding.
    """
    packet = ANT_Hdr(
        preamble=0xc5a6,
        device_number=0x1234,
        device_type=120,
        transmission_type=0x05,
        crc_present=0
    )
    
    raw_pkt = bytes(packet)
    
    # Check device number
    assert raw_pkt[2:4] == b'\x34\x12'
    # Check device type
    assert raw_pkt[4] == 120
    # Check transmission type
    assert raw_pkt[5] == 0x05

def test_ant_frame_flags():
    """Build an ANT frame with various bit flags set and check the packed byte.
    """
    packet = ANT_Hdr(
        preamble=0xc5a6,
        device_number=0,
        device_type=0,
        transmission_type=0,
        broadcast=1,
        ack=0,
        end=1,
        count=0,
        slot=0,
        unknown=0,
        crc_present=0
    )
    
    raw_pkt = bytes(packet)
    
    # broadcast=1, ack=0, end=1, count=0, slot=0, unknown=000 -> 10100000 = 0xA0
    assert raw_pkt[6] == 0xA0

def test_ant_frame_crc_generation():
    """Build an ANT frame with crc_present=1 and verify the CRC is correctly added.
    """
    payload_data = b"FOOBAR"
    packet = ANT_Hdr(
        preamble=0xc5a6,
        device_number=0x1122,
        device_type=0x33,
        transmission_type=0x44,
        broadcast=0, ack=0, end=0, count=0, slot=0, unknown=0,
        crc_present=1
    ) / payload_data

    # Craft the expected frame using our manual builder
    expected_frame = build_ant_frame(
        preamble=0xc5a6, 
        dev_num=0x1122, 
        dev_type=0x33, 
        tx_type=0x44, 
        flags=0x00, 
        payload=payload_data, 
        crc_present=True
    )

    raw_pkt = bytes(packet)

    # 7 bytes header + 6 bytes payload + 2 bytes CRC = 15 bytes
    assert len(raw_pkt) == 15
    assert raw_pkt == expected_frame
    
    # Check CRC bytes explicitly
    expected_crc = compute_crc(expected_frame[:13])
    assert raw_pkt[-2:] == pack("<H", expected_crc)

def test_ant_frame_no_crc():
    """Build an ANT frame with crc_present=0 and verify no CRC is appended.
    """
    payload_data = b"FOOBAR"
    packet = ANT_Hdr(
        preamble=0xc5a6,
        device_number=0x1122,
        device_type=0x33,
        transmission_type=0x44,
        broadcast=0, ack=0, end=0, count=0, slot=0, unknown=0,
        crc_present=0
    ) / payload_data

    raw_pkt = bytes(packet)

    # 7 bytes header + 6 bytes payload = 13 bytes
    assert len(raw_pkt) == 13
    assert raw_pkt[7:] == payload_data

def test_ant_profile_heart_rate():
    """Build an ANT Heart Rate profile packet and verify layer bindings.
    """
    # Device type 120 triggers the ANT_Plus_HR_Header_Hdr binding
    packet = ANT_Hdr(
        preamble=0xc5a6,
        device_number=0x1234,
        device_type=120, 
        transmission_type=0x01,
        crc_present=0
    ) / ANT_Plus_Header_Hdr() / ANT_Plus_HR_Header_Hdr(
        toggle_bit=1,
        data_page_number=0
    ) / ANT_HR_Default_Data_Page(
        reserved=0x112233
    )

    raw_pkt = bytes(packet)
    
    # Check that device type is set to 120 (HR)
    assert raw_pkt[4] == 120
    
    # Check the header toggle_bit=1 + data_page_number=0000000 -> 10000000 = 0x80
    assert raw_pkt[7] == 0x80
    
    # Check the default data page reserved payload
    assert raw_pkt[8:11] == b'\x33\x22\x11'