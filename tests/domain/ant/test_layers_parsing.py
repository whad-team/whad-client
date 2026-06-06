"""ANT Scapy layers parsing unit tests

This script provides different unit tests to ensure our ANT_Hdr scapy layer
works as expected when decoding raw byte frames.

The following tests are performed:
- ANT+ and ANT-FS preambles are correctly extracted
- Device Information (dev. number, dev. type, transmission type) are correctly parsed
- Bit flags (broadcast, ack, end, ...) are correctly identified
- Sub-layers (ANT+, Heart Rate profiles) are correctly resolved
- Re-generation of the parsed frame matches the original raw frame
"""
import struct

from whad.scapy.layers.ant import compute_crc, ANT_Hdr, ANT_Plus_Header_Hdr, \
    ANT_Plus_HR_Header_Hdr, ANT_HR_Default_Data_Page, ANT_FS_Header_Hdr, \
    ANT_FS_Type_Hdr, ANT_FS_Beacon_Packet, ANT_FS_Beacon_Link_Packet


def build_raw_ant_frame(preamble=0xc5a6, dev_num=0x1234, dev_type=120, tx_type=1, flags=0, payload=b'\x00'*8, has_crc=True):
    """Build a raw ANT frame as it would be received over the air.
    """
    # Build the 7-byte header: preamble (2 bits), dev_num (2 bits), dev_type (1 bits),
    # tx_type (1 bits), flags (1 bits)
    hdr = struct.pack("<HHBBB", preamble, dev_num, dev_type, tx_type, flags)
    
    if has_crc:
        frame_without_crc = hdr + payload
        crc = compute_crc(frame_without_crc)

        # Pack CRC and add it to frame
        return frame_without_crc + struct.pack("<H", crc)
    else:
        return hdr + payload

def test_ant_frame_parsing_preamble_ant_plus():
    """Build a raw ANT+ frame and check if ANT_Hdr parses the preamble correctly.
    """
    raw_frame = build_raw_ant_frame(preamble=0xc5a6)
    packet = ANT_Hdr(raw_frame)
    assert packet.preamble == 0xc5a6

def test_ant_frame_parsing_preamble_ant_fs():
    """Build a raw ANT-FS frame and check if ANT_Hdr parses the preamble correctly.
    """
    raw_frame = build_raw_ant_frame(preamble=0xa33b)
    packet = ANT_Hdr(raw_frame)
    assert packet.preamble == 0xa33b

def test_ant_frame_parsing_device_info():
    """Build a raw ANT frame and check if device_number, device_type 
    and transmission_type are correctly extracted.
    """
    raw_frame = build_raw_ant_frame(dev_num=0x5566, dev_type=120, tx_type=0x05)
    packet = ANT_Hdr(raw_frame)
    
    assert packet.device_number == 0x5566
    assert packet.device_type == 120
    assert packet.transmission_type == 0x05

def test_ant_frame_parsing_flags():
    """Build a raw ANT frame with specific bit flags set and check 
    if ANT_Hdr correctly maps them to the BitEnumFields.
    """
    # flags=0xA0 -> Binary: 1010 0000 
    # broadcast=1, ack=0, end=1, count=0, slot=0, unknown=000
    raw_frame = build_raw_ant_frame(flags=0xA0)
    packet = ANT_Hdr(raw_frame)
    
    assert packet.broadcast == 1
    assert packet.ack == 0
    assert packet.end == 1
    assert packet.count == 0
    assert packet.slot == 0

def test_ant_frame_parsing_hr_profile():
    """Build a raw ANT frame containing a Heart Rate default data page
    and verify that Scapy successfully resolves all sub-layers.
    """
    # Craft an 8-byte payload matching: 
    # ANT_Plus_HR_Header_Hdr (1 byte) + ANT_HR_Default_Data_Page (3 bytes) + ANT_HR_Common_Payload (4 bytes)
    # toggle_bit(0) | page_number(0) -> 0x00
    hr_payload = b'\x00' + b'\xff\xff\xff' + b'\x11\x22\x33\x44'
    
    raw_frame = build_raw_ant_frame(dev_type=120, payload=hr_payload)
    packet = ANT_Hdr(raw_frame)
    
    # Check if scapy correctly guessed the sub-layers based on device_type and page_number
    assert ANT_Plus_Header_Hdr in packet
    assert ANT_Plus_HR_Header_Hdr in packet
    assert ANT_HR_Default_Data_Page in packet

def test_ant_frame_parsing_crc_extraction():
    """Build a 17-bytes raw ANT frame (with CRC) and check if the pre_dissect
    function correctly isolates the CRC.
    """
    raw_frame = build_raw_ant_frame(has_crc=True)
    
    # Ensures the generated raw frame is exactly 17 bytes (7 hdr + 8 pay + 2 crc)
    assert len(raw_frame) == 17 
    
    packet = ANT_Hdr(raw_frame)
    expected_crc = struct.unpack("<H", raw_frame[-2:])[0]
    
    # pre_dissect is supposed to set crc_present to 1 for 17-bytes frames
    assert packet.crc_present == 1
    assert packet.crc == expected_crc

def test_ant_frame_generation():
    """Parse a raw ANT frame and check if serializing it back to bytes 
    yields the exact same raw frame.
    """
    raw_frame = build_raw_ant_frame(has_crc=True)
    packet = ANT_Hdr(raw_frame)
    
    # Verify that Scapy's post_build reconstructs the frame identically
    assert bytes(packet) == raw_frame

def test_ant_frame_parsing_antfs_beacon():
    """Parse a raw ANT-FS frame and checks it is correctly dissected.
    """
    # 17 bytes frame: Header (7) + Type (1) + Beacon (3) + Link (4) + CRC (2)
    raw_frame = bytes.fromhex("3BA3640001010A432B0000A0010200F694")
    packet = ANT_Hdr(raw_frame)

    # Check ANT_Hdr
    assert packet.preamble == 0xa33b
    assert packet.device_number == 100
    assert packet.device_type == 1
    assert packet.transmission_type == 1
    
    # Flags: 0x0A -> 00001010
    assert packet.broadcast == 0
    assert packet.ack == 0
    assert packet.end == 0
    assert packet.count == 0
    assert packet.slot == 1
    assert packet.unknown == 2
    
    assert packet.crc_present == 1
    assert packet.crc == 0x94f6

    assert ANT_FS_Header_Hdr in packet
    assert ANT_FS_Type_Hdr in packet
    assert ANT_FS_Beacon_Packet in packet
    assert ANT_FS_Beacon_Link_Packet in packet

    # 3. Check ANT_FS_Type_Hdr
    assert packet[ANT_FS_Type_Hdr].packet_type == 0x43  # 0x43 = Beacon

    # 4. Check ANT_FS_Beacon_Packet
    # 0x2B -> 00 1 0 1 011
    assert packet[ANT_FS_Beacon_Packet].reserved == 0
    assert packet[ANT_FS_Beacon_Packet].data == 1
    assert packet[ANT_FS_Beacon_Packet].upload == 0
    assert packet[ANT_FS_Beacon_Packet].pairing == 1
    assert packet[ANT_FS_Beacon_Packet].period == 3 # 3 -> 4 Hz (8192)
    assert packet[ANT_FS_Beacon_Packet].state == 0 # 0 -> link
    assert packet[ANT_FS_Beacon_Packet].auth_type == 0 # 0 -> pass-through

    # 5. Check ANT_FS_Beacon_Link_Packet
    assert packet[ANT_FS_Beacon_Link_Packet].dev_type == 416 # A0 01 -> 0x01A0 = 416
    assert packet[ANT_FS_Beacon_Link_Packet].manufacturer_id == 2 # 2 -> GarminFr405Antfs