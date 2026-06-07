"""ESB Scapy layers crafting unit tests

This script provides different unit tests to ensure our ESB_Hdr scapy layer
works as expected.

The following tests are performed:

"""
from whad.scapy.layers.esb import compute_crc, ESB_Hdr, ESB_Payload_Hdr, \
    ESB_Ping_Request, ESB_Ack_Response

def build_esb_frame(address='01:02:03:04:05', payload=b'', no_ack=False, pid=0):
    """Build an ESB frame
    """
    preamble = 0xaa if bytes.fromhex(address[:2])[0] >= 0x80 else 0x55

    # Compute payload length
    payload_len = len(payload)&0x3F

    # Build packet config field
    pcf = (payload_len)<<3
    pcf |= (pid&0x3)<<1
    if no_ack:
        pcf |= 1

    # Build payload bytes
    carry = pcf&1
    out = []
    for x in payload:
        out.append((x>>1) | (carry << 7))
        carry = x&1
    out.append(carry<<7)

    # Compute CRC
    frame = bytes.fromhex(address.replace(':','')) + bytes([pcf>>1]) + bytes(out)
    crc = compute_crc(frame)

    # Append the packet CRC
    out[-1] |= crc[0]>>1
    out.append((crc[1]>>1) | (crc[0]&1)<<7)
    out.append((crc[1]&1)<<7)

    # Build the final frame
    return bytes([preamble]) + bytes.fromhex(address.replace(':','')) + bytes([pcf>>1]) + bytes(out)

def test_esb_frame_preamble_0x55():
    """Build an ESB frame and check preamble is 0x55
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0x55,
        address='01:02:03:04:05',
        pid=0,
        no_ack=0
    )/ESB_Payload_Hdr(b"FOOBAR")
    
    assert bytes(packet)[0] == 0x55

def test_esb_frame_preamble_0xAA():
    """Build an ESB frame and check preamble is 0xAA
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='81:02:03:04:05',
        pid=0,
        no_ack=0
    )/ESB_Payload_Hdr(b"FOOBAR")
    
    assert bytes(packet)[0] == 0xAA

def test_esb_frame_address():
    """Build an ESB frame and check address
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='C1:C2:C3:C4:C5',
        pid=0,
        no_ack=0
    )/ESB_Payload_Hdr(b"FOOBAR")
    assert bytes(packet)[1:6] == bytes.fromhex('C1C2C3C4C5')

def test_esb_frame_payload_size():
    """Build an ESB frame and check payload size
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='C1:C2:C3:C4:C5',
        pid=0,
        no_ack=0
    )/ESB_Payload_Hdr(b"FOOBAR")

    assert bytes(packet)[6]>>2 == 6

def test_esb_frame_payload():
    """Build an ESB frame and check payload
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='C1:C2:C3:C4:C5',
        pid=0,
        no_ack=0
    )/ESB_Payload_Hdr(b"FOOBAR")

    # Craft the expected frame
    esb_frame = build_esb_frame("C1:C2:C3:C4:C5", b"FOOBAR")

    # Check payload bytes
    assert bytes(packet)[7:7+6] == esb_frame[7:7+6]

def test_esb_frame_noack():
    """Build an ESB frame with noack bit set and check PCF field
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='C1:C2:C3:C4:C5',
        pid=0,
        no_ack=1
    )/ESB_Payload_Hdr(b"FOOBAR")

    assert bytes(packet)[7]&0x80 == 0x80

def test_esb_frame_pid():
    """Build an ESB frame with PID set and check PCF field
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='C1:C2:C3:C4:C5',
        pid=2,
        no_ack=0
    )/ESB_Payload_Hdr(b"FOOBAR")

    assert bytes(packet)[6]&0x03 == 2

def test_esb_ping_req():
    """Build an ESB Ping request
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='C1:C2:C3:C4:C5',
        pid=0,
        no_ack=0
    )/ESB_Ping_Request()

    # Check encoded payload (bit-shifted)
    assert bytes(packet)[7:7+4] == b'\x07\x87\x87\x87'

def test_esb_ack_response():
    """Build an ESB Ack response
    """
    # Build our ESB packet with preamble 0x55
    packet = ESB_Hdr(
        preamble=0xAA,
        address='C1:C2:C3:C4:C5',
        pid=0,
        no_ack=0
    )/ESB_Ack_Response()

    # Check PCF is set to 0 (payload is null, PID=0 and no ack is not set)
    raw_pkt = bytes(packet)
    assert raw_pkt[6] == 0x00 and raw_pkt[7]&0x80 == 0x00
