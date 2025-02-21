----------------------------------------
-- script-name: esb.lua
--

----------------------------------------
-- creates a Proto object, but doesn't register it yet
local nrf24 = Proto("nrf24","nRF24L01+ protocol dissector")

--------------------------------------------------------------------------------
-- preferences handling stuff
local default_settings = {
    crc_length = 2
}
nrf24.prefs.upper_addr_bytes  = Pref.string("Upper Address Bytes", default_settings.upper_addr_bytes,
                            "The fixed values of the 2 - 5 upper address bytes")
nrf24.prefs.crc_length       = Pref.uint("CRC length", default_settings.crc_length,
                            "1 or 2 byte CRC ( 1 byte not yet supported :( )")
-- The nRF will compare [2,3,4,5] fixed upper bytes of the address
-- any remaining addr bytes are variable and will be returned as payload
print("Upper fixed address bytes set to ", nrf24.prefs.upper_addr_bytes )

function printx(a,x)
  print(a.."0x"..bit.tohex(x))
end

upperAddrPrepend = function( tvbIn )
    tempArray = ByteArray.new( nrf24.prefs.upper_addr_bytes )
    tempArray:append( tvbIn:bytes() )
    return ByteArray.tvb( tempArray, "full tvb with completed address" )
end

shiftLeft = function( tvbIn )
    -- Take a tvbIn and shift its content by 1 bit to the left and return it.
    local byteArrayOut = ByteArray.new()
    local inLen = tvbIn:len()
    byteArrayOut:set_size( inLen )
    local carryBit = 0
    local temp = 0
    for i=0,inLen-1,1 do
        if i>=inLen-1 then
            carryBit = 0
        else
            carryBit = bit.band( bit.rshift( tvbIn(i+1,1):uint(), 7 ), 0x01 )
        end
        temp = bit.lshift( tvbIn(i,1):uint(), 1 )
        temp = bit.bor( temp, carryBit )
        byteArrayOut:set_index( i, bit.band(temp,0xFF) )
    end
    return ByteArray.tvb( byteArrayOut, "Shifted paylaod and CRC data" )
end

-- The CRC is the error detection mechanism in the packet. It may either be 1 or 2 bytes and is calculated
-- over the address, Packet Control Field, and Payload.
-- The polynomial for 1 byte CRC is X^8 + X^2 + X + 1. Initial value 0xFF
-- The polynomial for 2 byte CRC is X^16 + X^12 + X^5 + 1. Initial value 0xFFFF
crc16 = function( byteArrIn, len_bits )
    local band = bit.band
    local xor = bit.bxor
    local rshift = bit.rshift
    local lshift = bit.lshift
    local crc = 0xffff    -- our shift register in its initial state
    --print("CRC: Got " .. byteArrIn:len()*8 .. "bits,  " .. "Calcing over " .. len_bits .. "bits" )
    if byteArrIn:len()*8 < len_bits then
        print("CRC: Error, not enough bits " )
        return crc
    end
    for currentBit=8,len_bits-1 do
        bitIndex = band( currentBit, 0x07 )                         -- counts from 0 to 7
        if bitIndex == 0 then                                       --   fetch a new byte on 0
            byteIndex = rshift(currentBit,3)
            byteValue = byteArrIn:get_index( byteIndex )
        end
        bit15Value = band( lshift( byteValue, 8+bitIndex ), 0x8000 )-- Shift the current bit to the position of bit 15
        crc = xor( crc, bit15Value )
        --print( byteIndex .. "." .. bitIndex .. " = " .. bit.tohex(bit15Value) .. " crc = " .. bit.tohex(crc) )
        if band( crc, 0x8000 ) > 0 then                             -- if polynomal is true, activate xors in shift register
            crc = xor( band( lshift(crc,1), 0xFFFF ), 0x1021 )      --   0x1021 = (1) 0001 0000 0010 0001 = x^16+x^12+x^5+1
        else
            crc = band( lshift(crc,1), 0xFFFF )                     --   otherwise do an ordinary shift
        end
    end
    --printx("CRC: -------- ", crc )
    return crc
end

----------------------------------------
-- Add ProtoFields
-- the abbreviation should always have "<myproto>." before the specific abbreviation, to avoid collisions
local f = nrf24.fields
-- Can be 1 or 2 bytes lower address
--f.pf_base_adr           = ProtoField.uint64("nrf24.low_adr",   "Lower Address",  base.HEX, nil, 0xFFFFFFFFFF000000 )
f.pf_preamble           = ProtoField.uint8 ("nrf24.preamble",  "Preamble" ,  base.HEX )
f.pf_full_adr           = ProtoField.bytes ("nrf24.full_adr",  "Full Address" )
f.pf_pcf                = ProtoField.uint16("nrf24.pcf",       "Packet Control Field", base.HEX )              -- 9 bit 0b1 1111 1111
f.pf_pcf_payload_length = ProtoField.uint16("nrf24.pcf.p_len", "Payload Length", base.DEC, nil, 0x01F8 )       -- 6 bit 0b1 1111 1000
f.pf_pcf_pid            = ProtoField.uint16("nrf24.pcf.pid",   "Packet Ident.",  base.DEC, nil, 0x0006 )       -- 2 bit 0b0 0000 0110
f.pf_pcf_noack          = ProtoField.uint16("nrf24.pcf.no_ack","No Ack Flag",    base.DEC, {[0]="Ack On", [1]="Ack Off"}, 0x0001 ) -- 1 bit
f.pf_payload            = ProtoField.bytes( "nrf24.payload", "Payload")
f.pf_crc                = ProtoField.uint16("nrf24.crc",     "  Received Check Sum", base.HEX)
f.pf_calcCrc            = ProtoField.uint16("nrf24.calcCrc", "Calculated Check Sum", base.HEX)
f.pf_garbage            = ProtoField.bytes( "nrf24.garb", "Garbage data")

nrf24.experts.ef_p_len_err = ProtoExpert.new("nrf24.p_len_err", "Illegal Payload length",
                                     expert.group.MALFORMED, expert.severity.ERROR)
nrf24.experts.ef_bad_crc   = ProtoExpert.new("nrf24.bad_crc", "Check sum error",
                                     expert.group.CHECKSUM, expert.severity.ERROR)


----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "dns.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function nrf24.dissector(tvbuf,pktinfo,root)
    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("NRF24")

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add( nrf24, tvbuf:range(0,-1) )

    -- Prepend the static part of the address to the tvbuf
    local tvbufFull = upperAddrPrepend( tvbuf )

    -- Add preamble to dissection
    local preambleRange = tvbufFull:range( 0, 1 )
    tree:add( f.pf_preamble, preambleRange )
    -- Add address to dissections
    local adrRange = tvbufFull:range( 1, 5 )
    tree:add( f.pf_full_adr, adrRange )
    -- Add address to upper gui list
    pktinfo.cols.src:set( string.format("0x%02X", adrRange:range(4, 1):uint() ) )

    -- extract the 9 bit packet control field
    local plLengthValue = tvbufFull:range( 6, 1 ):bitfield( 0, 6 )
    tree:append_text(", Address: " .. adrRange .. ", Payload: " .. plLengthValue .. " bytes" )
    pktinfo.cols.packet_len:set( string.format("%d",plLengthValue) )    -- setting the Length column has no effect :(
    local pcfRange = tvbufFull:range( 6, 2 ):bitfield( 0, 9 )
    local pcfTree = tree:add( f.pf_pcf, pcfRange )
    pcfTree:add( f.pf_pcf_payload_length, pcfRange )
    pcfTree:add( f.pf_pcf_pid,   pcfRange )
    pcfTree:add( f.pf_pcf_noack, pcfRange )
    if plLengthValue > 35 then
        pcfTree:add_proto_expert_info( nrf24.experts.ef_p_len_err )
        pktinfo.cols.info:set( string.format("Illegal payload length: %d", plLengthValue ) )
        return
    end

    -- extract payload til end of packet and shift it 1 bit to the left to get rid of the NO_ACK 9th bit
    local unshiftedRemainder = tvbufFull( 7, -1 )
    local shiftedRemainder = shiftLeft( unshiftedRemainder )

    tree:add( f.pf_payload, shiftedRemainder(0,plLengthValue) )
    local readCrc = shiftedRemainder(plLengthValue,nrf24.prefs.crc_length):uint()
    tree:add( f.pf_crc, readCrc )

    local calcCrc = crc16( tvbufFull:bytes(), 8*(1+5+plLengthValue)+9 ) --Calculated over the address, Payload and Packet Control Field
    tree:add( f.pf_calcCrc, calcCrc )

    tree:add( f.pf_garbage, shiftedRemainder(plLengthValue+nrf24.prefs.crc_length,-1) )

    if calcCrc ~= readCrc then
       tree:add_proto_expert_info( nrf24.experts.ef_bad_crc )
       pktinfo.cols.info:set( string.format("Checksum error, RX 0x%04X CALC 0x%04X", readCrc, calcCrc ) )
       return
    end

    pktinfo.cols.info:set( string.format("Adr: %s, Len: %2d, Pld: %s", tostring(adrRange), plLengthValue, tostring(shiftedRemainder(0,plLengthValue)) ) )
    -- tell wireshark how much of tvbuff we dissected
    --return pktlen
end
