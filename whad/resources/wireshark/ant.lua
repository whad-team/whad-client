-- ANT Protocol Dissector (Full & Corrected)
local ant_proto = Proto("ant", "ANT Protocol")

-- ---------- FIELDS ----------
local f = ant_proto.fields
f.preamble      = ProtoField.uint16("ant.preamble", "Preamble", base.HEX)
f.device_num    = ProtoField.uint16("ant.device_number", "Device Number", base.DEC)
f.device_type   = ProtoField.uint8("ant.device_type", "Device Type", base.DEC)
f.trans_type    = ProtoField.uint8("ant.trans_type", "Transmission Type", base.HEX)

-- Control Flags (Octet 6) - Masques basés sur 0x0a -> unknown=2, slot=True
f.flags          = ProtoField.uint8("ant.flags", "Control Flags", base.HEX)
f.flag_broadcast = ProtoField.uint8("ant.flags.broadcast", "Type", base.HEX, {[0]="Broadcast", [1]="Ack/Burst"}, 0x80)
f.flag_ack       = ProtoField.uint8("ant.flags.ack", "Ack", base.HEX, {[0]="False", [1]="True"}, 0x40)
f.flag_end       = ProtoField.uint8("ant.flags.end", "End", base.HEX, {[0]="False", [1]="True"}, 0x20)
f.flag_count     = ProtoField.uint8("ant.flags.count", "Count", base.DEC, nil, 0x10)
f.flag_slot      = ProtoField.uint8("ant.flags.slot", "Slot", base.HEX, {[0]="False", [1]="True"}, 0x08)
f.flag_unknown   = ProtoField.uint8("ant.flags.unknown", "Unknown", base.DEC, nil, 0x07)

f.payload       = ProtoField.bytes("ant.payload", "Payload")
f.crc           = ProtoField.uint16("ant.crc", "CRC", base.HEX)

-- ---------- MAIN DISSECTOR ----------
function ant_proto.dissector(tvb, pinfo, tree)
    local pkt_len = tvb:len()
    if pkt_len < 7 then return end 

    pinfo.cols.protocol = "ANT"
    local subtree = tree:add(ant_proto, tvb(), "ANT Protocol Frame")

    -- 1. Header (Little Endian pour les shorts)
    local preamble = tvb(0, 2):le_uint()
    subtree:add_le(f.preamble, tvb(0, 2))
    subtree:add_le(f.device_num, tvb(2, 2))
    subtree:add(f.device_type, tvb(4, 1))
    subtree:add(f.trans_type, tvb(5, 1))
    
    -- 2. Flags (Octet 6)
    local flags_tvb = tvb(6, 1)
    local flags_tree = subtree:add(f.flags, flags_tvb)
    flags_tree:add(f.flag_broadcast, flags_tvb)
    flags_tree:add(f.flag_ack, flags_tvb)
    flags_tree:add(f.flag_end, flags_tvb)
    flags_tree:add(f.flag_count, flags_tvb)
    flags_tree:add(f.flag_slot, flags_tvb)
    flags_tree:add(f.flag_unknown, flags_tvb)

    -- 3. Info Column Logic
    if preamble == 0xc5a6 then 
        pinfo.cols.info = "ANT+"
    elseif preamble == 0xa33b then 
        pinfo.cols.info = "ANT-FS"
    else 
        pinfo.cols.info = "ANT"
    end

    -- 4. Payload & CRC (CRC toujours sur les 2 DERNIERS octets)
    if pkt_len >= 9 then
        local payload_size = pkt_len - 7 - 2
        if payload_size > 0 then
            -- Interprétation minimale du payload (ANT-FS ou ANT+)
            if preamble == 0xa33b then
                local fs_tree = subtree:add(tvb(7, payload_size), "ANT-FS Data")
                -- On peut ajouter ici les commandes de base si besoin
            else
                subtree:add(f.payload, tvb(7, payload_size))
            end
        end
        -- Le CRC est à la fin du paquet
        subtree:add_le(f.crc, tvb(pkt_len - 2, 2))
    elseif pkt_len == 8 then
        -- Cas très court (pas de payload, pas de CRC complet ?)
        subtree:add(f.payload, tvb(7, 1))
    end
end

-- ---------- REGISTRATION ----------
local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0, ant_proto)
