local wihart = Proto("wihart", "WirelessHART")

-- Bit operations
local function bxor (a,b)
    local r = 0
    for i = 0, 31 do
        local x = a / 2 + b / 2
        if x ~= math.floor (x) then
            r = r + 2^i
        end
        a = math.floor (a / 2)
        b = math.floor (b / 2)
    end
    return r
end
local function band (a,b) return ((a+b) - bxor(a,b))/2 end

-- Protocol field definitions
local f = wihart.fields

local yes_no = { [0] = "No", [1] = "Yes" }
local priority_enum = { [0] = "Alarm", "Normal", "Process Data", "Command" }
local netkey_enum = { [0] = "False", "True" }
local pkttype_enum = { [0] = "Acknowledgement", "Advertisement", "Keep Alive", "Disconnect", [7] = "Data" }

-- ==========================================
-- Préférences (Déchiffrement)
-- ==========================================
wihart.prefs.network_key = Pref.string("Network Key (Hex)", "00112233445566778899AABBCCDDEEFF", "Clé réseau 128-bits (Format Hexadécimal sans espaces)")

local function hex2bytes(str)
    local bytes = {}
    for i = 1, #str, 2 do
        table.insert(bytes, tonumber(str:sub(i, i+1), 16))
    end
    return ByteArray.new(bytes)
end

-- ==========================================
-- 1. WirelessHART DLPDU fields
-- ==========================================
f.dlpduspec_reserved = ProtoField.uint8("wihart.dlpduspec.reserved", "Reserved", base.HEX, nil, 0xC0)
f.dlpduspec_priority = ProtoField.uint8("wihart.dlpduspec.priority", "Priority", base.DEC, priority_enum, 0x30)
f.dlpduspec_netkey = ProtoField.uint8("wihart.dlpduspec.netkey", "Network Key Use", base.DEC, netkey_enum, 0x08)
f.dlpduspec_type = ProtoField.uint8("wihart.dlpduspec.pkttype", "Packet Type", base.DEC, pkttype_enum, 0x07)
f.dlpdudata = ProtoField.bytes("wihart.dlpdudata", "DLPDU Data", base.NONE)
f.mic = ProtoField.uint32("wihart.mic", "Message Integrity Code", base.HEX)

-- ==========================================
-- 2. Network layer fields
-- ==========================================
f.nwk_dest_addr_len = ProtoField.uint8("wihart.nwk.dest_addr_len", "Destination Address Length", base.DEC, {[0]="Short", [1]="Long"}, 0x80)
f.nwk_src_addr_len = ProtoField.uint8("wihart.nwk.src_addr_len", "Source Address Length", base.DEC, {[0]="Short", [1]="Long"}, 0x40)
f.nwk_proxy_route = ProtoField.uint8("wihart.nwk.proxy_route", "Proxy Route", base.DEC, yes_no, 0x08)
f.nwk_first_src_route = ProtoField.uint8("wihart.nwk.first_src_route", "First Source Route Segment", base.DEC, yes_no, 0x02)
f.nwk_second_src_route = ProtoField.uint8("wihart.nwk.second_src_route", "Second Source Route Segment", base.DEC, yes_no, 0x01)

f.nwk_ttl = ProtoField.uint8("wihart.nwk.ttl", "Time To Live", base.DEC)
f.nwk_asn_snippet = ProtoField.uint16("wihart.nwk.asn_snippet", "ASN Snippet", base.HEX)
f.nwk_graph_id = ProtoField.uint16("wihart.nwk.graph_id", "Graph ID", base.HEX)

f.nwk_dest_addr = ProtoField.bytes("wihart.nwk.dest_addr", "Network Destination Address", base.NONE)
f.nwk_dest_addr64 = ProtoField.bytes("wihart.nwk.dest_addr64", "Network Destination Address (64-bit)", base.NONE)
f.nwk_src_addr = ProtoField.bytes("wihart.nwk.src_addr", "Network Source Address", base.NONE)
f.nwk_src_addr64 = ProtoField.bytes("wihart.nwk.src_addr64", "Network Source Address (64-bit)", base.NONE)
f.nwk_parent_proxy_addr = ProtoField.bytes("wihart.nwk.parent_proxy_addr", "Parent Proxy Address", base.NONE)
f.nwk_first_route_segment = ProtoField.bytes("wihart.nwk.first_route_segment", "First Route Segment", base.NONE)
f.nwk_second_route_segment = ProtoField.bytes("wihart.nwk.second_route_segment", "Second Route Segment", base.NONE)

-- ==========================================
-- 3. Network Security Sub-Layer fields
-- ==========================================
f.sec_types = ProtoField.uint8("wihart.sec.types", "Security Types", base.DEC, {
    [0]="Session Keyed", [1]="Join Keyed", [15]="Decrypted"
}, 0x0F)
f.sec_counter_short = ProtoField.uint8("wihart.sec.counter_short", "Counter (Short)", base.DEC)
f.sec_counter_long = ProtoField.uint32("wihart.sec.counter_long", "Counter", base.DEC)
f.sec_nwk_mic = ProtoField.uint32("wihart.sec.nwk_mic", "Network MIC", base.HEX)

-- ==========================================
-- 4. Transport Layer fields
-- ==========================================
f.tp_acknowledged = ProtoField.uint8("wihart.tp.acknowledged", "Acknowledged", base.DEC, yes_no, 0x80)
f.tp_response = ProtoField.uint8("wihart.tp.response", "Response", base.DEC, yes_no, 0x40)
f.tp_broadcast = ProtoField.uint8("wihart.tp.broadcast", "Broadcast", base.DEC, yes_no, 0x20)
f.tp_seq_num = ProtoField.uint8("wihart.tp.seq_num", "Transport Sequence Number", base.DEC, nil, 0x1F)

-- Device Status Bitfields
f.tp_ds_malfunction = ProtoField.uint8("wihart.tp.ds.malfunction", "Device Malfunction", base.DEC, yes_no, 0x80)
f.tp_ds_config_changed = ProtoField.uint8("wihart.tp.ds.config_changed", "Configuration Changed", base.DEC, yes_no, 0x40)
f.tp_ds_cold_start = ProtoField.uint8("wihart.tp.ds.cold_start", "Cold Start", base.DEC, yes_no, 0x20)
f.tp_ds_more_status = ProtoField.uint8("wihart.tp.ds.more_status", "More Status Available", base.DEC, yes_no, 0x10)
f.tp_ds_loop_fixed = ProtoField.uint8("wihart.tp.ds.loop_fixed", "Loop Current Fixed", base.DEC, yes_no, 0x08)
f.tp_ds_loop_sat = ProtoField.uint8("wihart.tp.ds.loop_sat", "Loop Current Saturated", base.DEC, yes_no, 0x04)
f.tp_ds_non_pri_out = ProtoField.uint8("wihart.tp.ds.non_pri_out", "Non-Primary Variable Out of Limit", base.DEC, yes_no, 0x02)
f.tp_ds_pri_out = ProtoField.uint8("wihart.tp.ds.pri_out", "Primary Variable Out of Limit", base.DEC, yes_no, 0x01)

-- Extended Device Status Bitfields
f.tp_ext_ds_reserved = ProtoField.uint8("wihart.tp.ext_ds.reserved", "Reserved", base.HEX, nil, 0xC0)
f.tp_ext_ds_func_check = ProtoField.uint8("wihart.tp.ext_ds.func_check", "Function Check", base.DEC, yes_no, 0x20)
f.tp_ext_ds_out_spec = ProtoField.uint8("wihart.tp.ext_ds.out_spec", "Out of Specification", base.DEC, yes_no, 0x10)
f.tp_ext_ds_fail = ProtoField.uint8("wihart.tp.ext_ds.fail", "Failure", base.DEC, yes_no, 0x08)
f.tp_ext_ds_crit_power = ProtoField.uint8("wihart.tp.ext_ds.crit_power", "Critical Power Failure", base.DEC, yes_no, 0x04)
f.tp_ext_ds_dev_alert = ProtoField.uint8("wihart.tp.ext_ds.dev_alert", "Device Variable Alert", base.DEC, yes_no, 0x02)
f.tp_ext_ds_maint_req = ProtoField.uint8("wihart.tp.ext_ds.maint_req", "Maintenance Required", base.DEC, yes_no, 0x01)

-- ==========================================
-- 5. Command Header fields
-- ==========================================
f.cmd_number = ProtoField.uint16("wihart.cmd.number", "Command Number", base.HEX)
f.cmd_len = ProtoField.uint8("wihart.cmd.len", "Payload Length", base.DEC)
f.cmd_payload = ProtoField.bytes("wihart.cmd.payload", "Command Payload", base.NONE)

-- ==========================================
-- 6. Acknowledgment fields
-- ==========================================
local ack_codes = { [0] = "Success", [61] = "No Buffers Available", [62] = "No Alarm/Event Buffers Available", [63] = "Priority Too Low" }
f.ack_code = ProtoField.uint8("wihart.ack.code", "Response Code", base.DEC, ack_codes)
f.ack_timeadj = ProtoField.int16("wihart.ack.timeadj", "Time Adjustment (usec)", base.DEC)

-- ==========================================
-- 7. Advertisement fields
-- ==========================================
f.adv_slot = ProtoField.bytes("wihart.adv.slot", "Absolute Slot Number", base.NONE)
f.adv_joinctl = ProtoField.uint8("wihart.adv.joinctl", "Join Control", base.HEX)
f.adv_mapsz = ProtoField.uint8("wihart.adv.chanmapsz", "Channel Map Size", base.DEC)
f.adv_map = ProtoField.bytes("wihart.adv.chanmap", "Channel Map", base.NONE)
f.adv_graphid = ProtoField.uint16("wihart.adv.graphid", "Graph ID", base.HEX)
f.adv_framecnt = ProtoField.uint8("wihart.adv.superframecount", "Number Of Superframes", base.DEC)
f.adv_frameid = ProtoField.uint8("wihart.adv.frameid", "Superframe ID", base.DEC)
f.adv_framesz = ProtoField.uint16("wihart.adv.framesz", "Superframe Number Of Slots", base.DEC)
f.adv_linkcnt = ProtoField.uint8("wihart.adv.linkcnt", "Number Of Links", base.DEC)
f.adv_linkjoinslot = ProtoField.uint16("wihart.adv.linkslot", "Link Join Slot", base.DEC)

-- Link Join Bitfields
f.adv_link_reserved = ProtoField.uint8("wihart.adv.link_reserved", "Reserved", base.HEX, nil, 0x80)
f.adv_link_xmit = ProtoField.uint8("wihart.adv.link_xmit", "Use for Transmission", base.DEC, { [0]="Denied", [1]="Allowed" }, 0x40)
f.adv_link_chanoff = ProtoField.uint8("wihart.adv.link_chanoff", "Channel Offset", base.DEC, nil, 0x3F)


function wihart.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "WiHART"

    local subtree = tree:add(wihart, buffer(), "WirelessHART DataLink Layer PDU")
    local pos = 0
    local addrspec = buffer(0,1):uint()

    -- ------------------------------------------
    -- DLPDU Specifier Bitmap
    -- ------------------------------------------
    local dlpduspec = buffer(pos,1):uint()
    local dlpdu_ctrl_tree = subtree:add(wihart, buffer(pos, 1), string.format("DLPDU Specifier (0x%02X)", dlpduspec))
    dlpdu_ctrl_tree:add(f.dlpduspec_reserved, buffer(pos, 1))
    dlpdu_ctrl_tree:add(f.dlpduspec_priority, buffer(pos, 1))
    dlpdu_ctrl_tree:add(f.dlpduspec_netkey, buffer(pos, 1))
    dlpdu_ctrl_tree:add(f.dlpduspec_type, buffer(pos, 1))
    pos = pos + 1
    
    local pkttype_val = band(dlpduspec, 0x07)
    local datalen = buffer:len() - pos - 4
    local pdu = buffer(pos,datalen)
    local pduname = pkttype_enum[pkttype_val] or "Unknown PDU"

    pinfo.cols.info = pduname

    subtree:add(f.dlpdudata, pdu)
    subtree:add(f.mic, buffer(buffer:len() - 4, 4))

    local function add_field(tree_node, field, size)
        local item = tree_node:add(field, buffer(pos, size))
        pos = pos + size
        return item
    end

    if pkttype_val == 7 then -- Data
        local nwktree = tree:add(wihart, pdu, "WirelessHART Network Layer")
        
        -- ------------------------------------------
        -- Network Control Bitmap
        -- ------------------------------------------
        local nwk_control = buffer(pos, 1):uint()
        local nwk_ctrl_tree = nwktree:add(wihart, buffer(pos, 1), string.format("Network Control Field (0x%02X)", nwk_control))
        nwk_ctrl_tree:add(f.nwk_dest_addr_len, buffer(pos, 1)) 
        nwk_ctrl_tree:add(f.nwk_src_addr_len, buffer(pos, 1))
        nwk_ctrl_tree:add(f.nwk_proxy_route, buffer(pos, 1))
        nwk_ctrl_tree:add(f.nwk_first_src_route, buffer(pos, 1))
        nwk_ctrl_tree:add(f.nwk_second_src_route, buffer(pos, 1))
        pos = pos + 1
        
        add_field(nwktree, f.nwk_ttl, 1)
        add_field(nwktree, f.nwk_asn_snippet, 2)
        add_field(nwktree, f.nwk_graph_id, 2)
        
        if band(nwk_control, 0x80) == 0x80 then
            add_field(nwktree, f.nwk_dest_addr64, 8)
        else
            add_field(nwktree, f.nwk_dest_addr, 2)
        end
        
        if band(nwk_control, 0x40) == 0x40 then
            add_field(nwktree, f.nwk_src_addr64, 8)
        else
            add_field(nwktree, f.nwk_src_addr, 2)
        end

        if band(nwk_control, 0x08) == 0x08 then
            add_field(nwktree, f.nwk_parent_proxy_addr, 2)
        end
        if band(nwk_control, 0x02) == 0x02 then
            add_field(nwktree, f.nwk_first_route_segment, 8)
        end
        if band(nwk_control, 0x01) == 0x01 then
            add_field(nwktree, f.nwk_second_route_segment, 8)
        end

        -- ------------------------------------------
        -- Network Security Sub-Layer
        -- ------------------------------------------
        if pos < buffer:len() - 4 then
            local sectree = tree:add(wihart, buffer(pos, buffer:len() - pos - 4), "WirelessHART Network Security Sub-Layer")
            
            -- Security Control Bitmap
            local sec_control = buffer(pos, 1):uint()
            local sec_ctrl_tree = sectree:add(wihart, buffer(pos, 1), string.format("Security Control Field (0x%02X)", sec_control))
            sec_ctrl_tree:add(f.sec_types, buffer(pos, 1))
            pos = pos + 1

            local sec_type_val = band(sec_control, 0x0F)

            if sec_type_val == 0 then
                add_field(sectree, f.sec_counter_short, 1)
            else
                add_field(sectree, f.sec_counter_long, 4)
            end
            
            sectree:add(f.sec_nwk_mic, buffer(buffer:len() - 4, 4))
            local encrypted_payload_tvb = buffer(pos, buffer:len() - pos - 4)

            -- ------------------------------------------
            -- Transport Layer
            -- ------------------------------------------
            if sec_type_val == 15 and pos < buffer:len() - 4 then
                local tptree = tree:add(wihart, buffer(pos, buffer:len() - pos - 4), "WirelessHART Transport Layer")
                
                -- Transport Control Bitmap
                local tp_control = buffer(pos, 1):uint()
                local tp_ctrl_tree = tptree:add(wihart, buffer(pos, 1), string.format("Transport Control Field (0x%02X)", tp_control))
                tp_ctrl_tree:add(f.tp_acknowledged, buffer(pos, 1))
                tp_ctrl_tree:add(f.tp_response, buffer(pos, 1))
                tp_ctrl_tree:add(f.tp_broadcast, buffer(pos, 1))
                tp_ctrl_tree:add(f.tp_seq_num, buffer(pos, 1))
                pos = pos + 1

                -- Device Status Bitmap
                local ds_val = buffer(pos, 1):uint()
                local ds_tree = tptree:add(wihart, buffer(pos, 1), string.format("Device Status (0x%02X)", ds_val))
                ds_tree:add(f.tp_ds_malfunction, buffer(pos, 1))
                ds_tree:add(f.tp_ds_config_changed, buffer(pos, 1))
                ds_tree:add(f.tp_ds_cold_start, buffer(pos, 1))
                ds_tree:add(f.tp_ds_more_status, buffer(pos, 1))
                ds_tree:add(f.tp_ds_loop_fixed, buffer(pos, 1))
                ds_tree:add(f.tp_ds_loop_sat, buffer(pos, 1))
                ds_tree:add(f.tp_ds_non_pri_out, buffer(pos, 1))
                ds_tree:add(f.tp_ds_pri_out, buffer(pos, 1))
                pos = pos + 1

                -- Extended Device Status Bitmap
                local ext_ds_val = buffer(pos, 1):uint()
                local ext_ds_tree = tptree:add(wihart, buffer(pos, 1), string.format("Extended Device Status (0x%02X)", ext_ds_val))
                ext_ds_tree:add(f.tp_ext_ds_reserved, buffer(pos, 1))
                ext_ds_tree:add(f.tp_ext_ds_func_check, buffer(pos, 1))
                ext_ds_tree:add(f.tp_ext_ds_out_spec, buffer(pos, 1))
                ext_ds_tree:add(f.tp_ext_ds_fail, buffer(pos, 1))
                ext_ds_tree:add(f.tp_ext_ds_crit_power, buffer(pos, 1))
                ext_ds_tree:add(f.tp_ext_ds_dev_alert, buffer(pos, 1))
                ext_ds_tree:add(f.tp_ext_ds_maint_req, buffer(pos, 1))
                pos = pos + 1

                -- Command Layer 
                while pos < buffer:len() - 4 do
                    local cmd_start = pos
                    local cmd_num = buffer(pos, 2):uint()
                    local cmd_tree = tptree:add(wihart, buffer(pos, 0), string.format("Command: 0x%04X", cmd_num))
                    
                    add_field(cmd_tree, f.cmd_number, 2)
                    local cmd_length = buffer(pos, 1):uint()
                    add_field(cmd_tree, f.cmd_len, 1)
                    
                    if cmd_length > 0 then
                        add_field(cmd_tree, f.cmd_payload, cmd_length)
                    end
                    cmd_tree:set_len(pos - cmd_start)
                end
            elseif sec_type_val ~= 15 then
                sectree:add(f.cmd_payload, encrypted_payload_tvb, "Encrypted Payload")
            end
        end
    end

    if pkttype_val == 0 then -- Ack
        local acktree = tree:add(wihart, pdu, "WirelessHART Acknowledgement")
        add_field(acktree, f.ack_code, 1)
        add_field(acktree, f.ack_timeadj, 2)
    end

    if pkttype_val == 1 then -- Advertise
        local advtree = tree:add(wihart, pdu, "WirelessHART Advertisement")

        add_field(advtree, f.adv_slot, 5)
        add_field(advtree, f.adv_joinctl, 1)
        
        local mapsz = math.ceil(buffer(pos, 1):uint() / 8)
        add_field(advtree, f.adv_mapsz, 1)
        add_field(advtree, f.adv_map, mapsz)
        add_field(advtree, f.adv_graphid, 2)
        
        local framecnt = buffer(pos, 1):uint()
        add_field(advtree, f.adv_framecnt, 1)

        for i = 1, framecnt do
            local frame_start = pos
            local frame_id = buffer(pos, 1):uint()
            
            local frame_tree = advtree:add(wihart, buffer(pos, 0), string.format("Superframe [ID: %d]", frame_id))
            
            add_field(frame_tree, f.adv_frameid, 1)
            add_field(frame_tree, f.adv_framesz, 2)
            
            local linkcnt = buffer(pos, 1):uint()
            add_field(frame_tree, f.adv_linkcnt, 1)
            
            for j = 1, linkcnt do
                local link_start = pos
                local link_slot = buffer(pos, 2):uint()
                
                local link_tree = frame_tree:add(wihart, buffer(pos, 3), string.format("Link [Slot: %d]", link_slot))
                add_field(link_tree, f.adv_linkjoinslot, 2)
                
                -- ------------------------------------------
                -- Link Join Bitmap
                -- ------------------------------------------
                local linkbits_val = buffer(pos, 1):uint()
                local linkbits_tree = link_tree:add(wihart, buffer(pos, 1), string.format("Link Join Bits (0x%02X)", linkbits_val))
                linkbits_tree:add(f.adv_link_reserved, buffer(pos, 1))
                linkbits_tree:add(f.adv_link_xmit, buffer(pos, 1))
                linkbits_tree:add(f.adv_link_chanoff, buffer(pos, 1))
                pos = pos + 1
            end
            
            frame_tree:set_len(pos - frame_start)
        end
    end
end

wihart:register_heuristic("wpan", function(buffer, pinfo, tree)
    if buffer:len() < 5 then
        return false
    end
    wihart.dissector(buffer, pinfo, tree)
    return true
end)