local PLUGIN_VERSION = "2.0.0"
-----------------------------------------------------------------
-----------------------------------------------------------------
-- Wireshark 128T / SSR SVR metadata plugin
--
-- Please report any issues!
--
-- Author: Paulo Machado <paulo@sumaumatelecom.com.br>
--
-- TLV layouts follow the IETF Secure Vector Routing draft
-- (draft-menon-svr, section 10 "SVR Metadata Format").
--
-----------------------------------------------------------------
-----------------------------------------------------------------
--
-- To enable the plugin on the command line use:
--   wireshark -Xlua_script:<path to the script> <pcap file>
-- ex:
--   wireshark -Xlua_script:./128t_plugin.lua ./128t_udp.pcap
--
-- You can do the same on tshark!
--   -Y will filter for the specific udp or tcp stream
--   -O will expand only the SVR section of the packet
--   -V would expand everything including other layers like TCP/UDP/Ethernet/etc
-- ex:
--   tshark -Xlua_script:./128t_plugin.lua -O "128t_over_tcp" -Y "128t_over_tcp" -r ./128t_tcp.pcap
--
-----------------------------------------------------------------

local SVR_COOKIE = "4C48DBC6DDF6670C"
local BASE_HEADER_LEN = 12   -- cookie(8) + version/header length(2) + payload length(2)

set_plugin_info({
   version = PLUGIN_VERSION,
   author = "Paulo Machado <pmachado@sumaumatelecom.com.br>",
   repository = "https://github.com/128technology/128t-metadata-dissector"
})

local my128t_proto_gen = Proto("__128T","128T SVR Metadata")

local my128t_proto_udp = Proto("128T_over_UDP","128T SVR Metadata (UDP)")
local my128t_proto_tcp = Proto("128T_over_TCP","128T SVR Metadata (TCP)")

--
-- Preferences (Edit >> Preferences >> Protocols >> __128T)
--
my128t_proto_gen.prefs.track_sessions = Pref.bool("Track SVR sessions", true,
   "Remember the session carried by each waypoint flow, so packets without metadata "..
   "still show (and can be filtered by) their session UUID, service and tenant. "..
   "Also stops other dissectors (RTCP, TRDP, ...) from claiming SVR waypoint traffic.")
my128t_proto_gen.prefs.decode_inner = Pref.bool("Decode unencrypted inner UDP payload", true,
   "When a session is not payload-encrypted, hand the original UDP payload to the "..
   "dissector registered for the original destination port (e.g. DNS on 53).")

--
-- adding field name and subtree description text
--
local drop_reasons = {
   [0] = "Unknown", [1] = "Keep Alive", [2] = "Enable SVR Metadata",
   [3] = "Disable SVR Metadata", [6] = "Delete Session",
   [8] = "Session Health Check: state exists",
}

local f_metadata   = ProtoField.bytes("128t.metadata", "Metadata")
local f_dir        = ProtoField.uint16("128t.dir", "Session Key", base.DEC,
                        { [2] = "Forward", [3] = "Forward (IPv6)", [4] = "Reverse", [5] = "Reverse (IPv6)" })
local f_proto      = ProtoField.uint8("128t.proto", "Protocol", base.DEC, { [1] ="128t_icmp", [6] = "128t_tcp", [17] = "128t_udp", [58] = "128t_icmpv6" })
local f_src_ipv4   = ProtoField.ipv4("128t.src_ipv4", "IP")
local f_src_ipv6   = ProtoField.ipv6("128t.src_ipv6", "IPv6")
local f_src_port   = ProtoField.uint16("128t.src_port", "Port")
local f_dst_ipv4   = ProtoField.ipv4("128t.dst_ipv4", "IP")
local f_dst_ipv6   = ProtoField.ipv6("128t.dst_ipv6", "IPv6")
local f_dst_port   = ProtoField.uint16("128t.dst_port", "Port")
local f_src_tenant = ProtoField.string("128t.src_tenant", "Src Tenant")
local f_src_peer   = ProtoField.string("128t.src_peer", "Source Router")
local f_src_peer_path_id   = ProtoField.string("128t.src_peer_path_id", "Peer Pathway ID")
local f_src_peer_sec_name  = ProtoField.string("128t.src_peer_sec_name", "Security Policy")
local f_dst_peer           = ProtoField.string("128t.dst_peer", "Destination Router")
local f_service            = ProtoField.string("128t.service", "Service")
local f_session_uuid       = ProtoField.string("128t.session_uuid", "Session UUID")
local f_app_name           = ProtoField.string("128t.app_name", "Application Name")
local f_security_id        = ProtoField.uint32("128t.security_id", "Security Key Version")
local f_interface_id       = ProtoField.uint32("128t.interface_id", "Global Interface ID")
local f_encrypted          = ProtoField.bool("128t.encrypted", "Session Payload Encrypted")
local f_tcp_syn            = ProtoField.bool("128t.tcp_syn", "TCP SYN Packet (TCP carried as UDP)")
local f_disable_fwd        = ProtoField.bool("128t.disable_fwd_metadata", "Disable Forward Metadata")
local f_icmp_err_ipv4      = ProtoField.ipv4("128t.icmp_error_ipv4", "ICMP Error Location Address")
local f_icmp_err_ipv6      = ProtoField.ipv6("128t.icmp_error_ipv6", "ICMP Error Location Address")
local f_drop_reason        = ProtoField.uint8("128t.drop_reason", "Control Message Drop Reason", base.DEC, drop_reasons)
local f_src_nat_ipv4       = ProtoField.ipv4("128t.src_nat_ipv4", "Source NAT Address")
local f_remaining_time     = ProtoField.uint32("128t.remaining_session_time", "Remaining Session Time", base.UNIT_STRING, {" s"})
local f_health_check       = ProtoField.uint8("128t.health_check", "Session Health Check", base.DEC, { [1] = "Request", [2] = "Request/Timeout" })
local f_security_key       = ProtoField.bytes("128t.security_key", "Security Encryption Key")
local f_pm                 = ProtoField.bytes("128t.pm", "Path Metrics")
local f_pm_tx_color        = ProtoField.uint32("128t.pm.tx_color", "Tx Color", base.DEC, nil, 0xF0000000)
local f_pm_tx_time         = ProtoField.uint32("128t.pm.tx_time", "Tx Time Value (ms)", base.DEC, nil, 0x0FFFFFFF)
local f_pm_rx_color        = ProtoField.uint32("128t.pm.rx_color", "Rx Color", base.DEC, nil, 0xF0000000)
local f_pm_rx_time         = ProtoField.uint32("128t.pm.rx_time", "Rx Time Value (ms)", base.DEC, nil, 0x0FFFFFFF)
local f_pm_drop            = ProtoField.bool("128t.pm.drop", "Drop", 16, nil, 0x8000)
local f_pm_prev_rx_count   = ProtoField.uint16("128t.pm.prev_rx_count", "Previous Rx Color Count", base.DEC, nil, 0x7FFF)
local f_mcast              = ProtoField.bytes("128t.mcast", "Multicast")
local f_mcast_family       = ProtoField.uint8("128t.mcast.family", "Address Family", base.HEX, { [4] = "IPv4", [6] = "IPv6" })
local f_mcast_flags        = ProtoField.uint8("128t.mcast.flags", "Flags", base.HEX)
local f_mcast_src_ipv4     = ProtoField.ipv4("128t.mcast.src_ipv4", "Source")
local f_mcast_grp_ipv4     = ProtoField.ipv4("128t.mcast.group_ipv4", "Group")
local f_mcast_src_ipv6     = ProtoField.ipv6("128t.mcast.src_ipv6", "Source")
local f_mcast_grp_ipv6     = ProtoField.ipv6("128t.mcast.group_ipv6", "Group")
local f_mcast_egress_count = ProtoField.uint16("128t.mcast.egress_count", "Egress Router Count")
local f_mcast_egress       = ProtoField.string("128t.mcast.egress_router", "Egress Router")
local f_cookie             = ProtoField.bytes("128t.cookie", "cookie")
local f_meta_version       = ProtoField.new("Metadata version", "128t.meta_version", ftypes.UINT16, {""}, base.UNIT_STRING, 0xF000, "metadata version")
local f_meta_header_length = ProtoField.new("Metadata header length", "128t.meta_header_length", ftypes.UINT16, {" bytes"}, base.UNIT_STRING, 0x0FFF, "metadata header length")
local f_meta_header        = ProtoField.bytes("128t.meta_header", "Metadata header")
local f_payload_length     = ProtoField.uint16("128t.payload_length", "Metadata payload length", base.UNIT_STRING, {" bytes"})
local f_payload_header     = ProtoField.bytes("128t.payload_header", "Payload")
local f_meta_encrypted     = ProtoField.bytes("128t.meta_encrypted", "Encrypted metadata")
local f_false_positive     = ProtoField.bool("128t.false_positive", "False-positive marker (payload starts with the SVR cookie)")
local f_frag_header        = ProtoField.bytes("128t.frag_header", "Fragment Header")
local f_frag_extended_id   = ProtoField.bytes("128t.frag_extended_id", "Fragment Extended ID")
local f_frag_original_id   = ProtoField.bytes("128t.frag_original_id", "Fragment Original ID")
local f_frag_flags_0       = ProtoField.new("Fragment Flags", "128t.frag_flags_0", ftypes.UINT8, {[0]="reserved", [1]="reserved"}, base.DEC, 128, "flags: reserved")
local f_frag_flags_1       = ProtoField.new("Fragment Flags", "128t.frag_flags_1", ftypes.UINT8, {[0]="none", [1]="dont fragment "}, base.DEC, 64, "flags: dont fragment")
local f_frag_flags_2       = ProtoField.new("Fragment Flags", "128t.frag_flags_2", ftypes.UINT8, {[0]="no other fragments", [1]="more fragments"}, base.DEC, 32, "flags: more fragments")
local f_frag_offset        = ProtoField.new("Fragment Offset", "128t.frag_offset", ftypes.UINT16, {{0,0,"none"}, {1,0x1FFF," eight-byte segments in this fragment"}}, base.RANGE_STRING, 0x1FFF, "flags: offset")
local f_frag_large_seen_frag = ProtoField.bytes("128t.frag_large_seen_frag", "Largest Seen Fragment")
local f_service_sessions_number = ProtoField.uint64("128t.service_sessions_number", "Number of Sessions in Service")
local f_modify_req_header = ProtoField.bytes("128t.modify_req_header", "Modify Request Header")
local f_modify_req_f      = ProtoField.new("Modify Request Header F", "128t.modify_req_header_f", ftypes.UINT16, {}, base.DEC, 0x8000)
local f_modify_req_d      = ProtoField.new("Modify Request Header D", "128t.modify_req_header_d", ftypes.UINT16, {}, base.DEC, 0x4000)
local f_modify_req_res    = ProtoField.new("Modify Request Header RES", "128t.modify_req_header_res", ftypes.UINT16, {}, base.DEC, 0x3000)
local f_modify_req_seq    = ProtoField.new("Modify Request Sequence Number", "128t.modify_req_header_seq", ftypes.UINT16, {}, base.DEC, 0x0FFF)
-- session tracking (generated on every packet of a tracked waypoint flow)
local f_has_metadata      = ProtoField.bool("128t.has_metadata", "Packet carries SVR metadata")
local f_session_frame     = ProtoField.framenum("128t.session_frame", "Session metadata first seen in frame")
local f_inner             = ProtoField.string("128t.inner", "Original 5-tuple (forward)")
-- Note any new fields must be added to 'my128t_proto_gen.fields' below!!!!

--
-- generic fields
--
local f_length       = ProtoField.uint16("128t.len", "Length")
local f_bytes        = ProtoField.bytes("128t.bytes", "Bytes")
local f_text         = ProtoField.string("128t.text", "Text")
local f_orig_payload = ProtoField.bytes("128t.orig_payload", "Original Payload")

--
-- Metadata Field types
-- Text will be used as the field "Type" inside each field's own subitem
--
local type_names = {
  [1]  = "Fragment",
  [2]  = "Forward Context IPv4",
  [3]  = "Forward Context IPv6",
  [4]  = "Reverse Context IPv4",
  [5]  = "Reverse Context IPv6",
  [6]  = "Session UUID",
  [7]  = "Tenant Name",
  [8]  = "Global Interface ID",
  [10] = "Service Name",
  [11] = "Session Encrypted",
  [12] = "TCP SYN Packet",
  [13] = "Number of sessions",
  [14] = "Source Router Name",
  [15] = "Security Policy",
  [16] = "Security ID",
  [17] = "Destination Router Name",
  [18] = "Disable Forward Metadata",
  [19] = "Peer Pathway ID",
  [20] = "IPv4 ICMP Error Location Address",
  [21] = "IPv6 ICMP Error Location Address",
  [24] = "SVR Control Message",
  [25] = "IPv4 Source NAT Address",
  [26] = "Path Metrics",
  [28] = "Modify Request",
  [35] = "Application Name",
  [42] = "Remaining Session Time",
  [46] = "Session Health Check / Security Encryption Key",
  [50] = "Multicast Group Context",
  [51] = "Multicast Egress List",
}
local f_type    = ProtoField.uint16("128t.type", "Type",  base.DEC, type_names)

local ef_malformed  = ProtoExpert.new("128t.malformed", "Malformed SVR metadata", expert.group.MALFORMED, expert.severity.ERROR)
local ef_encrypted  = ProtoExpert.new("128t.meta_encrypted.expert", "Payload TLVs are encrypted (or not parseable)", expert.group.SECURITY, expert.severity.NOTE)
local ef_unknown    = ProtoExpert.new("128t.unknown_type", "Undocumented SVR metadata TLV", expert.group.UNDECODED, expert.severity.CHAT)
local ef_control    = ProtoExpert.new("128t.control", "SVR control message", expert.group.SEQUENCE, expert.severity.NOTE)

my128t_proto_gen.fields = {
 f_metadata, f_dir, f_proto, f_src_tenant, f_src_ipv4, f_src_ipv6, f_dst_ipv4, f_dst_ipv6, f_src_port, f_dst_port,
 f_src_peer, f_src_peer_path_id, f_src_peer_sec_name, f_dst_peer, f_service,
 f_session_uuid, f_app_name, f_security_id, f_interface_id, f_encrypted, f_tcp_syn, f_disable_fwd,
 f_icmp_err_ipv4, f_icmp_err_ipv6, f_drop_reason, f_src_nat_ipv4, f_remaining_time, f_health_check, f_security_key,
 f_pm, f_pm_tx_color, f_pm_tx_time, f_pm_rx_color, f_pm_rx_time, f_pm_drop, f_pm_prev_rx_count,
 f_mcast, f_mcast_family, f_mcast_flags, f_mcast_src_ipv4, f_mcast_grp_ipv4, f_mcast_src_ipv6, f_mcast_grp_ipv6,
 f_mcast_egress_count, f_mcast_egress,
 f_cookie, f_meta_version, f_meta_header_length, f_meta_header, f_payload_length, f_payload_header,
 f_meta_encrypted, f_false_positive,
 f_frag_header, f_frag_extended_id, f_frag_original_id, f_frag_flags_0, f_frag_flags_1, f_frag_flags_2, f_frag_offset, f_frag_large_seen_frag,
 f_type, f_length, f_bytes, f_text, f_orig_payload,
 f_service_sessions_number,
 f_modify_req_header, f_modify_req_f, f_modify_req_d, f_modify_req_res, f_modify_req_seq,
 f_has_metadata, f_session_frame, f_inner,
}
my128t_proto_gen.experts = { ef_malformed, ef_encrypted, ef_unknown, ef_control }

local proto_names = { [1] = "ICMP", [6] = "TCP", [17] = "UDP", [58] = "ICMPv6" }

local function type_label(t)
   return type_names[t] or ("Unknown ("..t..")")
end

--
-- Every handler gets:
--   tlv   : TvbRange of the whole TLV (type + length + value)
--   value : TvbRange of the value, or nil when length is 0
--   len   : value length
--   tree  : the SVR subtree
--   meta  : table collecting the decoded session attributes (info column / tracking)
--
local function add_tlv_header(t, tlv)
   t:add(f_type, tlv(0,2))
   t:add(f_length, tlv(2,2))
end

local function type_default(t_num, tlv, value, len, tree, meta)
   -- Unknown TLV (or a known one with an unexpected length):
   -- show printable values as text, anything else as bytes
   local t = tree:add(f_type, tlv(0,2))
   t:append_text(" ("..len.." bytes)")
   t:add(f_length, tlv(2,2))
   if value then
      local raw = value:raw()
      if raw:match("^[%w%p ]+$") then
         t:add(f_text, value)
         t:append_text(": \""..raw.."\"")
      else
         t:add(f_bytes, value)
      end
   end
   if not type_names[t_num] then
      t:add_proto_expert_info(ef_unknown)
   end
   return t
end

local function flag_tlv(field, meta_key)
   return function(t_num, tlv, value, len, tree, meta)
      local t = tree:add(field, tlv, true)
      add_tlv_header(t, tlv)
      if meta_key then meta[meta_key] = true end
   end
end

local function basic_tlv(field, meta_key, size)
   -- We are using TLV format for the metadata
   -- in general that means
   -- 2 bytes for type
   -- 2 bytes for length (of the next data field)
   -- x bytes for the actual data
   return function(t_num, tlv, value, len, tree, meta)
      if not value or (size and len ~= size) then
         return type_default(t_num, tlv, value, len, tree, meta)
      end
      local t = tree:add(field, value)
      add_tlv_header(t, tlv)
      if meta_key then meta[meta_key] = value:string() end
   end
end

local function type_session_key(t_num, tlv, value, len, tree, meta)
   -- Forward/Reverse context: src addr, dst addr, src port, dst port, protocol
   local alen = (t_num == 3 or t_num == 5) and 16 or 4
   if len ~= alen*2 + 5 then
      local t = type_default(t_num, tlv, value, len, tree, meta)
      t:add_proto_expert_info(ef_malformed, type_label(t_num).." has unexpected length "..len)
      return
   end
   local f_s, f_d = f_src_ipv4, f_dst_ipv4
   local src_ip, dst_ip
   if alen == 16 then
      f_s, f_d = f_src_ipv6, f_dst_ipv6
      src_ip = "["..tostring(value(0,16):ipv6()).."]"
      dst_ip = "["..tostring(value(16,16):ipv6()).."]"
   else
      src_ip = tostring(value(0,4):ipv4())
      dst_ip = tostring(value(4,4):ipv4())
   end
   local sport = value(alen*2,2):uint()
   local dport = value(alen*2+2,2):uint()
   local proto = value(alen*2+4,1):uint()
   local src = src_ip..":"..sport
   local dst = dst_ip..":"..dport
   local pname = proto_names[proto] or tostring(proto)

   local key_tree = tree:add(f_dir, tlv(0,2))
   key_tree:append_text(" ["..src.." -> "..dst.." "..pname.."]")
   key_tree:add(f_length, tlv(2,2))
   local t = key_tree:add("Src: "..src)
   t:add(f_s, value(0,alen))
   t:add(f_src_port, value(alen*2,2))
   t = key_tree:add("Dst: "..dst)
   t:add(f_d, value(alen,alen))
   t:add(f_dst_port, value(alen*2+2,2))
   key_tree:add(f_proto, value(alen*2+4,1))

   meta.dir = (t_num == 2 or t_num == 3) and "fwd" or "rev"
   meta.inner = src.." -> "..dst.." "..pname
   meta.inner_proto = proto
   -- the server side port: destination on forward keys, source on reverse keys
   meta.server_port = meta.dir == "fwd" and dport or sport
end

local function add_control(meta, text)
   meta.control = meta.control and (meta.control..","..text) or text
end

local function format_uuid(value)
   local h = value:bytes():tohex():lower()
   return h:sub(1,8).."-"..h:sub(9,12).."-"..h:sub(13,16).."-"..h:sub(17,20).."-"..h:sub(21,32)
end

--
-- These functions are used to dissect specialized fields
-- avoiding the default handler that will display "bytes"
-- This will also use correct types like strings or ipv4, etc.
--
local t_128t_dissect = {
  [1]  = function (t_num, tlv, value, len, tree, meta)
      if len < 10 then return type_default(t_num, tlv, value, len, tree, meta) end
      local t = tree:add(f_frag_header, tlv, "Fragment")
      add_tlv_header(t, tlv)
      t:add(f_frag_extended_id, value(0,4)) -- Extended ID
      t:add(f_frag_original_id, value(4,2)) -- Original ID
      t:add(f_frag_flags_0, value(6,1)) -- Flags bit 0
      t:add(f_frag_flags_1, value(6,1)) -- Flags bit 1
      t:add(f_frag_flags_2, value(6,1)) -- Flags bit 2
      t:add(f_frag_offset, value(6,2)) -- Fragment Offset
      t:add(f_frag_large_seen_frag, value(8,2)) -- Largest Seen Fragment
      meta.fragment = true
  end,

  [2]   = type_session_key,
  [3]   = type_session_key,
  [4]   = type_session_key,
  [5]   = type_session_key,

  [6]   = function (t_num, tlv, value, len, tree, meta)
      if len ~= 16 then return type_default(t_num, tlv, value, len, tree, meta) end
      meta.uuid_str = format_uuid(value)
      local t = tree:add(f_session_uuid, value, meta.uuid_str)
      add_tlv_header(t, tlv)
  end,

  [7]   = basic_tlv(f_src_tenant, "tenant"),
  [8]   = basic_tlv(f_interface_id, nil, 4),
  [10]  = basic_tlv(f_service, "service"),
  [11]  = flag_tlv(f_encrypted, "encrypted"),
  [12]  = flag_tlv(f_tcp_syn, "tcp_syn"),
  [13]  = basic_tlv(f_service_sessions_number, nil, 8),
  [14]  = basic_tlv(f_src_peer),
  [15]  = basic_tlv(f_src_peer_sec_name),
  [16]  = basic_tlv(f_security_id, nil, 4),
  [17]  = basic_tlv(f_dst_peer),
  [18]  = flag_tlv(f_disable_fwd, "disable_fwd"),
  [19]  = basic_tlv(f_src_peer_path_id),
  [20]  = basic_tlv(f_icmp_err_ipv4, nil, 4),
  [21]  = basic_tlv(f_icmp_err_ipv6, nil, 16),

  [24]  = function (t_num, tlv, value, len, tree, meta)
      if len ~= 1 then return type_default(t_num, tlv, value, len, tree, meta) end
      local t = tree:add(f_drop_reason, value)
      add_tlv_header(t, tlv)
      local reason = value:uint()
      local label = drop_reasons[reason] or ("drop-reason-"..reason)
      add_control(meta, label)
      t:add_proto_expert_info(ef_control, "SVR control message: "..label)
  end,

  [25]  = basic_tlv(f_src_nat_ipv4, nil, 4),

  [26]  = function (t_num, tlv, value, len, tree, meta)
      if len ~= 10 then return type_default(t_num, tlv, value, len, tree, meta) end
      local t = tree:add(f_pm, value)
      add_tlv_header(t, tlv)
      t:add(f_pm_tx_color, value(0,4))
      t:add(f_pm_tx_time, value(0,4))
      t:add(f_pm_rx_color, value(4,4))
      t:add(f_pm_rx_time, value(4,4))
      t:add(f_pm_drop, value(8,2))
      t:add(f_pm_prev_rx_count, value(8,2))
      meta.path_metrics = true
  end,

  [28]  = function (t_num, tlv, value, len, tree, meta)
      if len < 2 then return type_default(t_num, tlv, value, len, tree, meta) end
      local t = tree:add(f_modify_req_header, tlv, "Modify Request Header")
      add_tlv_header(t, tlv)
      t:add(f_modify_req_f, value(0,2)) -- bit 0
      t:add(f_modify_req_d, value(0,2)) -- bit 1
      t:add(f_modify_req_res, value(0,2)) -- Flags bit 2,3
      t:add(f_modify_req_seq, value(0,2)) -- sequence number in the last 12 bits
  end,

  [35]  = basic_tlv(f_app_name, "app"),
  [42]  = basic_tlv(f_remaining_time, nil, 4),

  [46]  = function (t_num, tlv, value, len, tree, meta)
      -- the draft uses type 46 both for the 1-byte Session Health Check
      -- header TLV and for the variable-length Security Encryption Key
      if len == 1 then
         local t = tree:add(f_health_check, value)
         add_tlv_header(t, tlv)
         add_control(meta, "Session Health Check")
      elseif value then
         local t = tree:add(f_security_key, value)
         add_tlv_header(t, tlv)
      else
         type_default(t_num, tlv, value, len, tree, meta)
      end
  end,

  [50]  = function (t_num, tlv, value, len, tree, meta)
      if len < 1 then return type_default(t_num, tlv, value, len, tree, meta) end
      local alen = value(0,1):uint() == 6 and 16 or 4
      if len < 2 + alen*2 + 1 then return type_default(t_num, tlv, value, len, tree, meta) end
      local t = tree:add(f_mcast, value):set_text("Multicast Group Context")
      add_tlv_header(t, tlv)
      t:add(f_mcast_family, value(0,1))
      t:add(f_mcast_flags, value(1,1))
      t:add(alen == 16 and f_mcast_src_ipv6 or f_mcast_src_ipv4, value(2,alen))
      t:add(alen == 16 and f_mcast_grp_ipv6 or f_mcast_grp_ipv4, value(2+alen,alen))
      t:add(f_proto, value(2+alen*2,1))
      meta.multicast = true
  end,

  [51]  = function (t_num, tlv, value, len, tree, meta)
      if len < 2 then return type_default(t_num, tlv, value, len, tree, meta) end
      local t = tree:add(f_mcast, value):set_text("Multicast Egress List")
      add_tlv_header(t, tlv)
      t:add(f_mcast_egress_count, value(0,2))
      local pos = 2
      while pos < len do
         local n = value(pos,1):uint()
         if pos + 1 + n > len then
            t:add_proto_expert_info(ef_malformed, "Egress list entry overruns the TLV")
            break
         end
         if n > 0 then t:add(f_mcast_egress, value(pos+1,n)) end
         pos = pos + 1 + n
      end
  end,
}

--
-- True when the TLVs in tvb[from, to) walk cleanly to exactly `to`.
--
local function tlvs_fit(tvbuf, from, to)
   local pos = from
   while pos + 4 <= to do
      pos = pos + 4 + tvbuf(pos+2,2):uint()
   end
   return pos == to
end

--
-- Dissect TLVs in tvb[from, to); returns the position where the walk stopped.
--
local function walk_tlvs(tvbuf, from, to, tree, meta)
   local pos = from
   while pos + 4 <= to do
      local t_num = tvbuf(pos,2):uint()
      local len = tvbuf(pos+2,2):uint()
      if pos + 4 + len > to then break end
      local value = len > 0 and tvbuf(pos+4,len) or nil
      local handler = t_128t_dissect[t_num] or type_default
      handler(t_num, tvbuf(pos,4+len), value, len, tree, meta)
      pos = pos + 4 + len
   end
   return pos
end

--
-- Session tracking: the metadata only rides on the first packets of each
-- direction of a waypoint flow. Remember what it said, per outer flow, so
-- every later packet of that flow can be tied back to its session.
--
local flows = {}         -- outer flow key -> session record (first pass state)
local frame_session = {} -- frame number -> session record (stable for re-dissection)
local decoded = {}       -- frame number -> true once its metadata was dissected

function my128t_proto_gen.init()
   flows = {}
   frame_session = {}
   decoded = {}
end

local function flow_key(pinfo, transport)
   local a = tostring(pinfo.src).."/"..pinfo.src_port
   local b = tostring(pinfo.dst).."/"..pinfo.dst_port
   if a > b then a, b = b, a end
   return transport.." "..a.." <-> "..b
end

local function remember_session(pinfo, transport, meta)
   local key = flow_key(pinfo, transport)
   local rec = flows[key]
   -- a different forward key or UUID on the same waypoint flow means the
   -- waypoint ports were reused by a new session
   if rec == nil
      or (meta.dir == "fwd" and rec.inner_fwd and rec.inner_fwd ~= meta.inner)
      or (meta.uuid_str and rec.uuid_str and rec.uuid_str ~= meta.uuid_str) then
      rec = { frame = pinfo.number, key = key }
      flows[key] = rec
   end
   if meta.dir == "fwd" then
      rec.inner_fwd = meta.inner
   elseif meta.dir == "rev" then
      rec.inner_rev = meta.inner
   end
   rec.uuid_str = rec.uuid_str or meta.uuid_str
   rec.service = rec.service or meta.service
   rec.tenant = rec.tenant or meta.tenant
   rec.app = rec.app or meta.app
   rec.encrypted = rec.encrypted or meta.encrypted
   rec.inner_proto = rec.inner_proto or meta.inner_proto
   rec.server_port = rec.server_port or meta.server_port
   return rec
end

local function add_session_info(tree, rec)
   tree:add(f_session_frame, rec.frame):set_generated()
   if rec.uuid_str then tree:add(f_session_uuid, rec.uuid_str):set_generated() end
   if rec.service then tree:add(f_service, rec.service):set_generated() end
   if rec.tenant then tree:add(f_src_tenant, rec.tenant):set_generated() end
   if rec.app then tree:add(f_app_name, rec.app):set_generated() end
   if rec.inner_fwd then tree:add(f_inner, rec.inner_fwd):set_generated() end
   tree:add(f_encrypted, rec.encrypted and true or false):set_generated()
end

local function session_summary(rec)
   local parts = {}
   parts[#parts+1] = rec.inner_fwd or rec.inner_rev
   if rec.service then parts[#parts+1] = "svc="..rec.service end
   if rec.uuid_str then parts[#parts+1] = "uuid="..rec.uuid_str:sub(1,8) end
   return table.concat(parts, " ")
end

local function set_info(pinfo, text)
   pinfo.cols.info:prepend(text.." | ")
   pinfo.cols.info:fence()
end

--
-- Hand an unencrypted original UDP payload to the dissector for the
-- session's server port (e.g. DNS on 53)
--
local function decode_inner(payload, pinfo, root, my128t_proto, inner_proto, server_port)
   if inner_proto ~= 17 or not server_port or not my128t_proto_gen.prefs.decode_inner then return end
   local sub = DissectorTable.get("udp.port"):get_dissector(server_port)
   if sub then
      pcall(function() sub:call(payload, pinfo, root) end)
      pinfo.cols.protocol = my128t_proto.name
   end
end

--
-- Continuation packet of a tracked waypoint flow (no metadata on it)
--
local function dissect_continuation(tvbuf, pinfo, root, my128t_proto, transport)
   local rec = frame_session[pinfo.number]
   if rec == nil and not pinfo.visited then
      rec = flows[flow_key(pinfo, transport)]
      frame_session[pinfo.number] = rec
   end
   if rec == nil then return 0 end
   pinfo.cols.protocol = my128t_proto.name
   local subtree = root:add(my128t_proto, tvbuf(), "128T SVR Session (no metadata on this packet)")
   subtree:add(f_has_metadata, false):set_generated()
   add_session_info(subtree, rec)
   set_info(pinfo, "SVR "..session_summary(rec))
   if tvbuf:len() > 0 then
      subtree:add(f_orig_payload, tvbuf()):set_text(
                  "Original Payload: "..tvbuf:len().." bytes"..(rec.encrypted and " (encrypted)" or ""))
      if not rec.encrypted then
         decode_inner(tvbuf, pinfo, root, my128t_proto, rec.inner_proto, rec.server_port)
      end
   end
   return tvbuf:len()
end

--
-- This is the actual dissector function in charge of
-- generating the information displayed in wireshark
--
local function dissect_metadata(tvbuf, pinfo, root, my128t_proto, transport)
   decoded[pinfo.number] = true
   pinfo.cols.protocol = my128t_proto.name
   local tvb_len = tvbuf:len()
   -- Main metadata header
   local header_length = tvbuf(8,2):bitfield(4,12) -- header length on the last 12 bits
   local payload_length = tvbuf(10,2):uint()
   -- header_length includes the 12-byte base header, so the metadata ends at
   -- header_length + payload_length (the original packet payload follows)
   local meta_end = header_length + payload_length
   local subtree = root:add(my128t_proto, tvbuf(0, math.min(math.max(meta_end, BASE_HEADER_LEN), tvb_len)), "128T SVR Metadata")
   subtree:add(f_has_metadata, true):set_generated()
   local t = subtree:add("Metadata header length: ",tvbuf(8,2),header_length,"bytes"):set_generated()
   t:add(f_cookie,tvbuf(0,8))
   t:add(f_meta_version,tvbuf(8,2))  -- 0x1 by default on the first 4 bits
   t:add(f_meta_header_length,tvbuf(8,2))
   local pt = subtree:add(f_payload_length,tvbuf(10,2))

   if header_length < BASE_HEADER_LEN or meta_end > tvb_len then
      subtree:add_proto_expert_info(ef_malformed,
         "Metadata length "..meta_end.." (header "..header_length..", payload "..payload_length..
         ") does not fit the "..tvb_len.." byte L4 payload")
      set_info(pinfo, "SVR metadata (malformed)")
      return tvb_len
   end
   t:add(f_meta_header,tvbuf(0,header_length))
   if payload_length > 0 then
      pt:add(f_payload_header,tvbuf(header_length,payload_length))
   end

   local meta = {}
   if meta_end == BASE_HEADER_LEN then
      subtree:add(f_false_positive, tvbuf(0,BASE_HEADER_LEN), true)
      add_control(meta, "false-positive-marker")
   end

   --
   -- Header TLVs are guaranteed unencrypted. Payload TLVs may be encrypted:
   -- they are only decoded when all TLVs walk cleanly to the end of the metadata.
   --
   local walk_end = meta_end
   if not tlvs_fit(tvbuf, BASE_HEADER_LEN, meta_end) then
      walk_end = header_length
   end
   local pos = walk_tlvs(tvbuf, BASE_HEADER_LEN, walk_end, subtree, meta)
   if pos < meta_end then
      local et = subtree:add(f_meta_encrypted, tvbuf(pos, meta_end - pos))
      et:append_text(" ("..(meta_end - pos).." bytes)")
      et:add_proto_expert_info(ef_encrypted)
      meta.meta_encrypted = true
   end

   --
   -- session tracking
   --
   local rec = frame_session[pinfo.number]
   -- (packets quoted inside ICMP errors do not describe the outer flow)
   if rec == nil and not pinfo.visited and not pinfo.in_error_pkt
      and my128t_proto_gen.prefs.track_sessions then
      if meta.inner or meta.uuid_str then
         rec = remember_session(pinfo, transport, meta)
      else
         rec = flows[flow_key(pinfo, transport)]
      end
      frame_session[pinfo.number] = rec
      -- route every later packet of this waypoint flow to this dissector
      pinfo.conversation = my128t_proto
   end
   if rec then
      local st = subtree:add(my128t_proto_gen, tvbuf(0,0), "SVR session")
      st:set_generated()
      add_session_info(st, rec)
   end

   --
   -- Info column
   --
   local info = { "SVR" }
   if meta.dir then info[#info+1] = meta.dir end
   if meta.inner then info[#info+1] = meta.inner end
   if meta.service then info[#info+1] = "svc="..meta.service end
   if meta.tenant then info[#info+1] = "tenant="..meta.tenant end
   if meta.app then info[#info+1] = "app="..meta.app end
   if meta.control then info[#info+1] = "ctrl="..meta.control end
   if meta.path_metrics then info[#info+1] = "path-metrics" end
   if meta.multicast then info[#info+1] = "multicast" end
   if meta.disable_fwd then info[#info+1] = "disable-fwd-metadata" end
   if meta.encrypted then info[#info+1] = "enc" end
   if meta.meta_encrypted then info[#info+1] = "meta-enc" end
   if not meta.inner and rec then info[#info+1] = "("..session_summary(rec)..")" end
   set_info(pinfo, table.concat(info, " "))

   --
   -- marking the original packet payload being transported
   --
   local orig_len = tvb_len - meta_end
   if orig_len > 0 then
      local encrypted = meta.encrypted or (rec and rec.encrypted)
      local ot = root:add(f_orig_payload, tvbuf(meta_end, orig_len)):set_text(
                          "Original Payload: "..orig_len.." bytes"..(encrypted and " (encrypted)" or ""))
      ot:add(f_length, orig_len):set_generated()
      if not encrypted then
         decode_inner(tvbuf(meta_end, orig_len):tvb(), pinfo, root, my128t_proto,
                      meta.inner_proto or (rec and rec.inner_proto),
                      (rec and rec.server_port) or meta.server_port)
      end
   end
   return tvb_len
end

local function has_cookie(tvbuf)
   return tvbuf:len() >= BASE_HEADER_LEN and tostring(tvbuf(0,8):bytes()) == SVR_COOKIE
end

local function dissect(tvbuf, pinfo, root, my128t_proto, transport)
   if has_cookie(tvbuf) then
      return dissect_metadata(tvbuf, pinfo, root, my128t_proto, transport)
   end
   return dissect_continuation(tvbuf, pinfo, root, my128t_proto, transport)
end

function my128t_proto_udp.dissector(tvbuf,pktinfo,root)
   return dissect(tvbuf, pktinfo, root, my128t_proto_udp, "udp")
end

function my128t_proto_tcp.dissector(tvbuf,pktinfo,root)
   return dissect(tvbuf, pktinfo, root, my128t_proto_tcp, "tcp")
end

---
-- NOTE: the heuristics never see some SVR packets:
--       - TCP retransmissions (SSR repeats the metadata on retransmitted
--         first segments, which TCP analysis does not hand to subdissectors)
--       - waypoint ports another dissector owns (e.g. TRDP 17224/17225)
--       The postdissector below decodes those afterwards. To also keep the other
--       dissector off those ports enable "Try heuristic sub-dissectors first"
--       for UDP/TCP (tshark: -o udp.try_heuristic_first:TRUE).
--
local function heur_dissect_128t_udp(tvbuf,pktinfo,root)
   if not has_cookie(tvbuf) then return false end
   dissect_metadata(tvbuf, pktinfo, root, my128t_proto_udp, "udp")
   return true
end

local function heur_dissect_128t_tcp(tvbuf,pktinfo,root)
   if not has_cookie(tvbuf) then return false end
   dissect_metadata(tvbuf, pktinfo, root, my128t_proto_tcp, "tcp")
   return true
end

--
-- Postdissector fallback: SVR metadata that no heuristic was offered
--
local my128t_proto_post = Proto("__128T_fallback", "128T SVR Metadata (fallback)")
local f_udp_payload = Field.new("udp.payload")
local f_tcp_payload = Field.new("tcp.payload")

function my128t_proto_post.dissector(tvbuf, pinfo, root)
   if decoded[pinfo.number] or pinfo.in_error_pkt then return end
   for _, pair in ipairs({ { f_udp_payload, my128t_proto_udp, "udp" },
                           { f_tcp_payload, my128t_proto_tcp, "tcp" } }) do
      local fi = pair[1]()
      if fi and fi.range and fi.len >= BASE_HEADER_LEN then
         local payload = fi.range:tvb()
         if has_cookie(payload) then
            dissect_metadata(payload, pinfo, root, pair[2], pair[3])
            return
         end
      end
   end
end

--
-- Tools >> 128T SVR Sessions (GUI only): one line per tracked waypoint flow
--
local function sessions_window()
   local win = TextWindow.new("128T SVR Sessions")
   local lines = {}
   for _, rec in pairs(flows) do
      lines[#lines+1] = string.format("%-7d %-36s  %s  svc=%s tenant=%s%s\n        waypoint %s\n",
         rec.frame, rec.uuid_str or "(no uuid)", rec.inner_fwd or rec.inner_rev or "?",
         rec.service or "-", rec.tenant or "-", rec.encrypted and " enc" or "", rec.key)
   end
   table.sort(lines, function(a, b) return tonumber(a:match("^%d+")) < tonumber(b:match("^%d+")) end)
   win:set(#lines.." SVR waypoint flows tracked. Filter one with: 128t.session_uuid == \"<uuid>\"\n\n"..
           "frame   uuid                                  original 5-tuple\n"..table.concat(lines))
end

-- verify tshark/wireshark version is good enough - needs to be 3.0+
local major = tonumber((get_version():match("^(%d+)%."))) or 0
if major < 3 then
   error("\n\nSorry, but your Wireshark/Tshark version is too old for this script!\n"..
         "This script needs Wireshark/Tshark version 3.0 or higher.\n")
end

-- now register that heuristic dissector into the udp heuristic list
my128t_proto_udp:register_heuristic("udp",heur_dissect_128t_udp)
my128t_proto_tcp:register_heuristic("tcp",heur_dissect_128t_tcp)

DissectorTable.get("tcp.port"):add_for_decode_as(my128t_proto_tcp)
DissectorTable.get("udp.port"):add_for_decode_as(my128t_proto_udp)

register_postdissector(my128t_proto_post)

if gui_enabled() then
   register_menu("128T SVR Sessions", sessions_window, MENU_TOOLS_UNSORTED)
end
