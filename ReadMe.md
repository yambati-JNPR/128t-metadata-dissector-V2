# Overview

This plugin will decode the unencrypted metadata information present on SVR packets.
Any packets containing metadata will also be marked as either:
 - 128t_over_tcp 
 - 128t_over_udp

(**Tip**: you can use that as filters on Wireshark and tshark!)

The expected output is a new "128T SVR Metadata" header on SVR packets.

You can use '128t_over_tcp' or '128t_over_udp' as filters on the GUI or tshark to filter packets containing metadata.

You can also 'right click' on the metadata information and add them as filters on the GUI.

(**Tip**: you can filter by tenant name for example)

You can also use Wireshark's GUI
  ```sh
     View -> Coloring Rules
  ```
To color any SVR packets accordingly.

**Requirements**:

  - Wireshark 3.0 or greater (tested with 4.6)
  - It should work on any OS (let me know if you find any issues!)
  - 128T / SSR version 3.X or later (tested against SSR 5.x/6.x captures)

**Note**: Encrypted packets will be marked but not decrypted at this time!

## What gets decoded

TLV layouts follow the IETF Secure Vector Routing draft
([draft-menon-svr](https://datatracker.ietf.org/doc/draft-menon-svr/), section 10):

| Type | Attribute | Filter field |
|---|---|---|
| 1 | Fragment | `128t.frag_*` |
| 2 / 3 | Forward context IPv4 / IPv6 | `128t.dir == 2`, `128t.src_ipv4`, `128t.src_ipv6`, `128t.src_port`, ... |
| 4 / 5 | Reverse context IPv4 / IPv6 | `128t.dir == 4`, ... |
| 6 | Session UUID | `128t.session_uuid` |
| 7 | Tenant name | `128t.src_tenant` |
| 10 | Service name | `128t.service` |
| 11 | Session (payload) encrypted | `128t.encrypted` |
| 12 | TCP SYN packet (TCP carried as UDP) | `128t.tcp_syn` |
| 14 / 17 | Source / destination router name | `128t.src_peer`, `128t.dst_peer` |
| 15 | Security policy | `128t.src_peer_sec_name` |
| 16 | Security ID (key version) | `128t.security_id` |
| 18 | Disable forward metadata (handshake ack) | `128t.disable_fwd_metadata` |
| 19 | Peer pathway ID | `128t.src_peer_path_id` |
| 20 / 21 | ICMP error location address | `128t.icmp_error_ipv4`, `128t.icmp_error_ipv6` |
| 24 | SVR control message (drop reason) | `128t.drop_reason` |
| 25 | IPv4 source NAT address | `128t.src_nat_ipv4` |
| 26 | Path metrics | `128t.pm.*` |
| 35 | Application name | `128t.app_name` |
| 42 | Remaining session time | `128t.remaining_session_time` |
| 46 | Session health check / security encryption key | `128t.health_check`, `128t.security_key` |
| 50 / 51 | Multicast group context / egress list | `128t.mcast.*` |

Types 8, 13 and 28 keep their earlier decoding. Undocumented types are still shown
(as text when printable) and flagged with a "chat" expert item, `128t.unknown_type`.

Other fields worth knowing:

  - `128t.has_metadata`: true on packets carrying metadata, false on later packets of a tracked session
  - `128t.session_frame`: the frame where the session's metadata was first seen (clickable)
  - `128t.inner`: the original (forward) 5-tuple as text
  - `128t.meta_encrypted`: payload TLVs that could not be parsed (metadata encryption)
  - `128t.false_positive`: 12-byte "false positive" header (the payload merely started with the cookie)
  - `128t.orig_payload`: the original packet payload carried after the metadata
  - `128t.malformed`: expert item for metadata that does not fit the packet

## Session tracking

SVR metadata only rides on the first packets of each direction of a session. The
plugin remembers what the metadata said for each waypoint flow, then:

  - adds the session UUID, service, tenant, application and original 5-tuple (as
    generated fields) to **every** packet of that waypoint flow, so
    `128t.session_uuid == "eab7019d-7421-4d58-9b31-327b466e6137"` shows the whole
    session, both directions, including packets without metadata
  - makes itself the conversation dissector for the waypoint flow, so later packets
    are no longer mis-decoded as RTCP, TRDP, SCOP, ...
  - hands the original UDP payload of unencrypted sessions to the dissector for the
    session's server port (for example DNS on 53)
  - lists every tracked session under **Tools >> 128T SVR Sessions** (GUI)

Both behaviours can be switched off under
Edit >> Preferences >> Protocols >> __128T.

The Info column is prefixed with a summary such as
`SVR fwd 10.1.1.10:40000 -> 8.8.8.8:53 UDP svc=DNS tenant=blue app=DNS enc`.

The best way to use the plugin is to capture sessions using the 'session capture' described [here](https://www.juniper.net/documentation/us/en/software/session-smart-router/docs/ts_packet_capture/#selective-packet-capture).
That way you will see both the actual session and SVR unencrypted in the same capture.

Please report any issues!

At this point you should find lots of them :-)

## Using the plugin

To enable the plugin on the command line use:
  ```
  wireshark -Xlua_script:<path to the script> <pcap file>
  or
  tshark -Xlua_script:<path to the script> -r <pcap file> [filter]
  ```
ex:
  ```
  wireshark -Xlua_script:./128t_plugin.lua ./128t_udp_cript.pcap
  
  tshark -V -Xlua_script:./128t_plugin.lua -r ./128t_udp_cript.pcap '128t_over_udp'
  
  tshark -V -Xlua_script:./128t_plugin.lua -r ./128t_udp_cript.pcap '128t.src_tenant == "voip1"'
  ```

On tshark we can use "-T fields -e <filed name>" and display only selected 128t fields like:
  ```
tshark -V -r ./128T_newMetaData.pcap -Y 128t.src_peer=="Sumauma" -Tfields -e 128t.src_peer -e 128t.src_tenant -e 128t.src_ipv4 -e 128t.dst_ipv4 -e 128t.service
Sumauma	tntVlan600	172.31.11.157	172.31.18.20	toCore600
  ```

Every packet of one SVR session (both directions, with or without metadata), one line per packet:
  ```
tshark -X lua_script:./128t_plugin.lua -r capture.pcap -Y '128t.session_uuid == "eab7019d-7421-4d58-9b31-327b466e6137"'
  ```

One line per session (forward metadata packets only):
  ```
tshark -X lua_script:./128t_plugin.lua -r capture.pcap -Y '128t.dir == 2' -T fields -E occurrence=f \
       -e 128t.session_uuid -e 128t.src_ipv4 -e 128t.src_port -e 128t.dst_ipv4 -e 128t.dst_port \
       -e 128t.proto -e 128t.service -e 128t.src_tenant -e 128t.app_name | sort -u
  ```
  
To add the plugin to wireshark's init files so it will be automatically executed:

On **Windows**:
```
Edit the file: 
   /<Program files>/wireshark/init.lua
At the end of the file add the following line:
   dofile(DATA_DIR.."128t_plugin.lua")
Copy the 128t_plugin.lua file to:
   /<Program files>/wireshark/
```

On **OSX**
```
Edit:
   ~/.config/wireshark/init.lua
Add the a line at the end of the file with the full path for the lua script, like:
   dofile("/src/128t_plugin/metadata-dissector/128t_plugin.lua")
```

On **Linux** 
```
Edit:
   ~/.wireshark/init.lua
Add the a line at the end of the file with the full path for the lua script, like:
   dofile("/src/128t_plugin/metadata-dissector/128t_plugin.lua")
```

To disable the plugin, just remove the line from init.lua

## Known issues

+ Payload encryption and metadata encryption are reported, but not decrypted
+ Sessions whose metadata packets happened before the capture started cannot be tracked, so their waypoint packets may still be decoded as some other protocol
+ Some metadata packets are never offered to the heuristic dissectors: TCP retransmissions (SSR repeats the metadata on retransmitted first segments), and waypoint ports that another dissector owns (for example TRDP on 17224/17225). A post-dissector decodes those anyway. To also stop the other dissector from running on them, enable "Try heuristic sub-dissectors first" for UDP/TCP (tshark: `-o udp.try_heuristic_first:TRUE -o tcp.try_heuristic_first:TRUE`)
+ With `tshark -T fields -e _ws.col.info`, the Info-column prefix is missing on packets decoded by the post-dissector (the normal tshark output and the GUI show it)

This release was tested against SSR 5.x/6.x metadata (see `tests/` for a synthetic regression capture):

```
python3 tests/make_synthetic_pcap.py   # regenerate tests/synthetic_svr.pcap
tests/run_tests.sh                     # PASS / FAIL (tests/run_tests.sh --update to re-record)
```

Please report any issues, false positives or problems you might find!
(If possible also sendme the offending .pcap file.)

## Possible improvements

+ Lua has a prolem where it is not possible to add multiple heuristic dissectors with the same name, because of that I was forced to create those two protocol names:
   - "128t_over_tcp"
   - "128t_over_udp"
  When I find a way to fix that we will be able to use only "128t" as the filter.
+ Add a right-click "Filter on this SVR session" entry (`register_packet_menu`, Wireshark 3.6+)
+ Tie the original (pre-SVR) client packets on the LAN side to their SVR session

  

