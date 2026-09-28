#!/bin/sh
# Regression test: dissect tests/synthetic_svr.pcap and compare the summary
# lines with tests/expected_summary.txt.  Use --update to re-record.
set -e
cd "$(dirname "$0")"
# isolated config dir so a personal init.lua does not load a second copy of the plugin
CFG=$(mktemp -d)
trap 'rm -rf "$CFG"' EXIT
WIRESHARK_CONFIG_DIR=$CFG tshark -r synthetic_svr.pcap -X lua_script:../128t_plugin.lua \
    -T fields -e frame.number -e 128t.has_metadata -e 128t.session_uuid -e 128t.service \
    -e 128t.drop_reason -e 128t.encrypted -e dns.qry.name -e _ws.malformed -e _ws.lua.error \
    -E occurrence=f > actual_summary.txt 2>&1
if [ "$1" = "--update" ]; then
    mv actual_summary.txt expected_summary.txt
    echo "expected_summary.txt updated"
    exit 0
fi
if diff -u expected_summary.txt actual_summary.txt; then
    rm actual_summary.txt
    echo "PASS"
else
    echo "FAIL"
    exit 1
fi
