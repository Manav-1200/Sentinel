#!/bin/bash
# warmup_traffic.sh
# ====================
# Generates a quick burst of VARIED, representative "normal" traffic,
# specifically to give Sentinel's anomaly detector a good warm-up
# baseline fast — without needing to wait for a long real warm-up
# period (500 flows) to organically encounter the same traffic
# variety.
#
# Why variety matters more than raw count: Isolation Forest learns
# what "normal" looks like from the SHAPE of the traffic it's shown
# during warm-up. A short warm-up that happens to be mostly DNS
# lookups never sees an mDNS or SSDP packet — so when one legitimately
# shows up later, it can look anomalous purely because the model's
# training diet was too narrow, not because anything is actually
# wrong. This script deliberately generates one of each common
# "normal" traffic type your network already produces, several times
# each, so even a SHORT warmup_flows setting in config.yaml still
# covers a realistic variety.
#
# Usage:
#   chmod +x warmup_traffic.sh
#   ./warmup_traffic.sh
#
# Run this in a second terminal while `python main.py` is warming up
# in the first.

echo "Generating varied warm-up traffic..."
echo "(DNS, HTTPS, ICMP, mDNS/SSDP discovery — repeated several times)"
echo ""

for round in 1 2 3 4 5; do
    echo "Round $round/5..."

    # DNS lookups - several different domains, so it's not just one
    # repeated query pattern
    for domain in example.com wikipedia.org github.com cloudflare.com debian.org; do
        curl -s --max-time 2 "https://$domain" > /dev/null 2>&1 &
    done
    wait

    # ICMP - a small ping burst (varied target so it's not always the
    # exact same flow key)
    ping -c 2 8.8.8.8 > /dev/null 2>&1
    ping -c 2 1.1.1.1 > /dev/null 2>&1

    # A brief pause lets mDNS/SSDP discovery traffic (generated
    # passively by your own devices on the LAN) get captured
    # naturally during this window, without us needing to fake it.
    sleep 1
done

echo ""
echo "Done. Check Sentinel's terminal — warm-up should now include a"
echo "representative mix of DNS, HTTPS, ICMP, and discovery traffic."