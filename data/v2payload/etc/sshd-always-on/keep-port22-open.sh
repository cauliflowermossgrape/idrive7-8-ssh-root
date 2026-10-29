#!/bin/sh
# sshd-always-on.sh
# Keeps "tcp dport 22 accept" at the top of the ip/ip6 input chains, so SSH is not dropped
# when firewalldZ removes its debug-mode rules. Re-checks every 15 s.
while :; do
    for fam in ip ip6; do
        if /usr/sbin/nft list chain $fam filter input >/dev/null 2>&1 &&
           ! /usr/sbin/nft list chain $fam filter input | grep -qE '^[[:space:]]*tcp dport 22 accept$'; then
            /usr/sbin/nft insert rule $fam filter input tcp dport 22 accept && echo "port 22 opened ($fam)"
        fi
    done
    sleep 15
done
