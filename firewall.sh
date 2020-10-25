#!/bin/bash
#Original: http://www.hyenacloud.com/blog/?p=327
#Modified by Neoon

/sbin/iptables -D INPUT -m set --match-set blacklist src -j DROP
/sbin/ipset create blacklist hash:net hashsize 10000000 maxelem 200000
/sbin/iptables -I INPUT -m set --match-set blacklist src -j DROP
IP_TMP=/tmp/ip.tmp
IP_BLACKLIST=/root/IP-Blocking/ip-blacklist.conf
IP_BLACKLIST_TMP=/tmp/ip-blacklist.tmp

BLACKLISTS=(
"http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1" # Project Honey Pot Directory of Dictionary Attacker IPs
"http://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1" # TOR Exit Nodes
"http://www.maxmind.com/en/anonymous_proxies" # MaxMind GeoIP Anonymous Proxies
"http://danger.rulez.sk/projects/bruteforceblocker/blist.php" # BruteForceBlocker IP List
"http://www.spamhaus.org/drop/drop.lasso" # Spamhaus Don't Route Or Peer List (DROP)
"http://cinsscore.com/list/ci-badguys.txt" # C.I. Army Malicious IP List
"http://www.autoshun.org/files/shunlist.csv" # Autoshun Shun List
"http://lists.blocklist.de/lists/all.txt" # blocklist.de attackers
"https://iplists.firehol.org/files/firehol_level1.netset" #firehol_level1
)

for i in "${BLACKLISTS[@]}"
do
 curl "$i" > $IP_TMP
 grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' $IP_TMP >> $IP_BLACKLIST_TMP
done

sort $IP_BLACKLIST_TMP -n | uniq > $IP_BLACKLIST
rm $IP_BLACKLIST_TMP
wc -l $IP_BLACKLIST
/sbin/ipset flush blacklist

egrep -v "^#|^$" $IP_BLACKLIST | while IFS= read -r ip
do
 /sbin/ipset add blacklist $ip
done
