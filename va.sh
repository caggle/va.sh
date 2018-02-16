#!/bin/bash
 
function die()
{
    echo $*
    exit 127
}
# Kill any bg process on exit
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
 
[[ $# -lt 1 ]] && die "Host arg plz."
 
HOST="$1"
 
# Follows https://mana.mozilla.org/wiki/display/SECURITY/Vulnerability+Assessment+Process
# Make sure VPN or any jump is setup.
 
# Nessus
echo "Poping up Nessus. please scan manually for now."
ssh -L 8834:localhost:8834 nxp-con3.private.scl3.mozilla.com -N &
$BROWSER https://127.0.0.1:8834/#/
echo "Continuing with other scans in the meantime..."
 
#Nmap
echo "Performing TCP scan..."
ssh pentest-master.private.scl3.mozilla.com sudo nmap -v -Pn -sT -n --top-ports 1000  --open -T4 -oX scan_tcp.xml $HOST || die "tcp scan failed"
scp pentest-master.private.scl3.mozilla.com:./scan_tcp.xml ./ || die "scp failed"
echo "Scan results saved as scan_tcp.xml"
echo "Performing UDP scan..."
ssh pentest-master.private.scl3.mozilla.com sudo nmap -v -Pn -sU -sV -n -p 17,19,53,67,68,123,137,138,139,161,162,500,520,646,1900,3784,3785,5353,27015,27016,27017,27018,27019,27020,27960 --open -T4 -oX scan_udp.xml $HOST || die "udp scan failed"
scp pentest-master.private.scl3.mozilla.com:./scan_udp.xml ./ || die "scp failed"
echo "Scan results saved as scan_udp.xml"
 
#SSH?
echo "Checking if we need to ssh scan - NOTE if you see any non-standard SSH port it wont be scanned automatically"
grep 'state="open"' scan_tcp.xml | grep -q 'portid="22"' && ssh_scan -t $HOST
 
# ZAP
# check we got latest
echo "Checking we got latest docker image for zap.. note that you should be in the docker group for this to work"
echo "Note: no invasive scan is run automatically, for this refer to the docs"
echo "Note: No WP scan performed either, requires manual scan for WP"
docker pull owasp/zap2docker-weekly || die "failed to update zap"
docker run -t owasp/zap2docker-weekly zap-baseline.py -t $HOST
 
#dirb
echo "Running small dirb list (if specific webserver, you might want to do something manual here)"
dirb https://$HOST -f /usr/share/dirb/wordlists/small.txt || die "dirb failed to run"
 
# Observatory
echo "Running observatory scan"
scan=$(mktemp)
curl -X POST -d ""  https://http-observatory.security.mozilla.org/api/v1/analyze?host=$HOST > $scan || die "observatory scan failed"
while $(grep PENDING $scan); do
    echo "Waiting for scan to complete..."
    sleep 10
    curl -X POST -d ""  https://http-observatory.security.mozilla.org/api/v1/analyze?host=$HOST > $scan || die "observatory scan failed"
done
cat $scan && rm $scan
 
 
echo "All scan completed, yay!"
