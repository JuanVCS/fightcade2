#!/bin/sh
# fightcade2 latency checker for Linux and OSX
# (c)2013-2017 Pau Oliva Fora (@pof)

# check latency using ping or traceroute if the host doesn't respond to pings
# for traceroute we take the RTT of the worst hop

ip=$1
if [ -z ${ip} ]; then
	echo "Usage: check-latency.sh <ip>"
	exit 1
fi

res=$(ping -nq -c1 -W1 ${ip} |grep " ms$" |awk '{print $4}' |cut -f 2 -d "/")
if [ -z "${res}" ]; then
	os=$(uname)
	case "$os" in
		"Linux") res=$(traceroute -n -q 1 -w 0.4 -N 16 -m 16 ${ip} |grep " ms$" |rev |cut -f 2 -d " " |rev |cut -f 1 -d "." |sort -nr |head -n 1) ;;
		"Darwin") res=$(traceroute -n -q 1 -w 1 -m 15 ${ip} 2>&1 |grep " ms$" |rev |cut -f 2 -d " " |rev |cut -f 1 -d "." |sort -nr |head -n 1) ;;
	esac
fi
if [ -z "${res}" ]; then
	echo "150"
else
	echo "$res" |cut -f 1 -d "."
fi
