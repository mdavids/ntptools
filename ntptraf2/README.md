# NTPtraf2
NTP Statistics

A litle ncurses based tool that collects some NTP statistics from a live
tcpdump output, or a pcap-file.

## build
Just do
```
gcc -g -O2 -Wall -o ntptraf2 ntptraf2.c -lpcap -lncurses -lm
```
Or run 'make'.
 
Linux tip: you may need this first:
```
sudo apt install libncurses-dev libpcap-dev
```
(and obviously gcc has to be present, the 'build-essential'-package will provide you with that)

## run
Just do
```
sudo tcpdump -i eth0 -n "udp and port 123" -p --immediate-mode -U -s110 -w - 2> /dev/null | ./ntptraf2 -
```
Or adapt it to you need first, for example:

* Change the interface
* Change the filter expression

You can use tshark too!

## screenshot
![Alt text](/ntptraf2/screenshot2.png?raw=true "Screenshot")

## misc

Wireshark and Tshark are also great tools for peeking in NTP traffic! Here
are some examples:

Who are we sendint KoD RATE packets too?
```
tshark -i eth0 -f 'udp and port 123' -Y ntp.refid==52:41:54:45 -Tfields -e ip.dst -e ntp.refid
```
Get a rough idea of NTP versions:
```
tshark -c 100000 -Tfields -e ntp.flags.vn port 123 | sort | uniq -c | sort -rn | more
```

Or, if you are into it, try to fetch OUI information MAC addresses derived
from IPv6 SLAAC addresses:

```
tshark -r ./ntp.pcap -2 -R ipv6.dst_sa_mac -Nm -V | grep "Destination SA MAC" | sort | uniq
```

or
```
tshark -r ~/ntp.pcap -2 -R ipv6.dst_sa_mac -Nm -V | grep "Destination SA MAC" | awk '{print $4}' | awk -F\_ '{print $1}' | sort | uniq -c | sort -rn
```

or, for some live data:
```
sudo tshark -Y ipv6.dst_sa_mac -Nm -V | grep "Destination SA MAC"
```

Etc.
