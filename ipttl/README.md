# IP TTL
IP TTL Statistics (with a focus on NTP traffic)

A litle (**experimental**) tool that dumps IP TTL (or it's IPv6 equivalent Hop Limit)
from a tcpdump output, or a pcap-file and turns it into a gnuplot.

## build
Just do
```
gcc -g -O2 -Wall -o ipttl ipttl.c -lpcap
```
Or run `make`.
 
On Linux you may need the 'build-essential'-package first

## run
Just do:

```
./ipttlplot ./ntp.pcap
```
or
```
sudo tcpdump -i eth0 -n "udp and port 123 and host ntp.example.nl" -p --immediate-mode -U -s62 -w - 2> /dev/null | ./ipttlplot - > out.dat
```
But remember to adapt it to you need first, for example:

* Change the interface
* Change the filter expression (optionally - for additional fine tuning)

If you do `doit.sh`, you get all the steps in one go.

## example plot
![Alt text](/ipttl/example.png?raw=true "Example")

## rationale

This was a a little experiment with a twofold goal. First we would like to
see if we can get a rough idea of OS-es that contact our NTP-servers.

See:

* https://subinsb.com/default-device-ttl-values/
* https://packetpushers.net/ip-time-to-live-and-hop-limit-basics/

Second we where interested in the hop count of clients connecting to us to
see if this could shed some light on our anycast catchment or on NTP pool's GeoDNS
perhaps.

## future

The next step we foresee is to turn this into some sort of `dnstop` or
`dns-flood-detector` sort of tool. One that especially can trigger if there
is an anomaly due to an alledged DDoS. If many queries hit us from a
spoofed source address (victom), as part of a DoS-attempt, it is
likely to come from many different places, which might be discoverable
by looking at the IP TTL / Hop Limit.
 
