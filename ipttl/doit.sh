#!/bin/bash

echo "# X	Y" > out.dat
./ipttlplot ./ntp.pcap | grep -v 64 | sort -n | uniq -c | awk '{print $2"\t"$1}' >> out.dat
gnuplot --persist plot1.plt