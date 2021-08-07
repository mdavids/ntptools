set title "IP TTLs"

# Linux
set arrow from 64, graph 0 to 64, graph 1 nohead lw 2 lc rgb 'red'
# Windows
set arrow from 128, graph 0 to 128, graph 1 nohead lw 2 lc rgb 'red'
# Old Linux
set arrow from 255, graph 0 to 255, graph 1 nohead lw 2 lc rgb 'red'

set logscale y

plot 'out.dat' with impulses lw 2
