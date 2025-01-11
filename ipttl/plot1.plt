set title "IP TTLs"

# Linux/MAC OSX systems
set arrow from 64, graph 0 to 64, graph 1 nohead lw 2 lc rgb 'red'
# Windows systems
set arrow from 128, graph 0 to 128, graph 1 nohead lw 2 lc rgb 'red'
# Network devices like routers
set arrow from 255, graph 0 to 255, graph 1 nohead lw 2 lc rgb 'red'

set xrange [0:255] 
set xtics 10
set logscale y

plot 'out.dat' with impulses lw 2
