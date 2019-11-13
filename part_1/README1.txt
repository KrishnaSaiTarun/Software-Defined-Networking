Mininet Project Part 1

BINGJUN WANG and KRISHNA SAI TARUN PASUPULETI

#####################################################

FILES:

mytopo.py
p1_final.py

#####################################################

How it use:

(1) controller setup

open putty.exe and get the connection (with Xming11) to Virtual Machine

transfer the file p1_final.py to folder pox/pox/misc as the same name (I used WinSCP for the file upload to the Virtual Machine)

$ cd
$ cd pox
$ ./pox.py log.level --DEBUG misc.p1_final

(2) topology setup

open putty.exe and get the connection (with Xming11) to Virtual Machine

transfer the file mytopo.py to folder pox/pox/misc as the same name (I used WinSCP for the file upload to the Virtual Machine)

$ cd
$ cd pox/pox/misc
$ sudo mn --custom mytopo.py --topo mytopo --mac --switch ovsk --controller remote

#####################################################

Test:


(1) ping unknown address

mininet> h1 ping -c1 100.100.0.1

(2) check the connectivity between two host

mininet> h1 ping -c1 h2
mininet> h2 ping -c1 h3

(3) check the connectivity in the system

mininet> pingall

(4) check the TCP bandwidth
mininet> iperf

(5) check the TCP bandwidth with Xming windows

mininet> xterm h1 h3

host3:
$ iperf -s

host1:
$ iperf -c 10.0.3.100

(6)stop the topology and controller

in the topology window:

mininet> exit

$ sudo mn -c

in the controller window:

press Ctrl + c

