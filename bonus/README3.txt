Mininet Project Bonus (Firewall)

BINGJUN WANG and KRISHNA SAI TARUN PASUPULETI

#####################################################

FILES:

mytopo.py
firewall.py

#####################################################

How it use:

(1) controller setup

open putty.exe and get the connection (with Xming11) to Virtual Machine

transfer the file firewall.py to folder pox/pox/misc as the same name (I used WinSCP for the file upload to the Virtual Machine)

$ cd
$ cd pox
$ ./pox.py log.level --DEBUG misc.firewall

(2) topology setup

open putty.exe and get the connection (with Xming11) to Virtual Machine

transfer the file mytopo.py to folder pox/pox/misc as the same name (skip if you did it in Part 1) (I used WinSCP for the file upload to the Virtual Machine)

$ cd
$ cd pox/pox/misc
$ sudo mn --custom mytopo.py --topo mytopo --mac --switch ovsk --controller remote

#####################################################

Test:


(1) open the Xming windows

mininet> xterm h2 h3


(2) check iperf for h2 and h3

mininet> xterm h2 h3

in host2:
$ iperf -s


in host3:
$ iperf -c 10.0.2.100

Block msg will pop up in controller window

(3)stop the topology and controller

in the topology window:

mininet> exit

$ sudo mn -c

in the controller window:

press Ctrl + c

