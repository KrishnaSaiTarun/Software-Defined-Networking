Mininet Project Part 1

BINGJUN WANG and KRISHNA SAI TARUN PASUPULETI

#####################################################

FILES:

advtopo.py
p2_final.py

#####################################################

How it use:

(1) controller setup

open putty.exe and get the connection (with Xming11) to Virtual Machine

transfer the file p2_final.py to folder pox/pox/misc as the same name (I used WinSCP for the file upload to the Virtual Machine)

$ cd
$ cd pox
$ ./pox.py log.level --DEBUG misc.p2_final

(2) topology setup

open putty.exe and get the connection (with Xming11) as the same name to Virtual Machine

transfer the file advtopo.py to folder pox/pox/misc as the same name (I used WinSCP for the file upload to the Virtual Machine)

$ cd
$ cd pox/pox/misc
$ sudo mn --custom advtopo.py --topo advtopo --mac --switch ovsk --controller remote

#####################################################

Test:


(1) ping unknown address

mininet> h3 ping -c1 100.100.0.1

(2) check the connectivity between two host

mininet> h3 ping -c1 h4
mininet> h3 ping -c1 h5

(3) check the connectivity in the system

mininet> pingall


(4)stop the topology and controller

in the topology window:

mininet> exit

$ sudo mn -c


in the controller window:

press Ctrl + c

