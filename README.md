# eth-py-scapy
Automotive Ethernet SOME-IP/SD Scapy extensions (Autosar 4.2)

## Configuration (VLAN, Ethernet interfaces)

Depending on how you design your net's topology, it might be that VLAN (IEEE 802.1q) tagging is required. With Linux, it's a breeze to get it working, just follow a guideline like this one : https://wiki.ubuntu.com/vlan

### Interface configuration (linux)
iface eth1.10 inet static
    address 10.0.0.11
    netmask 255.255.255.0

$sudo ifup eth1.10    

## Execution
- set virtualenv : $source virtualenv/env/bin/activate
- execute etester.py using sudo
-- option 1 (specify path to python bin within virtualenv) : $sudo ./virtualenv/env/bin/python etester.py
-- option 2 (make etester.py executable, add #!./virtualenv/env/bin/python as script 1st line) : $sudo ./etester.py

## Wireshark as non root
$ sudo apt-get install wireshark
$ sudo dpkg-reconfigure wireshark-common 
$ sudo usermod -a -G wireshark $USER

### References
http://www.secdev.org/projects/scapy/
http://resources.infosecinstitute.com/port-scanning-using-scapy/
