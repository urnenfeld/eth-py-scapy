# eth-py-scapy
Automotive Ethernet SOME-IP/SD Scapy extensions (Autosar 4.2)

## 1. What is this?
**_eth-py-scapy_** is a Python package implementing Automotive Ethernet SOME-IP/SD protocol over Scapy.

It's meant to be used as a central pillar to design and implement the "host end" of a _'uC <--> PC'_ net topology in a flexible and effective way. Due to its multiplatform nature, you can use as "host end" devices ranging from  a full fledged PC to a Raspberry Pi (or many!), being then able to build complex SOME-IP/SD networks on the cheap.

Either if you need to test your ECU or microcontrolled based SOME-IP/SD implementation, or just want to learn how SOME-IP/SD works, **_eth-py-scapy_** is here to help you.

## 2. Configuration

### 2.1 VLAN

Depending on your net's topology design, it might be that VLAN (IEEE 802.1q) tagging is required. With Linux, it's a breeze to get it working, just follow a guideline like this one : https://wiki.ubuntu.com/vlan

For Windows systems (at least up to Win7), as far as we know, VLAN configuration depended totally on the capabilities of your internet interface's driver, so choose your hardware wisely!

### 2.2 Interface configuration (Linux)
Below you can find an example _/etc/network/interfaces_ for _eth1_, both with/without VLAN.
```
# eth1
iface eth1 inet static
    address 10.0.0.1
    netmask 255.255.255.0
# VLAN eth1
iface eth1.10 inet static
    address 10.0.0.11
    netmask 255.255.255.0
```
Now you're just an _ifup_ away from completing the configuration :
```
$sudo ifup eth1.10    
```
## 3. Build your own test collection
We now that sometimes project's timings are so tight, that every help available could make a difference, so we decided to include a very _small and simple_ test infrastructure in order to build test cases from day one (let us insist on the _small an simple_ fact, we invite you to grab **eth-py-scapy** and adapt it to your own test suite).

### 3.1 _auto_eth_test.py_ and _testcases_ folder
```
/eth-py-scapy/auto_eth_test.py
/eth-py-scapy/testcases
/eth-py-scapy/testcases/test_base.py
/eth-py-scapy/testcases/test_example.py
/eth-py-scapy/testcases/test_someip.py
```
**_test_cases_** folder is meant to hold multiple TestCollections definitions, containing each of them a number of TestCases.

On the other hand, **auto_eth_test.py** is the launcher that takes care of autoexecuting all TestCollections found and formatting TestCases' results presentation. Take a look at its implementation and personalize it!

### 3.2 TestCase creation and _auto_execution
Creating a new TestCollection is as easy as :
- create a new python file within _testcases_ folder. Each file represents a test _category_.
- within previous file, create a Subclass of baseTest. Populate this class with r'^test.*' functions representing _test cases_.
- launch _auto_eth_test.py_. If you have defined everything correctly, your test collection will be automatically launched.

Use the functions provided by _baseTest_ to organize our test cases and define how feedback is reported from them (error/warning messages ...). As reference, please observe the examples provided.

## 4. Virtual environment
We now this might not be the best distribution method available, but using _virtualenv_ we are almost completely sure that you *will* be able to play with _eth-py-scapy_ right out of the git clone ;)
Only requirement is to have Python installed on your system.

### 4.1 Restore virtualenv
Open a bash console and enter _virualenv_ folder, from there execute following commands:
```
$ virtualenv env
$ source env
$pip install -r requirements.txt
```
Now you have your new and shiny virtual enviroment ready!

### 4.2 Run it!!
In order to run _auto_eth_test.py_ :
- activate virtualenv : ```$source virtualenv/env/bin/activate```
- execute auto_eth_test.py using sudo
  - option 1 (specify path to python bin within virtualenv) : ```$sudo ./virtualenv/env/bin/python auto_eth_test.py```
  - option 2 (make etester.py executable, add #!./virtualenv/env/bin/python as script 1st line) : ```$sudo ./auto_eth_test.py```

Once you are finished, deactivate virtualenv with ```deactivate```

### 5. References
- http://www.secdev.org/projects/scapy/
- http://resources.infosecinstitute.com/port-scanning-using-scapy/
