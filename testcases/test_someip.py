# File  : test_someip
# Who   : jamores
# Some SOME/IP stuff 
# 
# note :    keep in mind that most of following tests are only meant as scapy_someip capabilities (to be captured and
#           analized with wireshark.In a normal test environment, some other device on you network should reply to generated test
#           requests

from test_base import baseTest

from scapy.all import *
from scapy_someip import scapy_helper as helper
from scapy_someip import *

import threading
import time

ETH_IFACE_SRC = "eth1.10"

class test_somepip(baseTest):

    def __init__(self):
        # call superclass constructor providing test collection category
        baseTest.__init__(self,"SOME/IP")

    # Test 00 : SOME/IP Magic cookie
    #   example of "fire and forget" communication
    def test_00(self):
        """ SOME/IP Magic cookie (client -> server)."""
        err_msg = ""

        # build SOME/IP packet
        sip = helper.newSOMEIP()
        sip.msg_id.srv_id = 0xffff
        sip.msg_id.sub_id = 0x0
        sip.msg_id.mtd_id = 0x0000

        sip.req_id.client_id = 0xdead
        sip.req_id.session_id = 0xbeef

        sip.type = SOMEIP.TYPE_REQUEST_NO_RET
        sip.retcode = 0x0

        # send message
        p = Ether()/IP(dst="10.0.0.11")/TCP(sport=30490,dport=30490)/sip
        ans = helper.sendp(p,iface="eth2.10")

        # log test results
        self.addTestCase("send SOMEIP Magic cookie",error=err_msg)
    
    # Test_01 : showoff SOME/IP-SD frame
    #   As per Autosar 4.2.1 "Example for a Seralization Protocol (SOME/IP)", 6.7.3.7 example
    def test_02(self):
        """ SOME/IP-SD : documentation example."""
        err_msg = ""
        
        # build SOME/IP-SD packet
        sip,sd = helper.newSD()

        sd.flags = 0x80
        sd.entry_array = [
                SDEntry_Service(type=SDEntry.TYPE_SRV_FINDSERVICE,srv_id=0x4711,inst_id=0xffff,major_ver=0xff,ttl=3600,minor_ver=0xffffffff),
                SDEntry_Service(type=SDEntry.TYPE_SRV_OFFERSERVICE,n_1_opt=1,srv_id=0x1234,inst_id=0x0001,major_ver=0x01,ttl=3,minor_ver=0x00000032)
                ]
        sd.option_array = [
                SDOption_IP4_EndPoint(addr="192.168.0.1",l4_proto=0x11,port=0xd903)
                ]
        
        # SEND MESSAGE 
        p = Ether()/IP(src="10.0.0.11",dst="10.0.0.12")/UDP(sport=30490,dport=30490)/sip/sd
        helper.sendp(p,iface=ETH_IFACE_SRC)
        
        # log test results
        self.addTestCase("send SOME/IP-SD : documentation example",error=err_msg)



    # Test 01 : SOME/IP-SD : Find service
    def _test_01_sender(self,p):
        # sender : immediately send provided packet
        ans = helper.srp1(p,iface=ETH_IFACE_SRC,timeout=5)

        print ans
    def _test_01_rcv(self,p):
        # receiver : wait for a while and send reply
        time.sleep(2)
        helper.sendp(p,iface=ETH_IFACE_SRC)
    def test_01(self):
        """SOME/IP-SD packet : subscribe eventgroup."""
        err_msg = ""

        # build SOME/IP-SD packet
        sip,sd = helper.newSD()
        
        sd.flags = 0x00
        sd.entry_array = [SDEntry_Eventgroup(type=SDEntry.TYPE_EVTGRP_SUBSCRIBE,
                                            n_1_opt=1,
                                            srv_id=0x1111,inst_id=0x2222,major_ver=0x03,egrp_id=0x04,cnt=0x0,ttl=0x05)]
        sd.option_array = [
                SDOption_IP4_EndPoint(addr="192.168.0.1",l4_proto=0x11,port=0xd903)
                ]
        
        # SEND MESSAGE (build request and reply packages)
        p = Ether()/IP(src="10.0.0.11",dst="10.0.0.12")/UDP(sport=30490,dport=30490)/sip/sd
        r = Ether()/IP(src="10.0.0.12",dst="10.0.0.11")/UDP(sport=30490,dport=30490)/sip/sd
        r['SD'].entry_array[0].type=SDEntry.TYPE_EVTGRP_SUBSCRIBE_ACK

        # use a couple of threads to emulate sender/reciever ends of communication
        t_send = threading.Thread(name='sender',target=self._test_01_sender,args=(p,))
        t_rcv = threading.Thread(name='receiver',target=self._test_01_rcv,args=(r,))
        t_send.start()
        t_rcv.start()
        t_send.join()
        t_rcv.join()

        # log test results
        self.addTestCase("send SOME/IP-SD : find service",error=err_msg)


