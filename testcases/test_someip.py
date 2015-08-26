# File  : test_someip
# Who   : jamores
# Some SOME/IP stuff

from test_base import baseTest

from scapy.all import *
from scapy_ext import scapy_helper as helper
from scapy_ext import *

import threading
import time

ETH_IFACE = "eth1.10"

class test_somepip(baseTest):

    def __init__(self):
        # call superclass constructor providing test collection category
        baseTest.__init__(self,"SOME/IP")

    # Test 00 : SOME/IP Magic cookie
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
    
    # Test 01 : SOME/IP-SD : Find service
    def _test_01_sender(self,p):
        pass
        ans = helper.srp1(p,iface="eth1.10",timeout=5)
    def _test_01_rcv(self,p):
        pass
        time.sleep(1)
        helper.sendp(p,iface="eth2.10")
    def test_01(self):
        """SOME/IP-SD packet."""
        err_msg = ""

        # build SOME/IP-SD packet
        sip = helper.newSOMEIP()
        sip.msg_id.srv_id = 0xffff
        sip.msg_id.sub_id = 0x1
        sip.msg_id.evt_id = 0x100
        sip.req_id.client_id = 0x00
        sip.req_id.session_id = 0x01
        sip.type = SOMEIP.TYPE_NOTIFICATION
        
        sd = helper.newSD()
        sd.flags = 0xff
        sd.entry_array = [SDEntry_Service(type=0,srv_id=0x1111,inst_id=0x2222,major_ver=0x01,ttl=0x02)]
        
        # SEND MESSAGE
        p = Ether()/IP(src="10.0.0.11",dst="10.0.0.12")/UDP(sport=30490,dport=30490)/sip/sd
        r = Ether()/IP(src="10.0.0.12",dst="10.0.0.11")/UDP(sport=30490,dport=30490)/sip/sd
        #ans = helper.srp1(p,iface="eth2.10")

        t_send = threading.Thread(name='sender',target=self._test_01_sender,args=(p,))
        t_rcv = threading.Thread(name='receiver',target=self._test_01_rcv,args=(r,))
        t_send.start()
        t_rcv.start()
        t_send.join()
        t_rcv.join()
        
        # log test results
        self.addTestCase("send SOME/IP-SD : find service",error=err_msg)
