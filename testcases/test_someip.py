# File  : test_someip
# Who   : jamores
# Some SOME/IP stuff

from test_base import baseTest

from scapy.all import *
from scapy_ext import scapy_helper as helper

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
        p = Ether()/IP()/TCP()/sip
        ans = helper.srp1(p,iface="")

        # log test results
        self.addTestCase("ping to google.com",error=err_msg)
