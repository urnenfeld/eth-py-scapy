# File  : test_basics
# Who   : jamores
# Some basic test collection

from test_base import baseTest

from scapy.all import *

class test_basics(baseTest):

    def __init__(self):
        # call superclass constructor providing test collection category
        baseTest.__init__(self,"basics")

    # Test 00 : ping google
    def test_00(self):
        """ Ping google."""
        err_msg = ""

        # send a ping to google
        packet = IP(dst="www.google.com")/ICMP()
        ans,unans = sr(packet,timeout=1)

        if(len(unans) > 0):
            err_msg = "unanswered ping packet : "+str(unans)

        # log test results
        self.addTestCase("ping to google.com",error=err_msg)

    def test_01(self):
        """ Port-closed scan tester (using TCP connect scan technique)."""
        warn_msg = ""
        
        # test port status (closed : test ok, open : test warning)
        dst_ip = "192.168.1.1"
        src_port = RandShort()
        dst_port = 80

        scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=5)
        if(str(type(scan_resp)) == "<type 'NoneType'>"):
            # port closed
            pass
        elif(scan_resp.haslayer(TCP)):
            if(scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=5)
                warn_msg = "port open at "+dst_ip+":"+str(dst_port)
            elif(scan_resp.getlayer(TCP).flags == 0x14):
                # port closed
                pass

        # log test results
        self.addTestCase("port closed at "+dst_ip+":"+str(dst_port)+" (TCP connect)",warning=warn_msg)
