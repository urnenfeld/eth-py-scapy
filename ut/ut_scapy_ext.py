# File  : scapy_ext.py
# Who   : J.Amores
# UnitTest file for Scapy extensions

import unittest
import sys
import ctypes
sys.path.append('..')

from scapy_ext import *
from scapy_ext import _SOMEIP_MessageId
#from scapy_ext import _SDOption_HDR,_SDOption_TAIL,_SDOption_IP4,_SDOption

class ut_scapy_ext(unittest.TestCase):
    
    def setUp(self):
        pass
    def tearDown(self):
        pass

    # -------
    # SOME/IP
    # -------
    def test_00_SOMEIP_MSGID(self):
        p = SOMEIP()
        p.msg_id.srv_id = 0x1111
        p.msg_id.mtd_id = 0x0222
        p.msg_id.evt_id = 0x0333

        # MessageID mit 'method_id'
        p.msg_id.sub_id = 0
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == 0x1111)
        self.assert_((struct.unpack("!B",str(p)[2:3])[0] & 0x80) == 0x00)
        self.assert_((struct.unpack("!H",str(p)[2:4])[0] & ~0x8000) == 0x0222)

        # MessageID mit 'event_id'
        p.msg_id.sub_id = 1
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == 0x1111)
        self.assert_((struct.unpack("!B",str(p)[2:3])[0] & 0x80) == 0x80)
        self.assert_((struct.unpack("!H",str(p)[2:4])[0] & ~0x8000) == 0x0333)


        # Post-MessageID field check
        self.assert_(struct.unpack("!I",str(p)[4:8])[0] == SOMEIP.LEN_OFFSET)

    def test_01_SOMEIP_REQID(self):
        p = SOMEIP()
        p.req_id.client_id = 0x1111
        p.req_id.session_id = 0x2222

        # ClientID
        self.assert_(struct.unpack("!H",str(p)[8:10])[0] == 0x1111)

        # SessionID
        self.assert_(struct.unpack("!H",str(p)[10:12])[0] == 0x2222)

        # Post-requestID field check
        self.assert_(struct.unpack("!B",str(p)[12])[0] == 0x01)

    def test_02_SOMEIP_UDP(self):
        """ check SOMEIP over UDP."""
        sip = SOMEIP()
        sip.msg_id.srv_id = 0x1111
        sip.msg_id.sub_id = 0
        sip.msg_id.mtd_id = 0x2222

        p = UDP(sport=20000,dport=25000)/sip
        # TODO : all layers of package should be set to "EXPLICIT" (or patch SCAPY.send_recv)
        p.explicit = 1

        self.assert_(struct.unpack("!H",str(p)[8:10])[0] == 0x1111)
        self.assert_(struct.unpack("!H",str(p)[10:12])[0] == 0x2222)

    # ----
    # SD 
    # ----

    # DEFAULTS
    def test_00_SD_Defaults(self):
        p = SDOption_Config()
        self.assert_(p.type == SDOPTION_CFG_TYPE)
        del p
        p = SDOption_LoadBalance()
        self.assert_(p.type == SDOPTION_LB_TYPE)
        del p
        
        p = SDOption_IP4_EndPoint()
        self.assert_(p.type == SDOPTION_IP4_EP_TYPE)
        del p
        p = SDOption_IP4_Multicast()
        self.assert_(p.type == SDOPTION_IP4_MC_TYPE)
        del p
        p = SDOption_IP4_SD_EndPoint()
        self.assert_(p.type == SDOPTION_IP4_SDEP_TYPE)
        del p

        p = SDOption_IP6_EndPoint()
        self.assert_(p.type == SDOPTION_IP6_EP_TYPE)
        del p
        p = SDOption_IP6_Multicast()
        self.assert_(p.type == SDOPTION_IP6_MC_TYPE)
        del p
        p = SDOption_IP6_SD_EndPoint()
        self.assert_(p.type == SDOPTION_IP6_SDEP_TYPE)
        del p

    # LENGTHS
    def test_01_SDOpt_lengths_00(self):
        # SDOption_Config
        p = SDOption_Config()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == 1)
        del p

        p = SDOption_Config(cfg_str="hello world")
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == (len("hello world")+1))

    def test_01_SDOpt_lengths_01(self):
        # SDOption_LoadBalance
        p = SDOption_LoadBalance()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == SDOPTION_LB_LEN)
    
    def test_01_SDOpt_lengths_02(self):
        # SDOption_IP4_EndPoint
        p = SDOption_IP4_EndPoint()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == SDOPTION_IP4_EP_LEN)
        # SDOption_IP4_Multicast
        p = SDOption_IP4_Multicast()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == SDOPTION_IP4_MC_LEN)
        # SDOption_IP4_SD_Endpoint
        p = SDOption_IP4_SD_EndPoint()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == SDOPTION_IP4_SDEP_LEN)

    def test_01_SDOpt_lengths_03(self):
        # SDOption_IP6_EndPoint
        p = SDOption_IP6_EndPoint()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == SDOPTION_IP6_EP_LEN)
        # SDOption_IP6_Multicast
        p = SDOption_IP6_Multicast()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == SDOPTION_IP6_MC_LEN)
        # SDOption_IP6_SD_Endpoint
        p = SDOption_IP6_SD_EndPoint()
        self.assert_(struct.unpack("!H",str(p)[:2])[0] == SDOPTION_IP6_SDEP_LEN)

    def test_01_SD_lengths(self):
        p = SD()
        #self.assert_(p.len_option_array == 0)

        # EntryArray
        p.entry_array = [SDEntry_Service()]
        self.assert_(struct.unpack("!I",str(p)[4:8])[0] == SDENTRY_OVERALL_LEN)
        p.entry_array = [SDEntry_Service(),SDEntry_Eventgroup()]
        self.assert_(struct.unpack("!I",str(p)[4:8])[0] == SDENTRY_OVERALL_LEN*2)
        p.entry_array = []
        self.assert_(struct.unpack("!I",str(p)[4:8])[0] == 0)

        # OptionArray
        p.option_array = [SDOption_Config()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_CFG_OVERALL_LEN)
        p.option_array = [SDOption_Config(),SDOption_LoadBalance()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_CFG_OVERALL_LEN+SDOPTION_LB_OVERALL_LEN)
        p.option_array = [SDOption_Config(),SDOption_LoadBalance(),SDOption_LoadBalance()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_CFG_OVERALL_LEN+2*SDOPTION_LB_OVERALL_LEN)

        p.option_array = [SDOption_IP4_EndPoint()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_IP4_OVERALL_LEN)
        p.option_array = [SDOption_IP4_EndPoint(),SDOption_IP4_Multicast()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_IP4_OVERALL_LEN*2)

        p.option_array = [SDOption_IP6_EndPoint()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_IP6_OVERALL_LEN)
        p.option_array = [SDOption_IP6_EndPoint(),SDOption_IP6_Multicast()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_IP6_OVERALL_LEN*2)

        p.option_array = [SDOption_IP4_EndPoint(),SDOption_IP6_EndPoint()]
        self.assert_(struct.unpack("!I",str(p)[8:12])[0] == SDOPTION_IP4_OVERALL_LEN+SDOPTION_IP6_OVERALL_LEN)

        # EntryArray +  OptionArray
        p.entry_array = [SDEntry_Service()]
        p.option_array = [SDOption_IP4_EndPoint()]
        self.assert_(struct.unpack("!I",str(p)[4:8])[0] == SDENTRY_OVERALL_LEN)
        self.assert_(struct.unpack("!I",str(p)[24:28])[0] == SDOPTION_IP4_OVERALL_LEN)
        

    # SD-FLAGS
    def test_02_SD_flags(self):
        p = SD()
        p.flags=0x00
        self.assert_(p.getFlag("RB") == 0)
        self.assert_(p.getFlag("rb") == 0)
        self.assert_(p.getFlag("UC") == 0)
        self.assert_(p.getFlag("uC") == 0)
        
        p.flags=0xff
        self.assert_(p.getFlag("rb") == 1)
        self.assert_(p.getFlag("uc") == 1)
        
        p.flags=0xff
        for i in p.FLAGSDEF.keys():
            p.setFlag(i,0)
            self.assert_(p.getFlag(i) == 0)
            self.assert_(ctypes.c_ubyte(~p.FLAGSDEF[i][0]).value == p.flags)

            p.setFlag(i,1)
            self.assert_(p.getFlag(i) == 1)
            self.assert_(0xff == p.flags)

            
    def _test_02(self):
        p = SDOption_IP4_EndPoint()
        p.show()
        p.show2()

if __name__=='__main__':
    unittest.main()
