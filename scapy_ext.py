# File  : scapy_ext.py
# Who   : J.Amores
# SCAPY extensions (SOME/IP, SD package definitions)

from scapy.fields import *
from scapy.packet import *
from scapy.all import *
from scapy.layers.inet6 import IP6Field
import ctypes

class scapy_helper:
    """ methods to guarantee correct usage of scapy."""
    @staticmethod
    def expand(x):
        yield x
        while x.payload:
            x = x.payload
            yield x

    @staticmethod
    def pre_send(p):
        """ make sure all protocol layers set to explicit."""
        for i in list(scapy_helper.expand(p)):
            i.explicit = 1

    @staticmethod
    def sendp(p,iface="eth0"):
        """ wrapper to perform  any additional actions before sending package."""
        scapy_helper.pre_send(p)
        sendp(p,iface=iface)

    @staticmethod
    def srp1(p,iface="eth0",timeout=1):
        """ Send Level2 package and expect 1 answer."""
        conf.debug_match=1
        scapy_helper.pre_send(p)
        # NOTE : to reduce ammount of income replies, set 'type=ETH_P_IP'
        p_ans = srp1(p,iface=iface,timeout=timeout,multi=0)
        return(p_ans)

    @staticmethod
    def sr1(p,iface="eth0",timeout=1):
        """ Send Level2 package and expect 1 answer."""
        conf.debug_match=1
        scapy_helper.pre_send(p)
        p_ans = sr1(p,iface=iface)
        return(p_ans)

    @staticmethod
    def newSOMEIP():
        """ Create new SOMEIP package, so PacketField attributes hold modifiable field-instances."""
        # NOTE : if new istances of 'msg_id,req_id' are not provided, sent package will reset this fields
        #        to their default values
        p = SOMEIP(msg_id=_SOMEIP_MessageId(),req_id=_SOMEIP_RequestId())
        return(p)
    
    @staticmethod
    def newSD():
        """ Create new SD package. Just for consistency with 'newSOMEIP' method."""
        p = SD()
        return(p)

## -------------------------
## SOME/IP PACKAGE DEFINTION
## -------------------------
class _SOMEIP_MessageId(Packet):
    fields_desc = [ ShortField("srv_id",0),
                    BitEnumField("sub_id",0,1,{0:"METHOD_ID",1:"EVENT_ID"}),
                    ConditionalField(BitField("mtd_id",0,15),lambda pkt:pkt.sub_id == 0),
                    ConditionalField(BitField("evt_id",0,15),lambda pkt:pkt.sub_id == 1)
    ]
    def extract_padding(self,p):
        return "",p

class _SOMEIP_RequestId(Packet):
    fields_desc = [ ShortField("client_id",0),
                    ShortField("session_id",0)
    ]
    def extract_padding(self,p):
        return "",p

class SOMEIP(Packet):
    explicit = 1 

    P_VER_DEFAULT = 0x01
    I_VER_DEFAULT = 0x01
    # Lenght offset value, without payload
    LEN_OFFSET    = 0x08

    # SOMEIP TYPE VALUES
    TYPE_REQUEST            = 0x00
    TYPE_REQUEST_NO_RET     = 0x01
    TYPE_NOTIFICATION       = 0x02
    TYPE_REQUEST_ACK        = 0x40
    TYPE_REQUEST_NORET_ACK  = 0x41 
    TYPE_NOTIFICATION_ACK   = 0x42
    TYPE_RESPONSE           = 0x80
    TYPE_ERROR              = 0x81
    TYPE_RESPONSE_ACK       = 0xc0
    TYPE_ERROR_ACK          = 0xc1
    # SOMEIP RETURN CODES
    RET_E_OK                = 0x00
    RET_E_NOT_OK            = 0x01
    RET_E_UNKNOWN_SERVICE   = 0x02
    RET_E_UNKNOWN_METHOD    = 0x03
    RET_E_NOT_READY         = 0x04
    RET_E_NOT_REACHABLE     = 0x05
    RET_E_TIMEOUT           = 0x06
    RET_E_WRONG_PROTOCOL_V  = 0x07
    RET_E_WRONG_INTERFACE_V = 0x08
    RET_E_MALFORMED_MSG     = 0x09
    RET_E_WRONG_MESSAGE_TYPE= 0x0a

    name="SOME/IP"
    fields_desc=[   PacketField("msg_id",_SOMEIP_MessageId(),_SOMEIP_MessageId),# MessageID
                    IntField("len",None),                                       # Length
                    PacketField("req_id",_SOMEIP_RequestId(),_SOMEIP_RequestId),# RequestID
                    ByteField("proto_ver",P_VER_DEFAULT),                       # Protocol version
                    ByteField("iface_ver",I_VER_DEFAULT),                       # Interface version
                    ByteEnumField("type",0,{                                # -- Message type --
                        TYPE_REQUEST:"REQUEST",                             # 0x00
                        TYPE_REQUEST_NO_RET:"REQUEST_NO_RETURN",            # 0x01
                        TYPE_NOTIFICATION:"NOTIFICATION",                   # 0x02
                        TYPE_REQUEST_ACK:"REQUEST_ACK",                     # 0x40
                        TYPE_REQUEST_NORET_ACK:"REQUEST_NO_RETURN_ACK",     # 0x41
                        TYPE_NOTIFICATION_ACK:"NOTIFICATION_ACK",           # 0x42
                        TYPE_RESPONSE:"RESPONSE",                           # 0x80
                        TYPE_ERROR:"ERROR",                                 # 0x81
                        TYPE_RESPONSE_ACK:"RESPONSE_ACK",                   # 0xc0
                        TYPE_ERROR_ACK:"ERROR_ACK",                         # 0xc1
                        }),
                    ByteEnumField("retcode",0,{                             # -- Return code --
                        RET_E_OK:"E_OK",                                    # 0x00
                        RET_E_NOT_OK:"E_NOT_OK",                            # 0x01
                        RET_E_UNKNOWN_SERVICE:"E_UNKNOWN_SERVICE",          # 0x02
                        RET_E_UNKNOWN_METHOD:"E_UNKNOWN_METHOD",            # 0x03
                        RET_E_NOT_READY:"E_NOT_READY",                      # 0x04
                        RET_E_NOT_REACHABLE:"E_NOT_REACHABLE",              # 0x05
                        RET_E_TIMEOUT:"E_TIMEOUT",                          # 0x06
                        RET_E_WRONG_PROTOCOL_V:"E_WRONG_PROTOCOL_VERSION",  # 0x07
                        RET_E_WRONG_INTERFACE_V:"E_WRONG_INTERFACE_VERSION",# 0x08
                        RET_E_MALFORMED_MSG:"E_MALFORMED_MESSAGE",          # 0x09
                        RET_E_WRONG_MESSAGE_TYPE:"E_WRONG_MESSAGE_TYPE",    # 0x0a
                        }),
                    ]

    def post_build(self,p,pay):
        l = self.len

        # length computation : RequestID + PV_IV_TYPE_RETURCODE + PAYLOAD
        if(l is None):
            l = self.LEN_OFFSET + len(pay)
            p = p[:4]+struct.pack("!I",l)+p[8:]
    
        return p+pay

    def answers(self,other):
        # NOTE : this function should use 'isinstance' method, but as a result of how module imports
        #       are handled, results are inconsistent. FIX imports and get rid of current comparison
        #       strategy
        #if isinstance(other,SOMEIP):
        if(other.__class__.__name__ == self.__class__.__name__):
            return 1
        return 0

## --------------------
## SD PACKAGE DEFINTION
## --------------------

## SD Entry
##  - Service
##  - EventGroup
SDENTRY_OVERALL_LEN = 16    # warning : overall length of SDEntry (to be used from UT)
class _SDEntry_HDR(Packet):
    fields_desc = [ ByteField("type",0),
                    ByteField("i_1_opt",0),
                    ByteField("i_2_opt",0),
                    BitField("n_1_opt",0,4), # warning : 4bits field
                    BitField("n_2_opt",0,4), # warning : 4bits field
                    ShortField("srv_id",0),
                    ShortField("inst_id",0),
                    ByteField("major_ver",0),
                    X3BytesField("ttl",0)]
class SDEntry(Packet):
    TYPE_FMT = ">B"
    TYPE_PAYLOAD_I=0
    # ENTRY TYPES : SERVICE
    TYPE_SRV_FINDSERVICE        = 0x00
    TYPE_SRV_OFFERSERVICE       = 0x01
    TYPE_SRV = (TYPE_SRV_FINDSERVICE,TYPE_SRV_OFFERSERVICE)
    # ENTRY TYPES : EVENGROUP
    TYPE_EVTGRP_SUBSCRIBE       = 0x06
    TYPE_EVTGRP_SUBSCRIBE_ACK   = 0x07
    TYPE_EVTGRP = (TYPE_EVTGRP_SUBSCRIBE,TYPE_EVTGRP_SUBSCRIBE_ACK)

    def guess_payload_class(self,payload):
        """ decode SDEntry depending on its type."""
        # TODO : initial implementation, to be reviewed for multiple entries
        pl_type = struct.unpack(SDEntry.TYPE_FMT,payload[SDEntry.TYPE_PAYLOAD_I])[0]
        if(pl_type in SDEntry.TYPE_SRV):
            return(SDEntry_Service)
        elif(pl_type in SDEntry.TYPE_EVTGRP):
            return(SDEntry_Eventgroup)

class SDEntry_Service(SDEntry):
    fields_desc = [ _SDEntry_HDR,
                    IntField("minor_ver",0)]
class SDEntry_Eventgroup(SDEntry):
    fields_desc = [ _SDEntry_HDR,
                    BitField("res",0,12),
                    BitField("cnt",0,4),
                    ShortField("egrp_id",0)]

## SD Option
##  - Configuration
##  - LoadBalancing
##  - IPv4 EndPoint
##  - IPv6 EndPoint
##  - IPv4 MultiCast
##  - IPv6 MultiCast
##  - IPv4 EndPoint
##  - IPv6 EndPoint

# base class for SDOption_* packages    
class _SDOption(Packet):
    # use this dictionary to set default values for desired fields
    # example : _defaults = {'field_1_name':field_1_value,'field_2_name':field_2_value}
    _defaults = {}  

    def _set_defaults(self):
        for key in self._defaults.keys():
            try:
                self.get_field(key)
            except KeyError:
                pass
            else:
                self.setfieldval(key,self._defaults[key])
    
    def init_fields(self):
        """ perform initialization of packet fields with desired values.
            NOTE : this funtion will only be called *once* when the class (or subclass) is constructed
        """
        Packet.init_fields(self)
        self._set_defaults()

    def guess_payload_class(self,payload):
        """ decode SDEntry depending on its type."""
        # TODO : initial implementation, to be reviewed for multiple options
        pl_type = struct.unpack(">B",payload[2])[0]
        
        if(pl_type == SDOPTION_CFG_TYPE):
            return(SDOption_Config)
        elif(pl_type == SDOPTION_LB_TYPE):
            return(SDOption_LoadBalance)
        elif(pl_type == SDOPTION_IP4_EP_TYPE):
            return(SDOption_IP4_EndPoint)
        elif(pl_type == SDOPTION_IP4_MC_TYPE):
            return(SDOption_IP4_Multicast)
        elif(pl_type == SDOPTION_IP4_SDEP_TYPE):
            return(SDOption_IP4_SD_EndPoint)
        elif(pl_type == SDOPTION_IP6_EP_TYPE):
            return(SDOption_IP6_EndPoint)
        elif(pl_type == SDOPTION_IP6_MC_TYPE):
            return(SDOption_IP6_MultiCast)
        elif(pl_type == SDOPTION_IP6_SDEP_TYPE):
            return(SDOption_IP6_SD_EndPoint)

class _SDOption_HDR(_SDOption):
    fields_desc = [ ShortField("len",None),
                    ByteField("type",0),
                    ByteField("res_hdr",0)]
class _SDOption_TAIL(_SDOption):
    fields_desc = [ ByteField("res_tail",0),
                    ByteEnumField("l4_proto",0x06,{
                        0x06:"TCP",
                        0x11:"UDP"
                        }),
                    ShortField("port",0)]
class _SDOption_IP4(_SDOption):
    fields_desc = [ _SDOption_HDR,
                    IPField("addr","0.0.0.0"),
                    _SDOption_TAIL]
class _SDOption_IP6(_SDOption):
    fields_desc = [ _SDOption_HDR,
                    IP6Field("addr","2001:cdba:0000:0000:0000:0000:3257:9652"),
                    _SDOption_TAIL]

# SDOPTIONS : Non IP-specific
SDOPTION_CFG_TYPE   = 0x01
SDOPTION_CFG_OVERALL_LEN= 4 # warning : overall length of CFG SDOption,empty 'cfg_str' (to be used from UT)
SDOPTION_LB_TYPE    = 0x02
SDOPTION_LB_LEN     = 0x05
SDOPTION_LB_OVERALL_LEN = 8 # warning : overall length of LB SDOption (to be used from UT)

SDOPTION_IP4_EP_TYPE    = 0x04
SDOPTION_IP4_EP_LEN     = 0x0009
SDOPTION_IP4_MC_TYPE    = 0x14
SDOPTION_IP4_MC_LEN     = 0x0009
SDOPTION_IP4_SDEP_TYPE  = 0x24
SDOPTION_IP4_SDEP_LEN   = 0x0009
SDOPTION_IP4_OVERALL_LEN= 12    # warning : overall length of IP4 SDOption (to be used from UT)

SDOPTION_IP6_EP_TYPE    = 0x06
SDOPTION_IP6_EP_LEN     = 0x0015
SDOPTION_IP6_MC_TYPE    = 0x16
SDOPTION_IP6_MC_LEN     = 0x0015
SDOPTION_IP6_SDEP_TYPE  = 0x26
SDOPTION_IP6_SDEP_LEN   = 0x0015
SDOPTION_IP6_OVERALL_LEN= 24    # warning : overall length of IP6 SDOption (to be used from UT)

class SDOption_Config(_SDOption):
    # offset to be added upon length calculation (corresponding to header's "Reserved" field)
    LEN_OFFSET    = 0x01

    # default values specification
    _defaults = {'type':SDOPTION_CFG_TYPE}
    # package fields definiton
    # TODO : add explicit control of "\0 terminated string"
    fields_desc = [ _SDOption_HDR,
                    StrField("cfg_str","")]

    def post_build(self,p,pay):
        # length computation : bytes occupied excluding 16b_length and 8b_flags
        l = self.len
        if(l is None):
            l = len(self.cfg_str)+self.LEN_OFFSET
            p = struct.pack("!H",l)+p[2:]
        return(p+pay)            

class SDOption_LoadBalance(_SDOption):
    # default values specification
    _defaults = {'type':SDOPTION_LB_TYPE,'len':SDOPTION_LB_LEN}
    # package fields definiton
    fields_desc = [ _SDOption_HDR,
                    ShortField("prio",0),
                    ShortField("weight",0)]
    
# SDOPTIONS : IPv4-specific 
class SDOption_IP4_EndPoint(_SDOption_IP4):
    # default values specification
    _defaults = {'type':SDOPTION_IP4_EP_TYPE,'len':SDOPTION_IP4_EP_LEN}

class SDOption_IP4_Multicast(_SDOption_IP4):
    # default values specification
    _defaults = {'type':SDOPTION_IP4_MC_TYPE,'len':SDOPTION_IP4_MC_LEN}

class SDOption_IP4_SD_EndPoint(_SDOption_IP4):
    # default values specification
    _defaults = {'type':SDOPTION_IP4_SDEP_TYPE,'len':SDOPTION_IP4_SDEP_LEN}

# SDOPTIONS : IPv6-specific 
class SDOption_IP6_EndPoint(_SDOption_IP6):
    # default values specification
    _defaults = {'type':SDOPTION_IP6_EP_TYPE,'len':SDOPTION_IP6_EP_LEN}

class SDOption_IP6_Multicast(_SDOption_IP6):
    # default values specification
    _defaults = {'type':SDOPTION_IP6_MC_TYPE,'len':SDOPTION_IP6_MC_LEN}

class SDOption_IP6_SD_EndPoint(_SDOption_IP6):
    # default values specification
    _defaults = {'type':SDOPTION_IP6_SDEP_TYPE,'len':SDOPTION_IP6_SDEP_LEN}

# --------------------
# SD packet definition
# --------------------
class SD(Packet):
    # TODO : improve 'flags' field
        # Flags definition: {"name":(mask,offset)}
    FLAGSDEF =  {   "RB":(0x80,7),   # ReBoot flag
                    "UC":(0x40,6)    # UniCast flag
                }

    name="SD"
    fields_desc=[   ByteField("flags",0),
                    X3BytesField("res",0),
                    FieldLenField("len_entry_array",None,length_of="entry_array",fmt="!I"),
                    PacketListField("entry_array",[],SDEntry,length_from = lambda pkt:pkt.len_entry_array),
                    FieldLenField("len_option_array",None,length_of="option_array",fmt="!I"),
                    PacketListField("option_array",[],_SDOption,length_from = lambda pkt:pkt.len_option_array)
    ]
    # NOTE : when adding 'entries' or 'options', do not use list.append() method but create a new list
    # ej :  p = SD()
    #       p.option_array = [SDOption_Config(),SDOption_IP6_EndPoint()]

    def getFlag(self,name):
        name = name.upper()
        if(name in self.FLAGSDEF):
            return((self.flags&self.FLAGSDEF[name][0])>>self.FLAGSDEF[name][1])
        else:return None
    def setFlag(self,name,value):
        name = name.upper()
        if(name in self.FLAGSDEF):
            self.flags = (self.flags&(ctypes.c_ubyte(~self.FLAGSDEF[name][0]).value))|((value&0x01)<<self.FLAGSDEF[name][1])


## -------------
## LAYER BINDING    
## -------------
# TODO : modify layer binding and define a broader range or ports
bind_layers(UDP,SOMEIP,sport=30490)
bind_layers(UDP,SOMEIP,sport=30501)
bind_layers(TCP,SOMEIP,sport=30490)
bind_layers(TCP,SOMEIP,sport=30501)
bind_layers(SOMEIP,SD)
