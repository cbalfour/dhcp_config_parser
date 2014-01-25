#!/usr/bin/python

# Parse up leases from the DHCP leases file
# CTB Fri Jun 21 15:17:34 SAST 2013

from pyparsing import *
import json
from datetime import datetime 

semi = Literal(";").suppress()
period = Literal(".")
lbrace = Literal("{").suppress()
rbrace = Literal("}").suppress()
colon = Literal(":")

ip = Combine(
        Word(nums) + 
        period + 
        Word(nums) + 
        period + 
        Word(nums) + 
        period + 
        Word(nums) 
    )("ip_address")

integer = Word(nums).setParseAction(lambda t: int(t[0]))
 
date = (
	integer('year') + '/' + integer('month') + '/' + integer('day') + 
	integer("hour") + ':' + integer('minute') + ':' + integer('second')
	)	

def convertToDatetime(s, loc, tokens):
    try:
        return datetime(tokens.year, tokens.month, tokens.day, tokens.hour, tokens.minute, tokens.second)
    except Exception as ve:
        errmsg = "'%d/%d/%d' is not a valid date, %s" % \
            (tokens.year, tokens.month, tokens.day, ve)
        raise ParseException(s, loc, errmsg)
date.setParseAction(convertToDatetime)

mac = Word("abcdefABCDEF0123456789:")("hardware ethernet")

ethernet = (
    Literal("hardware") + 
    Literal("ethernet") + 
    mac  +  
    semi
)

lease_starts = (Literal("starts") + Word(nums)  + date("starts_date") + semi)
lease_ends = (Literal("ends") + Word(nums) + date("ends_date") + semi)
lease_tstp = (Literal("tstp") + Word(nums) + date("tstp_date") + semi)
lease_cltt = (Literal("cltt") + Word(nums) + date("cltt_date") + semi)

lease_binding = (Literal("binding") + Literal("state") + Word(alphanums) + semi)
lease_next_binding = (Literal("next") + Literal("binding") + Literal("state") + Word(alphanums) + semi)
lease_uid = (Literal("uid") + dblQuotedString(alphanums) + semi)
lease_option_agent_circuit_id = (Literal("option") + Literal("agent.circuit-id") + mac + semi)
lease_option_agent_remote_id = (Literal("option") + Literal("agent.remote-id") + mac + semi)
lease_client_hostname = (Literal("client-hostname") + dblQuotedString(alphanums) + semi)

lease_stanza = (
	Literal("lease") + ip + lbrace + (
	Optional(lease_starts) &
	Optional(lease_ends) &
	Optional(lease_tstp) &
	Optional(lease_cltt) &
	Optional(lease_binding) &
	Optional(lease_next_binding) & 
	Optional(ethernet) &
	Optional(lease_uid) & 
	Optional(lease_option_agent_circuit_id) &
	Optional(lease_option_agent_remote_id) &
	Optional(lease_client_hostname)
	) + rbrace )


def scan_string(string, json_output=True):
    for x in lease_stanza.scanString(string):
        j = {}
        result, junk1, junk2 = tuple(x)
        j["lease_address"] = result["ip_address"]
        j["data"] = {}
        for i in dir(result):
            if not str(i).startswith("_"):
                if i != "ip_address": 
                    j["data"][i] = result[i] 

        if json_output:
            yield json.dumps(j, sort_keys=True, indent=2)
        else:
            yield j 

def scan_file(filename, json_output=True): 
    for x in lease_stanza.scanString(open(filename).read()):
        j = {}
        result, junk1, junk2 = tuple(x)
        j["lease_address"] = result["ip_address"]
        j["data"] = {}
        for i in dir(result):
            if not str(i).startswith("_"):
                if i != "ip_address": 
                    j["data"][i] = result[i] 

        if json_output:
            yield json.dumps(j, sort_keys=True, indent=2)
        else:
            yield j 

if __name__ == "__main__": 

    #from grammar.host import *


    leases = """
# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-V3.1.3

lease 192.168.73.250 {
  starts 3 2008/11/12 15:04:17;
  ends 3 2008/11/12 18:50:06;
  tstp 3 2008/11/12 18:50:06;
  binding state free;
  hardware ethernet 00:19:d1:04:12:1e;
  uid "\001\000\031\321\004\022\036";
}
lease 192.168.73.254 {
  starts 3 2008/11/12 13:06:22;
  ends 4 2008/11/13 01:06:22;
  tstp 4 2008/11/13 01:06:22;
  binding state free;
  hardware ethernet 00:16:d4:fb:b9:83;
}


"""

    for lease in scan_string(leases, json_output=False):
        print lease
