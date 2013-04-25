#!/usr/bin/python

from pyparsing import *
import json

semi = Literal(";").suppress()
period = Literal(".")
lbrace = Literal("{").suppress()
rbrace = Literal("}").suppress()

# General grammar

ip = Combine(
        Word(nums) + 
        period + 
        Word(nums) + 
        period + 
        Word(nums) + 
        period + 
        Word(nums) 
    )("ip_address")

mac = Word("abcdefABCDEF0123456789:")("hardware ethernet")

hostname = Combine(
        OneOrMore(
            Word(alphanums + "-") + 
            period 
        ) + 
        (
            Literal("com") | 
            Literal("org") | 
            Literal("za") | 
            Word(alphas, exact=2)
        ) 
    )("hostname")

comment = ( 
        Literal("#") + 
        restOfLine
    )

# Host specific - host x { y } 
ethernet = (
    Literal("hardware") + 
    Literal("ethernet") + 
    mac  +  
    semi
)

next_server = (
    Literal("next-server") + 
    ip("next-server") + 
    semi
)

filename = (
    Literal("filename") + 
    dblQuotedString("filename") + 
    semi
)

fixed_address = (
    Literal("fixed-address") + 
    ip("fixed-address") + 
    semi
)

option_hostname = (
    Literal("option") + 
    Literal("host-name") + 
    dblQuotedString("option host-name") + 
    semi
)

host_stanza = (
    Literal("host") +
    hostname + 
    lbrace + (
        Optional(ethernet) & 
        Optional(next_server) & 
        Optional(filename) & 
        Optional(option_hostname) & 
        Optional(fixed_address)
    ) + 
    rbrace
)

host_stanza.ignore(comment)


def scan_string(string, json_output=True):
    for x in host_stanza.scanString(string):
        j = {}
        result, junk1, junk2 = tuple(x)
        j["hostname"] = result["hostname"]
        j["data"] = {}
        for i in dir(result):
            if not str(i).startswith("_"):
                if i != "hostname": 
                    j["data"][i] = result[i] 

        if json_output:
            yield json.dumps(j, sort_keys=True, indent=2)
        else:
            yield j 

def scan_file(filename, json_output=True): 
    for x in host_stanza.scanString(open(filename).read()):
        j = {}
        result, junk1, junk2 = tuple(x)
        j["hostname"] = result["hostname"]
        j["data"] = {}
        for i in dir(result):
            if not str(i).startswith("_"):
                if i != "hostname": 
                    j["data"][i] = result[i] 

        if json_output:
            yield json.dumps(j, sort_keys=True, indent=2)
        else:
            yield j 

if __name__ == "__main__": 

    #from grammar.host import *

    hosts = """
    host foo.bar.co.za {
      hardware ethernet 00:19:d1:04:12:0d;
            fixed-address 192.168.44.46;
            next-server 192.168.40.3;
            filename "pxelinux.0";
            option host-name "foo";
    }
    """

    for host in scan_string(hosts, json_output=True):
        print host
