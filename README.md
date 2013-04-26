DHCP Config Parser
==================

Code for parsing (parts of) the ISC DHCP server config file.

Currently only host stanza's are supported.

Requirements
------------

* [pyparsing]: http://pyparsing.wikispaces.com/

Quickstart
----------

A few quick examples to get you going

### Example 1 ###


```python
from grammar.host import *

hosts = """
host foo.bar.co.za {
  hardware ethernet 00:19:d1:04:12:0d;
        fixed-address 192.168.44.46;
        next-server 192.168.40.3;
        filename "pxelinux.0";
        option host-name "foo";
}
"""

for host in scan_string(hosts):
    print host

```python

### Example 2 ###

This examples extracts host entries from dhcpd.conf and writes each
as a separate file to dhcpd.conf.d directory. 


```
from grammar.host import *

def write_host_file(host_data):

    f = open("dhcpd.conf.d/%s" % host_data['hostname'], "wb")
    f.write("host %s {\n" % host_data['hostname'])

    for k in host_data["data"].keys():
        f.write("    %s %s;\n" % (k, host_data['data'][k]))

    f.write("}\n")
    f.close()

for host in scan_file("dhcpd.conf", json_output=False): 
    write_host_file(host)

```

