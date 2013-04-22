# DHCP Parser

Code for parsing (parts of) the ISC DHCP server config file - 
usually known as dhcpd.conf. 

Currently only host stanza's are supported.

## Quickstart

```
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
```



