# static-router
## Overview
Wrote a simple router configured with a static routing table. The router will receive raw Ethernet frames and process the packets just like a real router, then forward them to the correct outgoing interface.

It is able to perform all of the following operations:

- Ping any of the router's interfaces from the servers.
- Traceroute to any of the router's interface IP addresses.
- Download a file using HTTP from one of the HTTP servers.