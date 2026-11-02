# Project X

- Name: Martin Gonzalez
- Email: martingonzalez@u.boisestate.edu
- Class: CS425-001

## Known Bugs or Issues

No known bugs or issues.

## Experience
The interface made it an easier project to follow along with, and gave me some more direction. The most challenging part of the project was doing the CIDR edge cases. /0 needed special handling, while /31 and /32 don't follow the usual rule of reserving network and broadcast addresses. Writing the mask and count logic with those made future one's easier though. 

## Design

/0 uses a zero mask instead of shifting bits and a 64-bit value to handle all 2^32 addresses. /31 allows both addresses to be used as hosts, which gives us two usable addresses. Since /32 represents a single host the first and last host are the same address. All other prefixes exclude the network and broadcast addresses.

The table checks every route to see if the destination matches its network. If multiple routes match, it chooses the one with the longest prefix which is the most specific. The default route (/0) is only used when no routes matche.
