# zonecontent
Summarize the contents of a DNS zone

A small script to summarize the contents of a DNS zone, obtained
via zone transfer from a specified server, or via a specified file.

### Pre-requisites

* Python 3
* The 'dig' program that comes with ISC BIND

### Usage string

```
$ zonecontent.py --help

Usage: zonecontent.py [Options] <zonename> ...

    Options:
    --help            Print this help message
    --verbose         Verbose mode (currently does nothing)
    --server=X        Use specified server IP or hostname to get AXFR from
                      (default server is 127.0.0.1)
    --tsig=X          Use TSIG algorithm:name:key specified in X
    --infile=X        Use specified input file as zone contents

If specifying an input file as the source of the zone, it must be composed
of 1 presentation format DNS RR per line, with no continuation lines.
```

### Example usage

```
$ zonecontent huque.com

### Zone: huque.com.
### Source: zone transfer from: 127.0.0.1
### Time: 2019-04-22T13:21EDT

RRs          =             572
RRs          =             199 (minus DNSSEC)
RRsets       =             468
RRsets       =             111 (minus DNSSEC)
Names        =             227
Names        =             100 (minus DNSSEC)
Wildcards    =               5
Delegations  =               8

TTL (min, max, avg) = 60, 86400, 23977

RRtype                    Count            %   %-non-dnssec
A                            97        17.0%          48.7%
AAAA                         13         2.3%           6.5%
CNAME                        29         5.1%          14.6%
DNAME                         2         0.3%           1.0%
DNSKEY                        2         0.3%
DS                            6         1.0%
MX                            2         0.3%           1.0%
NS                           24         4.2%          12.1%
NSEC3                       127        22.2%
NSEC3PARAM                    1         0.2%
NULL                          1         0.2%           0.5%
OPENPGPKEY                    1         0.2%           0.5%
RRSIG                       237        41.4%
SOA                           1         0.2%           0.5%
SRV                           1         0.2%           0.5%
SSHFP                         2         0.3%           1.0%
TLSA                         18         3.1%           9.0%
TXT                           8         1.4%           4.0%

### Elapsed time: 0.02s
```
