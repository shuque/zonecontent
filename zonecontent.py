#!/usr/bin/env python3
#
# zonecontent.py: summarize the contents of a zone, obtained via zone
# transfer, or from a specified source file.
#

import os
import sys
import socket
import time
import getopt
import subprocess


DEFAULT_SERVER = '127.0.0.1'

class Opts:
    zone = None
    verbose = False
    server = None
    tsig = None
    infile = None


dnssec_rrlist = ['DNSKEY', 'DS', 'CDNSKEY', 'CDS', 'TYPE65534',
                 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM']

rr_exclude_ttl = ['NSEC3PARAM', 'TYPE65534', 'TSIG', 'TKEY']


class ZoneStats:

    def __init__(self, name):
        self.zone = name
        self.counts = {
            'rr': 0,
            'rr_no_dnssec': 0,
            'rr_tsig': 0,
            'rr_exclude_ttl': 0,
            }
        self.RR = {}
        self.RRTYPE = {}
        self.RRSET = {}
        self.RRSET_NODNSSEC = {}
        self.ttl_max = -1
        self.ttl_min = 86400
        self.sum_ttl = 0

    def update_rr(self, textrr):
        owner, ttl, rrclass, rrtype, rdata = textrr.split(None, 4)
        if rrtype == 'TSIG':
            self.counts['rr_tsig'] += 1
            return
        ttl = int(ttl)
        self.sum_ttl += ttl
        if not exclude_from_ttl_calc(rrtype, rdata):
            if ttl > self.ttl_max:
                self.ttl_max = ttl
            if ttl < self.ttl_min:
                self.ttl_min = ttl
        else:
            self.counts['rr_exclude_ttl'] += 1
        self.RR[owner] = self.RR.get(owner, []) + [rrtype]
        self.RRTYPE[rrtype] = self.RRTYPE.get(rrtype, 0) + 1
        rrset_data = (owner, rrtype, rrclass)
        self.RRSET[rrset_data] = self.RRSET.get(rrset_data, 0) + 1
        self.counts['rr'] += 1
        if rrtype not in dnssec_rrlist:
            self.counts['rr_no_dnssec'] += 1
            self.RRSET_NODNSSEC[rrset_data] = \
                self.RRSET_NODNSSEC.get(rrset_data, 0) + 1

    def print_stats(self):

        if self.counts['rr'] == 0:
            print("ERROR: No zone data found.")
            return
        self.is_signed = 'NSEC' in self.RRTYPE or 'NSEC3' in self.RRTYPE

        print("Total RR     = {:15,}".format(self.counts['rr']))
        if self.is_signed:
            print("Total RR     = {:15,} (minus DNSSEC)".format(
            self.counts['rr_no_dnssec']))
        print("Total RRsets = {:15,}".format(len(self.RRSET)))
        if self.is_signed:
            print("Total RRsets = {:15,} (minus DNSSEC)".format(
            len(self.RRSET_NODNSSEC)))
        print("Total Names  = {:15,}".format(len(self.RR)))
        if self.is_signed and 'NSEC3' in self.RRTYPE:
            print("Total Names  = {:15,} (minus DNSSEC)".format(
                len(self.RR)-self.RRTYPE['NSEC3']))
        if self.counts['rr_tsig'] > 0:
            print("Total TSIGs  = {:15,}".format(self.counts['rr_tsig']))
        print("\nTTL (min, max, avg) = {}, {}, {}".format(
            self.ttl_min, self.ttl_max,
            int(self.sum_ttl * 1.0/ self.counts['rr'])))
        print("\n{:<15s} {:>15s}       {:>6s}".format(
            "RRtype", "Count", "%"), end='')
        if self.is_signed:
            print("   {:>6s}".format("%-non-dnssec"))
        else:
            print('')
        for (key, keycount) in sorted(self.RRTYPE.items()):
            percent = 100.0 * keycount / (self.counts['rr'] * 1.0)
            if key in dnssec_rrlist or not self.is_signed:
                print("{:<15s} {:15,}      {:6.1f}%".format(
                    key, keycount, percent))
            else:
                percent_nondnssec = 100.0 * keycount / \
                    (self.counts['rr_no_dnssec'] * 1.0)
                print("{:<15s} {:15,}      {:6.1f}%        {:6.1f}%".format(
                    key, keycount, percent, percent_nondnssec))


def usage(msg=None):
    """Print usage string with optional error message, then exit"""
    if msg:
        print("{}\n".format(msg))
    print("""\
Usage: {0} [Options] <zonename> ...

    Options:
    --help            Print this help message
    --verbose         Verbose mode (currently does nothing)
    --server=X        Use specified server IP or hostname to get AXFR from
                      (default server is {1})
    --tsig=X          Use TSIG algorithm:name:key specified in X
    --infile=X        Use specified input file as zone contents

If specifying an input file as the source of the zone, it must be composed
of 1 presentation format DNS RR per line, with no continuation lines.
""".format(os.path.basename(sys.argv[0]), DEFAULT_SERVER))
    sys.exit(1)


def process_args(arguments):
    """Process command line arguments"""

    longopts = [
        "help",
        "verbose",
        "server=",
        "tsig=",
        "infile=",
    ]

    try:
        (options, args) = getopt.getopt(arguments, "", longopts=longopts)
    except getopt.GetoptError as e:
        usage(e)

    for (opt, optval) in options:
        if opt == "--verbose":
            Opts.verbose = True
        elif opt == "--help":
            usage()
        elif opt == "--server":
            Opts.server = optval
        elif opt == "--tsig":
            Opts.tsig = optval
        elif opt == "--infile":
            Opts.infile = optval

    if Opts.server and Opts.infile:
        usage("Error: contradictory options specified: --server and --infile")

    if not Opts.server:
        Opts.server = DEFAULT_SERVER

    if len(args) != 1:
        usage("Error: zone name not specified")
    else:
        Opts.zone = args[0]

    return


def exclude_from_ttl_calc(rrtype, rdata):
    if rrtype in rr_exclude_ttl:
        return True
    if rrtype == 'RRSIG':
        if rdata.split()[0] in rr_exclude_ttl:
            return True
    return False


def print_header(Opts):
    print("### Zone: {}".format(Opts.zone))
    if Opts.infile:
        print("### Source: file: {}".format(Opts.infile))
    else:
        print("### Source: zone transfer from: {}".format(Opts.server))
    print("### Time: {}".format(
        time.strftime("%Y-%m-%dT%H:%M%Z", time.localtime(time.time()))))
    print('')
    return


def make_dig_command(Opts):
    command = ["dig",
               "@{}".format(Opts.server),
               "+nocmd",
               "+nostats",
               "+onesoa",
               "-t",
               "AXFR",]
    if Opts.tsig:
        command.append("-y:{}".format(Opts.tsig))
    command.append(Opts.zone)
    return command


def get_input_stream(Opts):
    if Opts.infile:
        return open(Opts.infile, 'rb')
    else:
        return subprocess.Popen(make_dig_command(Opts),
                                stdout=subprocess.PIPE).stdout


if __name__ == '__main__':

    process_args(sys.argv[1:])
    print_header(Opts)

    s = ZoneStats(Opts.zone)

    t1 = time.time()

    for line in get_input_stream(Opts):
        line = line.decode().rstrip('\n')
        if not line or line.startswith(';'):
            continue
        s.update_rr(line)

    s.print_stats()
    t2 = time.time()
    print("\n### Elapsed time: %.2fs" % (t2-t1))
