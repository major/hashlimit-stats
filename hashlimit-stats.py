#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# Copyright 2018 Major Hayden
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
"""Get statistics from iptables' hashlimit module."""
import argparse
from collections import Counter
import re

PACKET_PATH_REGEX = re.compile(r"([0-9\.]*):(\d+)->([0-9\.]*):(\d+)")


def parse_packet_path(packet_path):
    """Parse the packet path into its parts."""
    matches = PACKET_PATH_REGEX.search(packet_path)
    if matches:
        return {
            'src_ip': matches.groups()[0],
            'src_port': matches.groups()[1],
            'dst_ip': matches.groups()[2],
            'dst_port': matches.groups()[3],
        }


def parse_hashlimit_table(hashlimit_table):
    """Parse the hashlimit table specified by the user."""
    table_entries = []
    proc_path = "/proc/net/ipt_hashlimit/{}".format(hashlimit_table)
    with open(proc_path, 'r') as fileh:
        for line in fileh:
            (expires, packet_path, credit, credit_cap, cost) = line.split(' ')
            entry = parse_packet_path(packet_path)
            entry['expires'] = int(expires)
            entry['over_cap'] = int(credit) > int(cost)
            table_entries.append(entry)

    print("Total table entries: {:,}".format(len(table_entries)))
    over_cap = Counter(x['over_cap'] for x in table_entries)
    print(
        "Entries allowed/disallowed: ✓ {:,} ✗ {:,}".format(
            over_cap[False], over_cap[True]
        )
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Read iptables hashlimit statistics.'
    )
    parser.add_argument(
        'hashlimit-table',
        type=str,
        help=(
            "Name of the hash limit table (found in /proc/net/ipt_hashlimit/"
        )
    )
    args = vars(parser.parse_args())

    parse_hashlimit_table(args['hashlimit-table'])
