#!/usr/bin/env python3
"""Convert ssserver's private diagnostic stream to byte counts before storage."""
import re
import sys


TCP = re.compile(r'\btcp tunnel .* closed, L2R (\d+) bytes, R2L (\d+) bytes\s*$')
UDP = re.compile(r'\budp relay .* (->|<-) .* with (\d+) bytes\s*$')


def counts(line):
    match = TCP.search(line)
    if match:
        return int(match.group(1)), int(match.group(2))
    match = UDP.search(line)
    if match:
        size = int(match.group(2))
        return (size, 0) if match.group(1) == '->' else (0, size)
    return None


def main():
    for line in sys.stdin:
        result = counts(line)
        if result is not None:
            print('%d %d' % result, flush=True)


if __name__ == '__main__':
    main()
