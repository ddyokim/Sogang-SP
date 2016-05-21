#!/usr/bin/python
from sys import stdin, stdout
for line in stdin:
    words = line.split()
    for i in range(len(words)-1):
        print "%s\t%s\t%d" % (words[i], words[i+1], 1)
