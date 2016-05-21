#!/usr/bin/python
from sys import stdin, stdout
d = dict()
for line in stdin:
    word1, word2, cnt = line.split('\t')
    word = word1 +  " " + word2
    if word in d :
        d[word] += int(cnt)
    else :
        d[word] = int(cnt)
for word in sorted(d) :
    print "%s\t%d" % (word, d[word])
