from sys import stdin, stdout
d = dict()
for line in stdin:
    word, cnt = line.split('\t')
    if word in d :
        d[word] += int(cnt)
    else :
        d[word] = int(cnt)
for word in d :
    print "%s\t%d" % (word, d[word])
