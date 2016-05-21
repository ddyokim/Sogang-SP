from sys import stdin, stdout
for line in stdin:
    for word in line.split():
        print "%s\t%d" % (word, 1)
