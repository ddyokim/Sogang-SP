CC = gcc
SOURCE = 20141505.c 
OBJS = 20141505.o
TARGET = 20141505.out
CFLAGS = -W -Wall
	
all : $(SOURCE) $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) -o $@  $(CFLAGS) $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)
