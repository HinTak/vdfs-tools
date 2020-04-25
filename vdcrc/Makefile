CC = gcc
TARGET = vdcrc32

OBJS = vdcrc32.o
OBJS += crc32.o
SRCS = $(OBJS:.o=.c)

INCLUDES = ./../include

CFLAGS += -DUSER_SPACE
CFLAGS += $(addprefix -I,$(INCLUDES))

LDFLAGS = -static

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

vpath %.c ./:./../lib
