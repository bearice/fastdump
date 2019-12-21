CC = clang
CFLAGS ?= -g3 -finline-functions -Wall -fPIC -std=c11 -D_GNU_SOURCE

LD = clang
LDLIBS += -lev -lz

TARGET  := fastdump
MAINS   := $(TARGET:%=src/%.o)
HEADERS := $(wildcard src/*.h)
SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:.c=.o)
SHARED  := $(filter-out $(MAINS),$(OBJECTS))
TEST_SRC:= $(wildcard test/*.c)
TEST_OBJ:= $(TEST_SRC:.c=.o)
TEST_BIN:= $(TEST_SRC:.c=)

all: $(TARGET)
test: $(TEST_BIN)
	for t in $(TEST_BIN); do $$t ; done

$(TARGET): % : src/%.o $(SHARED)
	$(LD) $< $(SHARED) $(LDLIBS) -o$@

$(SOURCES): $(HEADERS)

$(TEST_OBJ): test/%.o : test/%.c $(HEADERS)
	$(CC) $(CFLAGS) -Isrc -o$@ -c $<

$(TEST_BIN): test/% : test/%.o $(SHARED)
	$(LD) $(LDLIBS) -o$@ $< $(SHARED) -lcunit

%.o: %.c
	$(CC) $(CFLAGS) -c -o$@ $<

clean:
	rm -rf $(OBJECTS) $(TARGET) $(TEST_BIN) $(TEST_OBJ)
