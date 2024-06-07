jclass-runner: $(patsubst %.c,%.o,$(wildcard *.c))
	gcc -o $@ $(wildcard build/*.o)

%.o: %.c
	gcc -o build/$@ $< -c

all: clean build jclass-runner

build:
	mkdir build

clean:
	rm -rf build
