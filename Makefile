jclass-runner: $(patsubst %.c,%.o,$(wildcard *.c))
	gcc -o $@ $(wildcard build/*.o) -m32 -lm

%.o: %.c
	gcc -o build/$@ $< -c -m32 -lm

all: clean build jclass-runner

build:
	mkdir build

clean:
	rm -rf build
