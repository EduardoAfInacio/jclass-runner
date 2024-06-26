jclass-runner: $(patsubst %.c,%.o,$(wildcard *.c))
	gcc -o $@ $(wildcard build/*.o) -m32 -lm

%.o: %.c
	gcc -o build/$@ $< -c -m32 -lm

all: jclass-runner

clean:
	rm -rf build
