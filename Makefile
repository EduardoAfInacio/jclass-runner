jclass-runner: $(patsubst %.c,%.o,$(wildcard *.c))
	gcc -o $@ $(wildcard build/*.o) -m32 -lm --std=c99

%.o: %.c
	gcc -o build/$@ $< -c -m32 -lm --std=c99

all: jclass-runner

clean:
	rm build/*.o
	rm jclass-runner
