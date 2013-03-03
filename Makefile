TARGETS=hw3

hw3: hw3.c
	gcc -Wall --std=gnu99 -g -o hw3 hw3.c

run: hw3
	@./hw3

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

