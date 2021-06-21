# build spi-csgdx-test executable when user executes "make"

spi-csgdx-test : spi-csgdx-test.o
	$(CC) $(LDFLAGS) spi-csgdx-test.o -o spi-csgdx-test
spi-csgdx-test.o : spi-csgdx-test.c
	$(CC) $(CFLAGS) -c spi-csgdx-test.c
# remove object files and executable when user executes "make clean"
clean:
	rm *.o spi-csgdx-test

