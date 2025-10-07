CC = gcc
CFLAGS = -O2 -Wall -Wextra -g

# This flag includes the Pthreads library on a Linux box.
# Others systems will probably require something different.
LIB = -lpthread
LIB_SRC = tiny.c kvstore.c hash_table.c rio.c file_initializer.c
LIB_OBJ = $(LIB_SRC:.c=.o)

kvstore: $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

format:
	clang-format -i --style=file *.c *.h

clean:
	rm -f *.o kvstore *~ core.*

