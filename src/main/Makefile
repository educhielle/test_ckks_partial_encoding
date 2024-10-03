ROOT=$(abspath ../..)
3P=$(ROOT)/3p
SRC=$(ROOT)/src
SEAL_INC=$(3P)/seal/include/SEAL-4.1
SEAL_LIB=$(3P)/seal/lib

CC=g++
INCS=-I$(SEAL_INC)
FLAGS=-Wall -Wextra -Werror -std=c++17 -O3
CPPS=
LIBS=-pthread -L$(SEAL_LIB) -lseal-4.1
DEFS=

all: info

%: %.cpp
	$(CC) $(INCS) $(FLAGS) -o $@.exe $< $(CPPS) $(LIBS) $(DEFS)

clean:
	rm -f *.exe

info:
	@echo "make filename"
