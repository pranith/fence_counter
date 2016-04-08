###############################################################################
# Qemu Simulation Framework (qsim)                                            #
# Qsim is a modified version of the Qemu emulator (www.qemu.org), coupled     #
# a C++ API, for the use of computer architecture researchers.                #
#                                                                             #
# This work is licensed under the terms of the GNU GPL, version 2. See the    #
# COPYING file in the top-level directory.                                    #
###############################################################################
QSIM_PREFIX ?= /usr/local
CXXFLAGS ?= -O3 -g -Wall -I$(QSIM_PREFIX)/include -std=c++11 -Wall
LDLIBS ?= -L$(QSIM_PREFIX)/lib -lqsim -lcapstone -pthread -ldl -lz

EXAMPLES = fcounter tester

all: $(EXAMPLES)

fcounter: fcounter.cpp cs_disas.o $(QSIM_PREFIX)/lib/libqsim.so
	$(CXX) $(CXXFLAGS) -o $@ cs_disas.o $< $(LDLIBS)

tester: tester.cpp $(QSIM_PREFIX)/lib/libqsim.so
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f *.o $(EXAMPLES) *~ *\#

