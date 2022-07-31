.PHONY: all
all: chal init

chal: LDLIBS=-lprotobuf -lcap
chal: LDFLAGS=-pthread
chal: chal.cc chal.pb.h chal.pb.o

chal.pb.o: chal.pb.cc

chal.pb.cc: chal.pb.h

chal.pb.h: chal.proto
	protoc --cpp_out=. chal.proto

init: LDFLAGS=-static
init: init.o
