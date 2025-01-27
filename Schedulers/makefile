#.PHONY: dirs

OBJ := obj
SRC := src
INC := include
RUN := run

CXX       = g++
CXXFLAGS  = -O3 -std=c++2a -ggdb -no-pie  -Wall -Wunused   #-Werror
LIBS      = -lcrypto -lz3 -lboost_serialization  -lrt   -pthread -lprocps  # -lcurl -lxmlrpc++ -lxmlrpc_client++ -lrpc -pthread 
EXEC_FILE = $(RUN)/schedule
MAKEFLAGS += -j 8 #$(NPROCS)

SOURCES = $(wildcard $(SRC)/*.cpp)
OBJECTS = $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SOURCES))

DEP = $(OBJECTS:%.o=%.d)

build:  dirs  $(EXEC_FILE)  

dirs:
	@mkdir -p $(OBJ)
	@mkdir -p $(RUN)

$(EXEC_FILE): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)


$(OBJ)/%.o: $(SRC)/%.cpp|$(INC)/%.h
	$(CXX) $(CXXFLAGS) -I $(INC) -MMD -c -o $@ $< $(LIBS)

-include $(DEP)

clean:
	rm -rf $(EXEC_FILE) $(OBJ) 

