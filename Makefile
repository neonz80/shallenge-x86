TARGET = shallenge
SRC = shallenge.cpp sha256-x86.cpp
HEADERS = print.hpp

all : $(TARGET)

$(TARGET): Makefile $(SRC) $(HEADERS)
	c++ -o $@ -O3 -msse4.1 -msha -std=c++20 $(SRC)

clean :
	-@$(RM) -f $(TARGET)
