CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra

SRCS = waf.cpp
TARGET = waf_detector

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) -lcurl
clean:
	rm -f $(TARGET)

# run
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
