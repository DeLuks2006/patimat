CXX = clang++
CXXFLAGS = -std=c++23 -I./include

IN = src/*.cpp
OUT = patimat

all:
	$(CXX) $(CXXFLAGS) $(IN) -o $(OUT)

clean:
	rm -rf $(OUT)
