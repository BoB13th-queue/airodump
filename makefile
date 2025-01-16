# Makefile
CXX = g++
CFLAGS = -Iinclude -Wall -Wextra -O2
CXXFLAGS = -Iinclude -Wall -Wextra -O2
LDFLAGS = -lpcap -lpthread

# 최종 타겟 바이너리 이름
TARGET = airodump

# 소스 파일 목록
C_SRCS = src/main.c src/parse.c
CPP_SRCS = src/airodump.cpp

# 오브젝트 파일은 object/ 디렉토리에 위치
C_OBJS = $(patsubst src/%.c,object/%.o,$(C_SRCS))
CPP_OBJS = $(patsubst src/%.cpp,object/%.o,$(CPP_SRCS))

# 최종 실행 파일은 bin/ 디렉토리에 생성
BIN_TARGET = bin/$(TARGET)

.PHONY: all clean

all: $(BIN_TARGET)

# C++ 소스 -> 오브젝트 빌드 규칙
object/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 링크(오브젝트 -> 실행 파일) 규칙
$(BIN_TARGET): $(C_OBJS) $(CPP_OBJS)
	@mkdir -p bin
	$(CXX) $(C_OBJS) $(CPP_OBJS) -o $@ $(LDFLAGS)

clean:
	rm -f object/*.o
	rm -f bin/$(TARGET)
