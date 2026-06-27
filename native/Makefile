# wifi-auditor native build (MinGW-w64)
#
#   make            -> build/wifi-auditor.exe
#   make run        -> build + launch
#   make clean
#
# Requires: gcc, g++, windres on PATH (MinGW-w64 / MSYS2 ucrt64).

CC      := gcc
CXX     := g++
WINDRES := windres

SRC     := src
BUILD   := build
EXE     := $(BUILD)/spidy-Air.exe

CFLAGS   := -O2 -Wall -Wextra -municode
CXXFLAGS := -O2 -Wall -Wextra -std=c++17 -municode -I$(SRC)
LDFLAGS  := -municode -mwindows -static -static-libgcc -static-libstdc++
LIBS     := -lwlanapi -lcomctl32 -lole32 -lcomdlg32

OBJS := $(BUILD)/wifi_scan.o $(BUILD)/main.o $(BUILD)/app_res.o

all: $(EXE)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/wifi_scan.o: $(SRC)/wifi_scan.c $(SRC)/wifi_scan.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/main.o: $(SRC)/main.cpp $(SRC)/wifi_scan.h $(SRC)/resource.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/app_res.o: $(SRC)/app.rc $(SRC)/resource.h $(SRC)/spider.ico $(SRC)/app.manifest | $(BUILD)
	$(WINDRES) -I$(SRC) $< -O coff -o $@

$(EXE): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)
	@echo "Built $(EXE)"

run: $(EXE)
	./$(EXE)

clean:
	rm -rf $(BUILD)

.PHONY: all run clean
