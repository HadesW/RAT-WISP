# WISP++ C++ agent — MinGW cross-build. Outputs -> bin/out, intermediates -> bin/temp.
#
# Targets: make | make all        x64 + x86 release EXE
#          make x64 | make x86
#          make exe dll svc       (per-arch outputs)
#          make clean

CXX_X64 := x86_64-w64-mingw32-g++
CXX_X86 := i686-w64-mingw32-g++

SRC_DIR  := src
OUT_DIR  := bin/out
TEMP_DIR := bin/temp

WISP_SRCS := main.cpp WispAgent.cpp WispConfig.cpp WispCrypto.cpp \
WispJson.cpp WispHttp.cpp WispRcp.cpp WispPlugin.cpp tweetnacl.c ApiLoader.cpp ProcLoader.cpp \
utils.cpp Encoders.cpp crt.cpp config.cpp
LEGACY_EXCLUDE :=

COMMON_FLAGS := -I $(SRC_DIR) \
                -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables \
                -fno-stack-protector -fno-strict-overflow -fno-delete-null-pointer-checks \
                -fno-strict-aliasing -fno-builtin -fpermissive -w -fPIC

# config.cpp is compiled from files/config.tpl in the legacy tree; the WISP++
# build uses the checked-in src/config.cpp stub (service name only).
SOURCES := $(WISP_SRCS)

X64_OBJS := $(patsubst %.cpp,$(TEMP_DIR)/x64/%.o,$(SOURCES))
X86_OBJS := $(patsubst %.cpp,$(TEMP_DIR)/x86/%.o,$(SOURCES))

.PHONY: all x64 x86 exe dll svc clean pre

all: x64 x86

pre:
	@mkdir -p $(OUT_DIR) $(TEMP_DIR)/x64 $(TEMP_DIR)/x86

x64: pre $(OUT_DIR)/wisp-agent-cpp-x64.exe
x86: pre $(OUT_DIR)/wisp-agent-cpp-x86.exe

exe: x64 x86
dll: $(OUT_DIR)/wisp-agent-cpp-x64.dll $(OUT_DIR)/wisp-agent-cpp-x86.dll
svc: $(OUT_DIR)/wisp-agent-cpp-x64-svc.exe $(OUT_DIR)/wisp-agent-cpp-x86-svc.exe

$(TEMP_DIR)/x64/%.o: $(SRC_DIR)/%.cpp | pre
	@echo "[x64] $<"
	@$(CXX_X64) -c $(COMMON_FLAGS) -D NDEBUG $< -o $@

$(TEMP_DIR)/x86/%.o: $(SRC_DIR)/%.cpp | pre
	@echo "[x86] $<"
	@$(CXX_X86) -c $(COMMON_FLAGS) -D NDEBUG $< -o $@

# no-CRT link: custom entry (WinMain), kernel32 only, symbols resolved at runtime
$(OUT_DIR)/wisp-agent-cpp-x64.exe: $(X64_OBJS)
	@$(CXX_X64) -nostdlib -mwindows -Wl,--entry=WinMain -Wl,-s -o $@ $^ -lkernel32
	@echo "OK: $@"

$(OUT_DIR)/wisp-agent-cpp-x86.exe: $(X86_OBJS)
	@$(CXX_X86) -nostdlib -mwindows -Wl,--entry=WinMain -Wl,-s -o $@ $^ -lkernel32
	@echo "OK: $@"

$(OUT_DIR)/wisp-agent-cpp-x64.dll: $(patsubst %.cpp,$(TEMP_DIR)/x64dll/%.o,$(SOURCES))
	@mkdir -p $(TEMP_DIR)/x64dll
	@$(CXX_X64) -nostdlib -shared -Wl,--entry=DllMain@12 -Wl,-s -o $@ $^ -lkernel32
	@echo "OK: $@"

$(OUT_DIR)/wisp-agent-cpp-x86.dll: $(patsubst %.cpp,$(TEMP_DIR)/x86dll/%.o,$(SOURCES))
	@mkdir -p $(TEMP_DIR)/x86dll
	@$(CXX_X86) -nostdlib -shared -Wl,--entry=DllMain@12 -Wl,-s -o $@ $^ -lkernel32
	@echo "OK: $@"

$(OUT_DIR)/wisp-agent-cpp-x64-svc.exe: $(patsubst %.cpp,$(TEMP_DIR)/x64svc/%.o,$(SOURCES))
	@mkdir -p $(TEMP_DIR)/x64svc
	@$(CXX_X64) -nostdlib -mwindows -Wl,--entry=WinMain -Wl,-s -DBUILD_SVC -o $@ $^ -lkernel32
	@echo "OK: $@"

$(OUT_DIR)/wisp-agent-cpp-x86-svc.exe: $(patsubst %.cpp,$(TEMP_DIR)/x86svc/%.o,$(SOURCES))
	@mkdir -p $(TEMP_DIR)/x86svc
	@$(CXX_X86) -nostdlib -mwindows -Wl,--entry=WinMain -Wl,-s -DBUILD_SVC -o $@ $^ -lkernel32
	@echo "OK: $@"

clean:
	@rm -rf $(TEMP_DIR) $(OUT_DIR)
	@echo cleaned
