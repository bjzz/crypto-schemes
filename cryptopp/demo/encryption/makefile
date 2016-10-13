# ------------------------------------------------------------------------------
# name:   C/C++ makefile
# author: chenyao
# mail:   cheny@meizu.com
# date:   2016年 10月 13日 星期四 21:16:37 CST
# 
# ------------------------------------------------------------------------------
#
#
# ------------------------------------------------------------------------------
TARGET   :=enryption
LIBS     :=cryptopp

PATH_LIB :=../../lib
PATH_INC :=../../include
PATH_SRC :=.
PATH_OBJ :=../obj/$(TARGET)/
PATH_BIN :=../bin/

CXX      :=g++
CPPFLAGS :=-g -Wall -O3
CPPFLAGS +=$(addprefix -I,$(PATH_INC))

RM :=rm -f

BINS :=$(addprefix $(PATH_BIN),$(TARGET))
SRCS :=$(foreach n,$(PATH_SRC),$(wildcard $(addsuffix .cpp,$(n)/*))) 
OBJS :=$(addprefix $(PATH_OBJ),$(addsuffix .o,$(basename $(notdir $(SRCS)))))
DEPS_MISS :=$(filter-out $(wildcard $(DEPS)),$(DEPS))


.PHONY: all clean rebuild info link

all: $(PATH_BIN) $(PATH_OBJ) $(BINS)

$(PATH_BIN): ; -mkdir -p $(PATH_BIN)
$(PATH_OBJ): ; -mkdir -p $(PATH_OBJ)

$(PATH_OBJ)%.o: %.cpp
	$(CXX) $(CPPFLAGS) -c -o $@ $<

$(BINS): $(OBJS) link
	$(CXX) -o $(BINS) $(OBJS) $(addprefix -L,$(PATH_LIB)) $(addprefix -l,$(LIBS))

link:
	@ln -s -f $(PATH_LIB)/libcryptopp.so $(PATH_BIN)/libcryptopp.so.5.6

clean:
	@$(RM) $(BINS)
	@$(RM) $(OBJS)

rebuild: clean all

info:
	@echo $(BINS)
	@echo $(SRCS)
	@echo $(OBJS)
