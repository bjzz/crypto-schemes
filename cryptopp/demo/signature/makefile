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
TARGET   :=signature
LIBS     :=cryptopp

# ------------------------------------------------------------------------------
# path
# ------------------------------------------------------------------------------
PATH_LIB :=../../lib
PATH_INC :=../../include
PATH_SRC :=.
PATH_OBJ :=../obj/$(TARGET)/
PATH_BIN :=../bin/

LINK     :=g++
CXX      :=g++
CPPFLAGS :=-g -Wall -O3
CPPFLAGS +=$(addprefix -I,$(PATH_INC))
LIBFLAGS :=-Wl,--rpath='$$ORIGIN'
LIBFLAGS +=$(addprefix -L,$(PATH_LIB)) $(addprefix -l,$(LIBS))

RM :=rm -f

BINS :=$(addprefix $(PATH_BIN),$(TARGET))
SRCS :=$(foreach n,$(PATH_SRC),$(wildcard $(addsuffix .cpp,$(n)/*))) 
OBJS :=$(addprefix $(PATH_OBJ),$(addsuffix .o,$(basename $(notdir $(SRCS)))))


.PHONY: all clean rebuild info link prepare

all: prepare $(BINS) 

prepare: link
	@-mkdir -p $(PATH_BIN)
	@-mkdir -p $(PATH_OBJ)

$(PATH_OBJ)%.o: %.cpp
	$(CXX) $(CPPFLAGS) -c -o $@ $<

$(BINS): $(OBJS)
	$(LINK) -o $(BINS) $(OBJS) $(LIBFLAGS)

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
