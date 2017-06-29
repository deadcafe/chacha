# Copyright (C) 2017, deadcafe.beef@gmail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#   3. Neither the name of the project nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

CHACHA_ROOT ?= ..

TARGET = chacha


export CHACHA_ROOT
export LANG=C
export LC_ALL=$(LANG)
export LC_MESSAGES=$(LANG)
export OBJ_DIR=$(CHACHA_ROOT)/objs

CC = gcc
AR ?= ar
RANLIB ?= ranlib
RM ?= rm
MKDIR ?= mkdir

OBJ_DIR = objs
SRCS = $(wildcard *.c)
OBJS = $(addprefix $(OBJ_DIR)/,$(notdir $(SRCS:.c=.o)))
DEPENDS =  .depends

CPPFLAGS = -D_FORTIFY_SOURCE=2 -std=gnu11 -D_GNU_SOURCE -I$(CHACHA_ROOT)/include -I.

# -fno-strict-aliasing -fno-strict-overflow -fno-tree-vrp \

CFLAGS = \
	-g -m64 -fPIE -fomit-frame-pointer \
        -Werror -Wall -Wextra \
        -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings \
        -Wfloat-equal -Wpointer-arith \
        -Wtrampolines -Wtrampolines

CFLAGS += -fstack-protector
LDFLAGS = -g
LIBS =

.PHONY: all clean depend
.SUFFIXES: .c .o


#CFLAGS += -O3 -march=westmere -mtune=westmere -msse4
#CFLAGS += -O3 -march=core-avx-i -mtune=core-avx-i -mavx -msse2avx

CFLAGS_GEN    = -O3 -march=native
CFLAGS_SSE    = -O3 -msse4
CFLAGS_AVX    = -O3 -mavx
CFLAGS_AVX2   = -O3 -mavx2
CFLAGS_AVX512 = -O3 -mavx512f -mavx512bw -mavx512dq -mavx512vl


all:	$(TARGET)

$(TARGET):	$(OBJS)
	$(CC) -o $@ $^ $(LIBS) $(LDFLAGS)

$(OBJ_DIR)/chacha_sse.o: chacha_sse.c depend
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_SSE) -o $@ -c $<

$(OBJ_DIR)/chacha_avx.o: chacha_avx.c depend
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_AVX) -o $@ -c $<

$(OBJ_DIR)/chacha_avx2.o: chacha_avx2.c depend
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_AVX2) -o $@ -c $<

$(OBJ_DIR)/chacha_opt_avx2.o: chacha_opt_avx2.c depend
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_AVX2) -o $@ -c $<

$(OBJ_DIR)/chacha_avx512.o: chacha_avx512.c depend
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_AVX512) -o $@ -c $<

$(OBJ_DIR)/chacha_gen.o: chacha_gen.c depend
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_GEN) -o $@ -c $<

$(OBJ_DIR)/main.o:	main.c depend
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_GEN) -o $@ -c $<

depend:	$(OBJ_DIR) Makefile
	$(CC) -MM $(CPPFLAGS) $(SRCS) > $(DEPENDS)

$(OBJ_DIR):
	@$(MKDIR) $(OBJ_DIR)

clean:
	@$(RM) $(OBJS) $(DEPENDS) $(TARGET) core

-include $(DEPENDS)
