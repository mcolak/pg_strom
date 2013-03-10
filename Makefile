# Makefile of pg_strom
MODULE_big = pg_strom
OBJS = main.o plan.o exec.o utilcmds.o columnizer.o \
	opencl_serv.o opencl_entry.o

OPENCL_INCLUDE := /usr/include
# OPENCL_INCLUDE := /usr/local/cuda/include
PG_CPPFLAGS := -I$(OPENCL_INCLUDE) -Werror
SHLIB_LINK := -ldl

EXTENSION = pg_strom
DATA = pg_strom--1.0.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
