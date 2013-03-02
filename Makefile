# Makefile of pg_strom
MODULE_big = pg_strom
OBJS = main.o plan.o exec.o utilcmds.o columnizer.o opencl_serv.o

OPENCL_DIR := /usr/local/cuda
OPENCL_INCLUDE := $(OPENCL_DIR)/include

PG_CPPFLAGS := -I$(OPENCL_INCLUDE)
SHLIB_LINK := -lcuda -Wl,-rpath,'$(OPENCL_DIR)/lib64' -Wl,-rpath,'$(OPENCL_DIR)/lib'

EXTENSION = pg_strom
DATA = pg_strom--1.0.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
