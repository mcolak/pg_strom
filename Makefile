# Makefile of PG-Strom
MODULE_big = pg_strom
OBJS = main.o shmem.o plan.o scan.o modify.o utilcmds.o vacuum.o \
	opencl_common.o codegen.o opencl_serv.o opencl_entry.o toast.o

OPENCL_INCLUDE := /usr/include
# OPENCL_INCLUDE := /usr/local/cuda/include
PG_CPPFLAGS := -I$(OPENCL_INCLUDE) -Werror
SHLIB_LINK := -ldl -lpthread

EXTENSION = pg_strom
DATA = pg_strom--1.0.sql
EXTRA_CLEAN = opencl_common.c

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

opencl_common.c: opencl_common.h
	(echo "const char *pgstrom_common_clhead ="; \
	 sed -e 's/\\/\\\\/g' -e 's/\t/\\t/g' -e 's/"/\\"/g' \
	     -e 's/^/  "/g' -e 's/$$/\\n"/g'< $^; \
	 echo ";") > $@
