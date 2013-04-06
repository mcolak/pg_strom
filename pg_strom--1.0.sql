--
-- pg_strom installation queries
--
CREATE FUNCTION pgstrom_fdw_handler()
  RETURNS fdw_handler
  AS 'MODULE_PATHNAME'
  LANGUAGE C STRICT;

CREATE FUNCTION pgstrom_fdw_validator(text[], oid)
  RETURNS void
  AS 'MODULE_PATHNAME'
  LANGUAGE C STRICT;

CREATE FUNCTION pgstrom_vacuum(regclass)
  RETURNS int
  AS 'MODULE_PATHNAME'
  LANGUAGE C STRICT;

CREATE TYPE __pgstrom_shmem_dump AS (
  block_type text,
  block_size int8,
  start_addr text,
  end_addr   text,
  owned_by   int4,
  overrun    bool
);
CREATE FUNCTION pgstrom_shmem_dump()
  RETURNS SETOF __pgstrom_shmem_dump
  AS 'MODULE_PATHNAME'
  LANGUAGE C STRICT;

CREATE FOREIGN DATA WRAPPER pg_strom
  HANDLER pgstrom_fdw_handler
  VALIDATOR pgstrom_fdw_validator;

CREATE SERVER pg_strom FOREIGN DATA WRAPPER pg_strom;


--CREATE TYPE __pgstrom_gpu_info AS
--  (gpuid int, attr text, value text);
--CREATE FUNCTION pgstrom_gpu_info(int default -1)
--  RETURNS SETOF __pgstrom_gpu_info
--  AS 'MODULE_PATHNAME'
--  LANGUAGE C STRICT;

--CREATE VIEW pgstrom_shadow_relations AS
--  SELECT oid, relname, relkind, pg_relation_size(oid) AS relsize
--  FROM pg_class WHERE relnamespace IN
--    (SELECT oid FROM pg_namespace WHERE nspname = 'pg_strom');
