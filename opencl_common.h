#ifndef OPENCL_COMMON_H
#define OPENCL_COMMON_H
/*
 * opencl_serv always adds -DSTROMCL_VECTOR_WIDTH=<width> on kernel
 * build, but not for host code. So, the #if ... #endif block is
 * available only opencl code.
 */
#ifdef STROMCL_VECTOR_WIDTH
#pragma OPENCL EXTENSION cl_khr_fp64 : enable

/* NULL definition */
#define NULL	((void *) 0)

/* type definitions for APIs */
typedef char		cl_char;
typedef uchar		cl_uchar;
typedef short		cl_short;
typedef ushort		cl_ushort;
typedef int			cl_int;
typedef uint		cl_uint;
typedef long		cl_long;
typedef ulong		cl_ulong;
typedef float		cl_float;
typedef double		cl_double;

/* Stuff related to varlena */
typedef struct {
	int		vl_len;
	char	vl_dat[1];
} varlena;
#define VARHDRSZ			((int) sizeof(int))
#define VARDATA(PTR)		(((varlena *)(PTR))->vl_dat)
#define VARSIZE(PTR)		(((varlena *)(PTR))->vl_len)
#define VARSIZE_EXHDR(PTR)	(VARSIZE(PTR) - VARHDRSZ)

/* common opencl definition for PG-Strom */
#if STROMCL_VECTOR_WIDTH == 16
typedef char16		char_v;
typedef short16		short_v;
typedef int16		int_v;
typedef long16		long_v;
typedef float16		float_v;
typedef double16	double_v;
#define pg_convert_char_v(X)		convert_char16(X)
#define pg_convert_short_v(X)		convert_short16(X)
#define pg_convert_int_v(X)			convert_int16(X)
#define pg_convert_long_v(X)		convert_long16(X)
#define pg_convert_float_v(X)		convert_float16(X)
#define pg_convert_double_v(X)		convert_double16(X)
#define pg_vload(OFFSET,PTR)		vload16((OFFSET),(PTR))
#define pg_vstore(DATA,OFFSET,PTR)	vstore16((DATA),(OFFSET),(PTR))
#define IF_VEC16(X)			X
#define IF_VEC08(X)			X
#define IF_VEC04(X)			X
#define IF_VEC02(X)			X
#define IF_VEC01(X)			X

#elif STROMCL_VECTOR_WIDTH == 8
typedef char8		char_v;
typedef short8		short_v;
typedef int8		int_v;
typedef long8		long_v;
typedef float8		float_v;
typedef double8		double_v;
#define pg_convert_char_v(X)		convert_char8(X)
#define pg_convert_short_v(X)		convert_short8(X)
#define pg_convert_int_v(X)			convert_int8(X)
#define pg_convert_long_v(X)		convert_long8(X)
#define pg_convert_float_v(X)		convert_float8(X)
#define pg_convert_double_v(X)		convert_double8(X)
#define pg_vload(OFFSET,PTR)		vload8((OFFSET),(PTR))
#define pg_vstore(DATA,OFFSET,PTR)	vstore8((DATA),(OFFSET),(PTR))
#define IF_VEC16(X)
#define IF_VEC08(X)			X
#define IF_VEC04(X)			X
#define IF_VEC02(X)			X
#define IF_VEC01(X)			X

#elif STROMCL_VECTOR_WIDTH == 4
typedef char4		char_v;
typedef short4		short_v;
typedef int4		int_v;
typedef long4		long_v;
typedef float4		float_v;
typedef double4		double_v;
#define pg_convert_char_v(X)		convert_char4(X)
#define pg_convert_short_v(X)		convert_short4(X)
#define pg_convert_int_v(X)			convert_int4(X)
#define pg_convert_long_v(X)		convert_long4(X)
#define pg_convert_float_v(X)		convert_float4(X)
#define pg_convert_double_v(X)		convert_double4(X)
#define pg_vload(OFFSET,PTR)		vload4((OFFSET),(PTR))
#define pg_vstore(DATA,OFFSET,PTR)	vstore4((DATA),(OFFSET),(PTR))
#define IF_VEC16(X)
#define IF_VEC08(X)
#define IF_VEC04(X)			X
#define IF_VEC02(X)			X
#define IF_VEC01(X)			X

#elif STROMCL_VECTOR_WIDTH == 2
typedef char2		char_v;
typedef short2		short_v;
typedef int2		int_v;
typedef long2		long_v;
typedef float2		float_v;
typedef double2		double_v;
#define pg_convert_char_v(X)		convert_char2(X)
#define pg_convert_short_v(X)		convert_short2(X)
#define pg_convert_int_v(X)			convert_int2(X)
#define pg_convert_long_v(X)		convert_long2(X)
#define pg_convert_float_v(X)		convert_float2(X)
#define pg_convert_double_v(X)		convert_double2(X)
#define pg_vload(OFFSET,PTR)		vload2((OFFSET),(PTR))
#define pg_vstore(DATA,OFFSET,PTR)	vstore2((DATA),(OFFSET),(PTR))
#define IF_VEC16(X)
#define IF_VEC08(X)
#define IF_VEC04(X)
#define IF_VEC02(X)			X
#define IF_VEC01(X)			X
#else
#if STROMCL_VECTOR_WIDTH != 1
#error STROMCL_VECTOR_WIDTH must be one of 16, 8, 4, 2 or 1
#endif
typedef char		char_v;
typedef short		short_v;
typedef int			int_v;
typedef long		long_v;
typedef float		float_v;
typedef double		double_v;
#define pg_convert_char_v(X)		convert_char(X)
#define pg_convert_short_v(X)		convert_short(X)
#define pg_convert_int_v(X)			convert_int(X)
#define pg_convert_long_v(X)		convert_long(X)
#define pg_convert_float_v(X)		convert_float(X)
#define pg_convert_double_v(X)		convert_double(X)
#define pg_vload(OFFSET,PTR)		*((PTR) + (OFFSET))
#define pg_vstore(DATA,OFFSET,PTR)	\
	do { *((PTR) + (OFFSET)) = (DATA); } while(0)
#define IF_VEC16(X)
#define IF_VEC08(X)
#define IF_VEC04(X)
#define IF_VEC02(X)
#define IF_VEC01(X)			X
#endif

/* template for native types */
#define STROMCL_NATIVE_DATATYPE_TEMPLATE(NAME,BASE)	\
	typedef struct									\
	{												\
		BASE		value;							\
		char		isnull;							\
	} pg_##NAME##_s;								\
	typedef struct									\
	{												\
		BASE##_v	value;							\
		char_v		isnull;							\
	} pg_##NAME##_v;

/* Template for simple type */
#define STROMCL_SIMPLE_DATATYPE_TEMPLATE(NAME,BASE)	\
	typedef struct									\
	{												\
		BASE		value;							\
		char		isnull;							\
	} pg_##NAME##_s;								\
	typedef struct									\
	{												\
		struct {									\
			IF_VEC01(BASE	s0);					\
			IF_VEC02(BASE	s1);					\
			IF_VEC04(BASE	s2);					\
			IF_VEC04(BASE	s3);					\
			IF_VEC08(BASE	s4);					\
			IF_VEC08(BASE	s5);					\
			IF_VEC08(BASE	s6);					\
			IF_VEC08(BASE	s7);					\
			IF_VEC16(BASE	s8);					\
			IF_VEC16(BASE	s9);					\
			IF_VEC16(BASE	sa);					\
			IF_VEC16(BASE	sb);					\
			IF_VEC16(BASE	sc);					\
			IF_VEC16(BASE	sd);					\
			IF_VEC16(BASE	se);					\
			IF_VEC16(BASE	sf);					\
		} value;									\
		char_v	isnull;								\
	} pg_##NAME##_v;
#define STROMCL_VARLENA_DATATYPE_TEMPLATE(NAME)		\
	STROMCL_SIMPLE_TYPE_TEMPLATE(NAME, __global varlena *)

/* Template of pg_vref_<name> function for native types */
#define STROMCL_NATIVE_VARREF_TEMPLATE(NAME,BASE)					\
	static pg_##NAME##_v pg_##NAME##_vref(							\
		__private int attidx,										\
		__private int rowidx,										\
		__global kern_args_t *kargs,								\
		__global char *kvlbuf)										\
	{																\
		pg_##NAME##_v result;										\
		__global BASE *p_values;									\
		__global char *p_isnull;									\
																	\
		if (kargs->offset[j].isnull == 0)							\
			result.isnull = (char)0;								\
		else														\
		{															\
			p_isnull = (((__global char *)kargs) +					\
						kargs->offset[j].isnull);					\
			result.isnull = pg_vload(rowidx, p_isnull);				\
		}															\
		p_values = (__global BASE *)(((__global char *)kargs) +		\
									 kargs->offset[j].values);		\
		result.value = pg_vload(rowidx, p_values);					\
																	\
		return result;												\
	}

/* Template of pg_<name>_vref function for simple types */
#define STROMCL_SIMPLE_VARREF_TEMPLATE(NAME,BASE)					\
	static pg_##NAME##_v pg_##NAME##_vref(							\
		__private int attidx,										\
		__private int rowidx,										\
		__global kern_args_t *kargs,								\
		__global char *kvlbuf)										\
	{																\
		pg_##NAME##_v result;										\
		__global BASE *p_values;									\
		__global char *p_isnull;									\
																	\
		if (kargs->offset[j].isnull == 0)							\
			result.isnull = (char)0;								\
		else														\
		{															\
			p_isnull = (((__global char *)kargs) +					\
						kargs->offset[j].isnull);					\
			result.isnull = pg_vload(rowidx, p_isnull);				\
		}															\
		p_values = (__global BASE *)(((__global char *)kargs) +		\
									 kargs->offset[j].values);		\
		IF_VEC01(result.value.s0 = p_values[rowidx++]);				\
		IF_VEC02(result.value.s1 = p_values[rowidx++]);				\
		IF_VEC04(result.value.s2 = p_values[rowidx++]);				\
		IF_VEC04(result.value.s3 = p_values[rowidx++]);				\
		IF_VEC08(result.value.s4 = p_values[rowidx++]);				\
		IF_VEC08(result.value.s5 = p_values[rowidx++]);				\
		IF_VEC08(result.value.s6 = p_values[rowidx++]);				\
		IF_VEC08(result.value.s7 = p_values[rowidx++]);				\
		IF_VEC16(result.value.s8 = p_values[rowidx++]);				\
		IF_VEC16(result.value.s9 = p_values[rowidx++]);				\
		IF_VEC16(result.value.sa = p_values[rowidx++]);				\
		IF_VEC16(result.value.sb = p_values[rowidx++]);				\
		IF_VEC16(result.value.sc = p_values[rowidx++]);				\
		IF_VEC16(result.value.sd = p_values[rowidx++]);				\
		IF_VEC16(result.value.se = p_values[rowidx++]);				\
		IF_VEC16(result.value.sf = p_values[rowidx++]);				\
																	\
		return result;												\
	}

/* Template of pg_vref_<name> function for non-native types */
#define STROMCL_VARLENA_VARREF_TEMPLATE(NAME)						\
	static pg_##NAME##_v pg_##NAME##_vref(							\
		__private int attidx,										\
		__private int rowidx,										\
		__global kern_args_t *kargs,								\
		__global char *kvlbuf)										\
	{																\
		pg_##NAME##_v ret;											\
		__global varlena *p_values;									\
		__global uint *p_offset										\
		__global char *p_isnull;									\
																	\
		if (kargs->offset[j].isnull == 0)							\
			ret.isnull = (char)0;									\
		else														\
		{															\
			p_isnull = (((__global char *)kargs) +					\
						kargs->offset[j].isnull);					\
			ret.isnull = pg_vload(rowidx, p_isnull);				\
		}															\
		p_offset = (__global BASE *)(((__global char *)kargs) +		\
									 kargs->offset[j].values);		\
		IF_VEC01(ret.value.s0 = (varlena *)(kvlbuf + p_offset[rowidx])); \
		IF_VEC02(ret.value.s1 = (varlena *)(kvlbuf + p_offset[rowidx+ 1])); \
		IF_VEC04(ret.value.s2 = (varlena *)(kvlbuf + p_offset[rowidx+ 2])); \
		IF_VEC04(ret.value.s3 = (varlena *)(kvlbuf + p_offset[rowidx+ 3])); \
		IF_VEC08(ret.value.s4 = (varlena *)(kvlbuf + p_offset[rowidx+ 4])); \
		IF_VEC08(ret.value.s5 = (varlena *)(kvlbuf + p_offset[rowidx+ 5])); \
		IF_VEC08(ret.value.s6 = (varlena *)(kvlbuf + p_offset[rowidx+ 6])); \
		IF_VEC08(ret.value.s7 = (varlena *)(kvlbuf + p_offset[rowidx+ 7])); \
		IF_VEC16(ret.value.s8 = (varlena *)(kvlbuf + p_offset[rowidx+ 8])); \
		IF_VEC16(ret.value.s9 = (varlena *)(kvlbuf + p_offset[rowidx+ 9])); \
		IF_VEC16(ret.value.sa = (varlena *)(kvlbuf + p_offset[rowidx+10])); \
		IF_VEC16(ret.value.sb = (varlena *)(kvlbuf + p_offset[rowidx+11])); \
		IF_VEC16(ret.value.sc = (varlena *)(kvlbuf + p_offset[rowidx+12])); \
		IF_VEC16(ret.value.sd = (varlena *)(kvlbuf + p_offset[rowidx+13])); \
		IF_VEC16(ret.value.se = (varlena *)(kvlbuf + p_offset[rowidx+14])); \
		IF_VEC16(ret.value.sf = (varlena *)(kvlbuf + p_offset[rowidx+15])); \
																	\
		return result;												\
	}

/* function template to reference native-type'd parameter */
#define STROMCL_NATIVE_PARAMREF_TEMPLATE(NAME,BASE)				\
	static pg_##NAME##_v pg_##NAME##_pref(						\
		int p_index,											\
		__global kern_params_t *kparams)						\
	{															\
		pg_##NAME##_v result;									\
		size_t p_offset;										\
		BASE value;												\
																\
		p_offset = kparams->p_offset[p_index];					\
		if (p_offset == 0)										\
			result.isnull = (char)(-1);							\
		else													\
		{														\
			result.isnull = (char)(0);							\
			value = *((__global BASE *)							\
					  (((__global char *)kparams) + p_offset));	\
			result.value = value;								\
		}														\
		return result;											\
	}

/* function template for pg_<name>_pref */
#define STROMCL_SIMPLE_PARAMREF_TEMPLATE(NAME,BASE)				\
	static pg_##NAME##_v pg_##NAME##_pref(						\
		int p_index,											\
		__global kern_params_t *kparams)						\
	{															\
		pg_##NAME##_v result;									\
		size_t p_offset;										\
		BASE value;												\
																\
		p_offset = kparams->p_offset[p_index];					\
		if (p_offset == 0)										\
			result.isnull = (char)(-1);							\
		else													\
		{														\
			result.isnull = (char)(0);							\
			value = *((__global BASE *)							\
					  (((__global char *)kparams) + p_offset));	\
			IF_VEC01(result.value.s0 = value);					\
			IF_VEC02(result.value.s1 = value);					\
			IF_VEC04(result.value.s2 = value);					\
			IF_VEC04(result.value.s3 = value);					\
			IF_VEC08(result.value.s4 = value);					\
			IF_VEC08(result.value.s5 = value);					\
			IF_VEC08(result.value.s6 = value);					\
			IF_VEC08(result.value.s7 = value);					\
			IF_VEC16(result.value.s8 = value);					\
			IF_VEC16(result.value.s9 = value);					\
			IF_VEC16(result.value.sa = value);					\
			IF_VEC16(result.value.sb = value);					\
			IF_VEC16(result.value.sc = value);					\
			IF_VEC16(result.value.sd = value);					\
			IF_VEC16(result.value.se = value);					\
			IF_VEC16(result.value.sf = value);					\
		}														\
		return result;											\
	}

#define STROMCL_VARLENA_PARAMREF_TEMPLATE(NAME)					\
	static pg_##NAME##_v pg_##NAME##_pref(						\
		int p_index,											\
		__global kern_params_t *kparams)						\
	{															\
		pg_##NAME##_v result;									\
		size_t p_offset;										\
		__global varlena *value;								\
																\
		p_offset = kparams->p_offset[p_index];					\
		if (p_offset == 0)										\
			result.isnull = (char)(-1);							\
		else													\
		{														\
			result.isnull = (char)(0);							\
			value = (__global varlena *)						\
				(((__global char *)kparams) + p_offset);		\
			IF_VEC01(result.value.s0 = value);					\
			IF_VEC02(result.value.s1 = value);					\
			IF_VEC04(result.value.s2 = value);					\
			IF_VEC04(result.value.s3 = value);					\
			IF_VEC08(result.value.s4 = value);					\
			IF_VEC08(result.value.s5 = value);					\
			IF_VEC08(result.value.s6 = value);					\
			IF_VEC08(result.value.s7 = value);					\
			IF_VEC16(result.value.s8 = value);					\
			IF_VEC16(result.value.s9 = value);					\
			IF_VEC16(result.value.sa = value);					\
			IF_VEC16(result.value.sb = value);					\
			IF_VEC16(result.value.sc = value);					\
			IF_VEC16(result.value.sd = value);					\
			IF_VEC16(result.value.se = value);					\
			IF_VEC16(result.value.sf = value);					\
		}														\
		return result;											\
	}

#define STROMCL_NATIVE_TYPE_TEMPLATE(NAME,BASE)		\
	STROMCL_NATIVE_DATATYPE_TEMPLATE(NAME,BASE)		\
	STROMCL_NATIVE_VARREF_TEMPLATE(NAME,BASE)		\
	STROMCL_NATIVE_PARAMREF_TEMPLATE(NAME,BASE)

#define STROMCL_SIMPLE_TYPE_TEMPLATE(NAME,BASE)		\
	STROMCL_SIMPLE_DATATYPE_TEMPLATE(NAME,BASE)		\
	STROMCL_SIMPLE_VARREF_TEMPLATE(NAME,BASE)		\
	STROMCL_SIMPLE_PARAMREF_TEMPLATE(NAME,BASE)

#define STROMCL_VARLENA_TYPE_TEMPLATE(NAME)			\
	STROMCL_VARLENA_DATATYPE_TEMPLATE(NAME)			\
	STROMCL_VARLENA_VARREF_TEMPLATE(NAME)			\
	STROMCL_VARLENA_PARAMREF_TEMPLATE(NAME)

/* misc definitions */
#define ROWMAP_BASE(kargs)						\
	(((__global char *)(kargs)) + (kargs)->offset[(kargs)->i_rowmap].values)

#endif	/* STROMCL_VECTOR_WIDTH */
/*
 * Kernel Parameters - 1st argument of kernel function
 */
typedef struct {
	cl_int		p_nums;			/* number of parameters */
	cl_int		p_offset[0];	/* value offset. 0 means NULL */
} kern_params_t;

/*
 * Kernel Arguments - 2nd argument of kernel function
 */
typedef struct {
	cl_int		nargs;		/* number of argumens */
	cl_int		i_rowmap;	/* index to rowmap field */
	cl_int		nitems;		/* number of items */
	struct {
		cl_int	isnull;
		cl_int	values;
	} offset[0];
} kern_args_t;

/*
 * Error codes
 */
#define STROMCL_ERRCODE_SUCCESS				((char)0x00)	/* OK */
#define STROMCL_ERRCODE_DIV_BY_ZERO			((char)0x20)
#define STROMCL_ERRCODE_OUT_OF_RANGE		((char)0x21)
#define STROMCL_ERRCODE_INTERNAL			((char)0x22)
#define STROMCL_ERRCODE_ROW_MASKED			((char)0xff)	/* masked */

#endif	/* OPENCL_COMMON_H */
