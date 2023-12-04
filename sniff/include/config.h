/* define if you have a cloning BPF device */
/* #undef HAVE_CLONING_BPF */

/* define if you have the DAG API */
/* #undef HAVE_DAG_API */

/* define if you have streams capable DAG API */
/* #undef HAVE_DAG_STREAMS_API */

/* define if you have a /dev/dlpi */
/* #undef HAVE_DEV_DLPI */

/* on HP-UX 10.20 or later */
/* #undef HAVE_HPUX10_20_OR_LATER */

/* on HP-UX 9.x */
/* #undef HAVE_HPUX9 */

/* if ppa_info_t_dl_module_id exists */
/* #undef HAVE_HP_PPA_INFO_T_DL_MODULE_ID_1 */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* if there's an os_proto.h */
/* #undef HAVE_OS_PROTO_H */

/* Define to 1 if you have the <sys/dlpi_ext.h> header file. */
/* #undef HAVE_SYS_DLPI_EXT_H */

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* if unaligned access fails */
#ifdef _SUN_MACHINE
	#define LBL_ALIGN 1
	/* Define to 1 if you have the <sys/bufmod.h> header file. */
	#define HAVE_SYS_BUFMOD_H 1
	/* On solaris */
	#define HAVE_SOLARIS 1
#else
	/* for _AIX_MACHINE */

	#undef LBL_ALIGN 
	/* Define to 1 if you have the <sys/bufmod.h> header file. */
	#undef HAVE_SYS_BUFMOD_H
	/* On solaris */
	#undef HAVE_SOLARIS
#endif

/* for AIX 5.2 */
#define _SUN 1

/* /dev/dlpi directory */
/* #undef PCAP_DEV_PREFIX */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Enable parser debugging */
/* #undef YYDEBUG */

/* needed on HP-UX */
/* #undef _HPUX_SOURCE */

/* Define as token for inline if inlining supported */
#define inline inline

/* on sinix */
/* #undef sinix */

/* if we have u_int16_t, u_int16_t, u_int8_t */
#ifndef  u_int32t 
	#define u_int32_t u_int
#endif

#ifndef  u_int16_t 
	#define u_int16_t u_short
#endif

#ifndef  u_int8_t 
	#define u_int8_t u_char
#endif

#define _IDS_MODE
