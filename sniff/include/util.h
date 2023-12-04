/*
** (C) Copyright 2010. PNP Secure, Inc.
**
** Any part of this source code can not be copied with
** any method without prior written permission from
** the author or authorized person.
**
*/

/*---- FILE DESCRIPTION ---------------------------------------------*/

/**
 * @file util.h
 * @author SunTae Jin(zalhae@pnpsecure.com)
 * @brief util.c의 header file
 */

/*---- INCLUDES		 ------------------------------------------------*/

#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "repository.h"
#include "packet.h"


/*---- DEFINES		  -----------------------------------------------*/

#ifndef __UTIL_H
#define __UTIL_H

#define  no_argument           0            /**< 추가 옵션이 없는 매개 변수를 나타냄 */
#define  required_argument     1            /**< 추가 옵션이 있는 매개 변수를 나타냄 */
#define  MIN_FIELD_SIZE        4            /**< 환경 파일 필드의 최소 길이 */
#define  MAX_STR_SIZE          2048         /**< buffer size */

#define  CONF_DELIMITER        "=\"\r\n"    /**< configure field에서 사용하는 delimiter */
#define  CONF_FIELD_DELIMITER  "\"\r\n"     /**< configure line을 구분하기 위한 delimiter */
#define  ONE_MINUTE_SEC  60                 /**< 1분 == 60초 */

#define  CONF_DIR_DS2          "/dbms_ips/.conf/"   /**< 환경 설정 file이 저장된 경로#1 */
#define  CONF_DIR_ETC          ".conf/"             /**< 환경 설정 file이 저장된 경로#4 */

#define  CONF_FILE_NAME        "conf/server_agent.conf"
#define  OS_INFO_NAME          "conf/os.conf"

#define  CRC_BYTE_SIZE         20
#define  CRC_STR_SIZE          (CRC_BYTE_SIZE*2+1)

#define  IP_HEADER_LEN         20
#define  TCP_HEADER_LEN        20

#ifdef _AIX43_NONE_GCC
 #define __func__ "unknown"
#endif

typedef unsigned char BYTE;

/* for error code */
enum _error_no_e
{
	ERR_UNKNOWN = -1,
	ERR_SUCCESS = 0,
	ERR_NULL,
	ERR_INVAL,
	ERR_FREAD,
	ERR_FORK
};


typedef enum
{
	SERVICE_UNKNOWN = -1,
	SERVICE_STOP = 0,
	SERVICE_START,
	SERVICE_RESTART,
	SERVICE_ALIAS_UPDATE,
	SERVICE_RULE_UPDATE,
	SERVICE_GET_LOG,
	SERVICE_AGENT_UPGRADE,
	SERVICE_MANAGER_UPGRADE
} category_e;


/*---- TYPEDEF/STRUCT DECLARATION -----------------------------------*/

struct option2
{
	const char *name;
	int has_arg;
	int *flag;
	int val;
};


/*! \brief
 *   Port 번호를 비교하기 위한 구조체
 *  \remark
 *   count 값을 기준으로 단일형 또는 범위형인지 알 수 있다.
 */
typedef struct
{
	char category;
	char crc[CRC_STR_SIZE];
	unsigned int length;
} sa_message_t;


/*! \brief
 * tcp checksum을 구하기 위한 pseudo header
 */
typedef struct  {
	u_int32_t saddr;       /**< 출발지 IP주소 */
	u_int32_t daddr;       /**< 목적지 IP주소 */
	u_int8_t  useless;     /**< reserved field */
	u_int8_t  protocol;    /**< protocol 번호 (TCP, UDP, ...) */
	u_int16_t tcplength;   /**< tcp header의 길이 */
} pseudohdr_t;


#if 0
/*! \brief
 * TCP/IP header 모음 구조체
 */
typedef struct 
{
	sniff_ip_t  iph;       /**< IP header */
	sniff_tcp_t tcph;      /**< TCP header */
} sniff_raw_t;
#endif


/*! \brief
 *   IP 주소를 비교하기 위한 구조체
 *  \remark
 *   ip_seg가 0이면 정보가 없다는 뜻이고, 0x1-0x32는 세그먼트형,
 *   나머지는 범위형,
 *   단일형은 여부는 상위 session_mask에 의하여 알 수 있음
 */
typedef struct
{
    unsigned char  ip_seg;              /**< ip 비교시 어떤 형태로 비교할 것인지 지정 */
    unsigned int   ip_base;             /**< 기준 IP 주소 or FROM IP */
    unsigned int   ip_max;              /**< 범위형을 고려한 최대 IP 주소 */
} ip_info_t;


/* Alert전송 구조체. */
typedef struct _ALERT_T {
	unsigned char crc;     /**< CRC */
	char time[20];         /**< 전송 시간. */
	char jumpdata[255];    /**< Not use. */
	char msg[255];         /**< 전송 메시지. */
} ALERT_T;


/*
#if !defined(socklen_t)
        typedef int socklen_t;
#endif
*/

/*---- GLOBAL VARIABLES ----------------------------------------------*/

extern char *optarg;
extern const char *g_license_string;

/*---- FUNCTIONS FORWARD DECLARATION ---------------------------------*/

int  get_dump_conf(const char* file_name, const char* field_name, char* output, int max_size);
void strim_both(char *source);
int  is_empty_string(const char *str);
char getopt_long2(int argc, char *argv[], char *options, const struct option2 longopts[], int *reserved, char **optarg);

int init_resetpacket(const char *interface);
int send_reset(int raw_sock, const u_char *packet, const packet_t *p, int is_bypass_mode);

int parse_protocol(char *field_value, unsigned short *protocol);
int parse_alias_list(const char *str_value, void *alias_list, int type, char *conf_file_name);
int parse_flow(char *field_value, unsigned char *flow);
int service_onoff(const char *path, const char *cmd);
void write_own_pid(const char *path);
int get_hash_from_file(const char *infile, char *output);
unsigned int get_hash_data(char *pszBuf, int nSize, unsigned int uiSeed);
unsigned int get_hash_string(char *pszBuf, int nSize, BYTE *pacHash);

int write_timeout(int un_sock, const void *buf, int len, unsigned int sec);
int open_uds_socket(const char *uds_path, int is_server);
void kill_process(const char *pid_path);
void display_version(char *progname);
int send_alert_data(const char *agent_ip, unsigned short port, const char *jumpdata, const char *logmsg );
int log_printf (char *pname, const char *pre_fmt , ... );
void *malloc_n_exit(size_t nSize, const char *pFname, int nLine);
int select_timeout(int sock, int sec);
int get_content(char *sbuf, char *content, unsigned short *c_size, int *is_include_binary);
int sort_ip_alias_value(ip_info_t *ip_tmp);

int is_invalid_logic(char *str, int size, u_char *buf);
int search_mem_keyword(char *buff, int buff_len, char *keyword, int keyword_len);
char *strncpy2(char *dest, const char *src, size_t n);

void print_interface();
int remove_pid_file(pid_t stPid);
int check_pid_file(pid_t stPid);
void print_to_console(const packet_t *p, const u_char *packet, int is_print_console, int is_print_hexa);

#ifndef _memcmp
inline int _memcmp(const void *pSrc, const void *pDst, size_t nSize)
{	
	size_t n = nSize>>2;
	if ( n )
	{
		register int *p1_end = (int*)pSrc + n;
		register int *p_src = (int*)pSrc;
		register int *p_dst = (int*)pDst;
	
		for ( ; p_src < p1_end ; p_src++, p_dst++ )
		{
			if ( *p_src != *p_dst )
				return *p_src - *p_dst;
		}

		return memcmp(pSrc, pDst, nSize - (n<<2));
	}

	return memcmp(pSrc, pDst, nSize);
}
#endif

#endif /* __UTIL_H */

