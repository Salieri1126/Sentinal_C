/*
** (C) Copyright 2023. PNP Secure, Inc.
**
** Any part of this source code can not be copied with
** any method without prior written permission from
** the author or authorized person.
**
*/

/*---- FILE DESCRIPTION ------------------------------------------------------*/

/*! \file   policy.h
 *  \date   2023/08/07
 *  \note   N/A
 *  \author JST(zalhae@pnpsecure.com)
 *  \remark
 *   - 정책 처리 관련 구조체 및 변수 정의
 */

#ifndef __POLICY_H_
#define __POLICY_H_


/*---- INCLUDES         ------------------------------------------------------*/

#include <iostream>
#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <mysql.h>

#include "dbms_ips.h"
#include "dbms_ips_manager.h"
#include "util.h"


/*---- GLOBAL DEFINES          -----------------------------------------------*/

#define  MAX_IPADDR_LEN         16          /**< '\0'를 포함한 IP주소의 최대 길이 */
#define  MAX_ARRAY_SIZE         4096        /**< 최대 배열 개수 */

/**< 프로세스 종료 시그널 동기화를 위한 코드 */
#define  DO_NOTHING             0x0         /**< 아무것도 하지 않을 경우 */
#define  DO_LOG_LISTENER        0x1         /**< log_listener 처리 중 */
#define  DO_NET_MONITOR         0x2         /**< net_monitor 처리 중 */
#define  DO_MAIN_THREAD         0x4         /**< main_thread 처리 중 */
#define  DO_EXIT                0x8         /**< 종료 시그널을 받은 상태 */

/* for session compare */
#define  SESSION_MASK_NONE      0x0000      /**< 세션 검사를 하지 않음, 필요하지 않음 */
#define  SESSION_MASK_ALL       0xFFFF      /**< 모든 세션 검사를 수행함, 필요하지 않음 */
#define  SESSION_MASK_PORT      0x00F0      /**< port 검사를 함 */
#define  SESSION_MASK_IP        0x0F00      /**< ip 검사를 함 */
#define  SESSION_MASK_CONTENT   0xF000      /**< 내용 검사를 함 */
#define  SESSION_MASK_PROTOCOL  0x0001      /**< protocol 비교 */
#define  SESSION_MASK_SP        0x0010      /**< source port를 비교 */
#define  SESSION_MASK_DP        0x0020      /**< destination port를 비교 */
#define  SESSION_MASK_SIP       0x0100      /**< source ip 주소 비교 */
#define  SESSION_MASK_DIP       0x0200      /**< destination ip 주소 비교 */

#define  SESSION_MASK_BOTH      0x0400      /**< IP나 포트를 방향성과 상관없이 비교 */

#define  SESSION_MASK_CONTENT1  0x1000      /**< content 비교1 */
#define  SESSION_MASK_CONTENT2  0x2000      /**< content 비교2 */

#define  MAX_ALIAS              2048        /**< IP/Port/Time alias의 크기 */

#ifndef ETH_P_8021Q
 #define  ETH_P_8021Q           0x8100      /**< VLAN의 ethernet type code */
#endif
#ifndef ETH_P_RARP
 #define  ETH_P_RARP            0x8035      /**< Reverse Addr Res packet  */
#endif
#ifndef ETH_P_ARP
 #define  ETH_P_ARP             0x0806      /**< Address Resolution packet    */
#endif
#ifndef ETH_P_IP
 #define  ETH_P_IP              0x0800      /**< Internet Protocol packet */
#endif
#ifndef INADDR_NONE
  #define INADDR_NONE           0xffffffff  /**< NONE IP address (-1) */
#endif

#define  COMPARE_SINGLE         1           /**< IP나 Port를 1개만 비교 */
#define  COMPARE_RANGE          2           /**< IP나 Port를 2개로 범위 비교 */
#define  COMPARE_SKIP           0           /**< 비교하지 않음 */

#define  IP_ADDRESS_STR_LEN     15          /**< IP주소 문자열의 최대 길이 */
#define  IP_FULL_MASK           0xFFFFFFFF  /**< 4byte의 IP주소 전체를 덮는 MASK */
#define  IP_SEGMENT_BITS        32          /**< IP주소 전체 BIT수 */

#define  VALUE_STR_ANY         "ANY"        /**< any */
#define  VALUE_STR_any         "any"        /**< any */
#define  VALUE_STR_NOTHING     "NOTHING"    /**< nothing */

#define  ACTION_PASS           0            /**< 통과 */
#define  ACTION_DROP           1            /**< 차단 */
#define  ACTION_ALERT          2            /**< 경고 처리 == 로그 남김 */
#define  ACTION_LOG            ACTION_ALERT /**< 로그 남김 */

#define  VALUE_STR_PASS        "pass"        /**< 통과 */
#define  VALUE_STR_DROP        "drop"        /**< 차단 */
#define  VALUE_STR_LOG         "log"         /**< 로그 남김 */
#define  VALUE_STR_ALERT       "alert"       /**< 경고처리 == 로그 남김 */
#define  VALUE_STR_QUARANTINE  "quarantine"  /**< 격리 */

#define  DEFAULT_INTERFACE     "eth0"        /**< default bridge */

/* for snort rule */
#define  SIG_CONTENT_KEY       "content:\"" /**< snort rule의 content field name */
#define  SIG_MESSAGE_KEY       "msg:\""     /**< snort rule의 message field name */
#define  SIG_SID_KEY           "sid:"       /**< snort rule의 sid field name */
#define  SIG_DATE_KEY          "date:"      /**< date scheduling 값 */
#define  SIG_TIME_KEY          "time:"      /**< time scheduling 값 */
#define  SIG_END_KEY           "\";"        /**< snort rule에서 field의 끝을 나타내는 문자 */ 
#define  SIG_NEND_KEY          ";"          /**< snort rule에서 sid, date, time field의 끝을 나타내는 문자 */ 
#define  HEX_STR_LEN           10           /**< hexa code를 작업하기 위한 중간 버퍼의 길이 */
#define  MAX_CONTENT_LEN       1024         /**< content안에 들어가는 signature의 최대 길이 */ 
#define  MAX_RULE_STR_LEN      2048         /**< 1개의 룰의 최대 bytes수 */
#define  MAX_RULE_NUMBER       1025         /**< 최대 룰 개수  */
#define  FIELD_DELIMITER       ",+; \t\r\n\0"  /**< field delimiter */

#define  PCAP_TIMEOUT          0            /**< default expire seconds, == configure_t.expire_seconds */

#define  CONSOLE_CMD_STOP      "STOP"       /**< 콘솔상에서의 서비스 중지 명령 */
#define  CONSOLE_CMD_START     "START"      /**< 콘솔상에서의 서비스 시작 명령 */
#define  CONSOLE_CMD_UPGRADE   "UPGRADE"    /**< 콘솔상에서의 원격 업그레이드 실행 명령 */

#define  TABLENAME_POLICY_IPS_RULES "policy_ips_rules"     /**< DB접속 정책 테이블명 */
#define  ALERT_DELIMITER       "==="        /**< 필터링 메시지와 alert 메시지를 구분하는 delimter */
#define  HEALTH_CHECK_FILE     "./var/server_agent.health"  /**< 서버 에이전트들의 상태를 기록될 file path */
#define  ALERT_SERVER_UDP_PORT 3119         /**< ips_agent의 UDP 포트 번호, 기존 3119, ACL 3133 */
#define  MAX_SERVICE_COUNT     2048         /**< 서비스 최대 개수 */

#define  AGENT_MANAGER_TIMER   3            /**< 서버에이전트에서 로그를 읽어오기 위한 폴링 시간(10초) */
#define  MAX_RECOVER_COUNT     10           /**< 복구 시도 최대 회수 */

#define  MAX_PCAP_CHECK_COUNT  10           /**< PCAP 인터페이스 할당 재시도 최대 값, 10회 */
#define  MAX_QUARANTINE_TIME   60           /**< 세션 격리 60초 */ 
#define  MAX_BLOCKING_TIME     8            /**< 세션 차단을 위해서 패킷 추적 최대 8개까지 */
#define  IPS_MTU_SIZE          1520         /**< MTU(Maximum Transmission Unit) Size */

// Define 정의 2, Policy action - permit, deny, log.
#define  POLICY_ACTION_DENY              0
#define  POLICY_ACTION_DENY_LOG          POLICY_ACTION_FLAG_LOG
#define  POLICY_ACTION_PERMIT            POLICY_ACTION_FLAG_PERMIT
#define  POLICY_ACTION_PERMIT_LOG        (POLICY_ACTION_FLAG_PERMIT|POLICY_ACTION_FLAG_LOG)
#define  POLICY_ACTION_KILL              POLICY_ACTION_FLAG_KILL
#define  POLICY_ACTION_KILL_LOG          (POLICY_ACTION_FLAG_KILL|POLICY_ACTION_FLAG_LOG)
#define  POLICY_ACTION_QUARANTINE        POLICY_ACTION_FLAG_QUARANTINE
#define  POLICY_ACTION_QUARANTINE_LOG    (POLICY_ACTION_FLAG_QUARANTINE|POLICY_ACTION_FLAG_LOG)
    
// common policy.
#define  POLICY_ACTION_FLAG_LOG          0x01
#define  POLICY_ACTION_FLAG_PERMIT       0x02
#define  POLICY_ACTION_FLAG_KILL         0x40
#define  POLICY_ACTION_FLAG_QUARANTINE   0x100

#define  DEFAULT_DBSCAN_CYCLE_SEC        600


/*---- GLOBAL TYPEDEF/STRUCT/CLASS DECLARATION -------------------------------*/

typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef long long      llong;

/*! \brief
 *   traffic flow
 */
typedef enum
{
    FILTER_FLOW_RIGHT = 0,              /**< sip -> dip type (default) */
    FILTER_FLOW_LEFT,                   /**< sip <- dip type */
    FILTER_FLOW_BOTH,                   /**< sip <-> dip type */
    FILTER_FLOW_UNKNOWN = 0xffff        /**< invalid type */
} filter_flow_e;


/*! \brief
 *   화면 출력 모드 
 */
typedef enum
{
	VIEW_SILENT_MODE = 0,               /**< 화면에 아무것도 출력하지 않는 mode, option: default */
    VIEW_PRINT_MODE,                    /**< packet을 화면에 출력하는 mode, option: -L */
	VIEW_SIMPLE_MODE                    /**< packet을 화면에 출력하되 console(80*24) 크기에 맞게 출력, option: -l */
} view_mode_e;


/*! \brief
 *   탐지룰 필드의 속성 분류
 *  \remark
 *   탐지룰의 각 필드의 속성은 크게 문자열, 숫자, 시간그룹, IP그룹, Port그룹로 나뉜다.
 */
typedef enum
{
    FIELD_TYPE_STRING2 = 0,             /**<  문자열 속성 (default) */
    FIELD_TYPE_NUMBER,                  /**<  숫자 속성 */
    FIELD_TYPE_TIMEGROUP,               /**<  시간 속성 */
    FIELD_TYPE_IPGROUP,                 /**<  IP 주소 속성 */
    FIELD_TYPE_PORTGROUP,               /**<  Port 번호 속성 */
    FIELD_TYPE_UNKNOWN = 0xFFFF
} field_type_e;


typedef enum
{
	WDAY_SUN = 0,
	WDAY_MON,
	WDAY_TUE,
	WDAY_WED,
	WDAY_THU,
	WDAY_FRI,
	WDAY_SAT,
} wday_num_e;

typedef enum
{
	WDAY_SUN_MASK = 1,
	WDAY_MON_MASK = 2,
	WDAY_TUE_MASK = 4,
	WDAY_WED_MASK = 8,
	WDAY_THU_MASK = 16,
	WDAY_FRI_MASK = 32,
	WDAY_SAT_MASK = 64
} wday_mask_e;

typedef enum
{
	INPUT_TYPE_NET = 0,
	INPUT_TYPE_FILE,
	INPUT_TYPE_DB,
	INPUT_TYPE_RESET
} input_type_e;


typedef enum
{
	LOGIC_TYPE_NONE         = 0,
	LOGIC_TYPE_PASS         = 0x00000001,
	LOGIC_TYPE_MANIPULATION = 0x00000002,
	LOGIC_TYPE_BLINDFOLDED  = 0x00000004,
	LOGIC_TYPE_MULTIQUERY   = 0x00000008
} logic_type_e;

typedef struct _rule_list_t rule_list_t;


/*! \brief
 *   Port 번호를 비교하기 위한 구조체
 *  \remark
 *   count 값을 기준으로 단일형 또는 범위형인지 알 수 있다.
 */
typedef struct
{
    unsigned char  count;               /**< count 0이면 정보가 없다는 뜻이고, 0x1은 단일형, 0x2는 범위형 */
    unsigned short port_base;           /**< 기준 port 번호 or FROM port */
    unsigned short port_max;            /**< 범위형을 고려한 최대 port 번호 */
} port_info_t;


/*! \brief
 *   범위형 min과 max를 저장하기 위한 구조체
 *  \remark
 *   저장 형태는 date의 경우 YYYYMMDD의 interger 값이며,
 *   time의 경우 hhmmss의 interger 값으로 한다. 이유는 플랫폼에 따라 시간 처리 부분이 다를 수 있기 때문
 */
typedef struct
{
	unsigned int n_min;                 /**< 최소 값 */
	unsigned int n_max;                 /**< 최소 값 */
} range_int_t;


typedef struct
{
	u_int   type:2;                     /**< '0: do nothing, 1: include, 2:exclude' */
	char    *content;                   /**< 패턴 문자열 */
	char    *unicode;                   /**< 유니코드 패턴일 들어갈 자리 */
	u_short length;                     /**< content의 길이 */
	u_short offset1;                    /**< 0~1500 */
	u_short offset2;                    /**< 0~1500, 단 txt_offset1보다는 같거나 큰 값 */ 
	u_short depth1;                     /**< 0~1500 */
	u_short depth2;                     /**< 0~1500, 단 txt_depth2보다는 같거나 큰 값 */
	u_int   is_nocase;                  /**< 0:대소문자 구분하지 않음, 1:대소문자 구분함 */
	// txt1_nocase` int(1) NOT NULL default '1' COMMENT 'tcp ugt',
} pattern_content_t;

typedef struct
{
	u_int      object_index;
	u_int      group_index;
	u_int      ip;
	u_short    port;
	u_short    type; 
	u_char     is_web;
} ipport_info_t;

typedef struct
{
	u_int      object_index;
	u_int      group_index;
	int        type;     
	u_int      ip_from;
	u_int      ip_to;
	char       mac[18];
} ipgroup_list_t;

typedef struct
{
	u_int  object_index;
	u_int  group_index;
	u_char time_type;                   /**< 0: 기간 안에 매일 시간 따로 검사, 1: 시작일의 시간시간부터 종료일의 종료시간까지 */
	u_char week_mask;                   /**< 0x0: any, 0x01:일, 0x02:월, 0x04:화, 0x08:수, 0x10:목, 0x20:금, 0x40:토 */ 
	u_int  time_begin;                  /**< 시작시간 00:00:00 초 기준으로 누적 초 */
	u_int  time_end;                    /**< 종료시간 00:00:00 초 기준으로 누적 초 */
	u_int  date_begin;                  /**< 시작 일 YYYYMMDD */
	u_int  date_end;                    /**< 종료 일 YYYYMMDD */
} time_info_t;


typedef struct _mts_ports_t 
{
	u_int   ip;
	u_short orignal_port;

	time_t  time_last;
	u_short port;

	struct _mts_ports_t *left;        
	struct _mts_ports_t *right;   
} mts_ports_t;


/*!
 \brief
  통계형 탐지룰을 위해서 존재하는 linked list 
 */
typedef struct _detect_session_t
{
	u_int   key;
	
	u_int   sip;
	u_short sp;
	u_int   dip;
	u_short dp;

	time_t time_first;
	time_t time_last;
	u_int  count;
	u_int  bytes;
	u_int  type;               /**< 서비스 형태, DB, SHELL, FTP */
	u_int  is_web;

	u_int  auth_success; 
	
	struct _detect_session_t *left;        
	struct _detect_session_t *right;   
} detect_session_t;

typedef struct _service_tree_t service_tree_t;
struct _service_tree_t
{
	unsigned int ip;
	ipport_info_t service;
	service_tree_t *left;
	service_tree_t *right;
};

/*!
 \brief
  접속 정책 정보를 저장하는 구조체 
 */
struct _rule_list_t
{
	int    is_skip;              /**< 스케쥴러에 따라 0(동작), 1(무시)로 바뀔 수 있음 */
	long long rule_no;           /**< 정책 번호 */
	char   name[126];            /**< 탐지룰 명 */
	u_int  order;                /**< 우선 순위 */
	u_int  userdefine:1;         /**< 0: 고정룰, 1:사용자 정의 룰 */
	u_int  level:3;              /**< 위험 등급 */
	char comment[255];           /**< 설명 문 */
	u_int  base_sec;             /**< 기준초 */
	u_int  base_count;           /**< 기준 반복 횟수 */

	u_int  length_min;           /**< 패킷의 최소 길이 */
	u_int  length_max;           /**< 패킷의 최대 길이 */
	
	u_int  flag_type:2;          /**, COMMENT 0: do nothing, 1:equal, 2:include */
	u_char flag;                 /** 'tcp flags' */

	pattern_content_t txt[3];    /**< 패턴 3개 정의 */

	u_int sip_count;             /**< sip_list의 개수 */
	ip_info_t *sip_list;         /**< 검사 대상이 되는 Source IP리스트 */
	char servergroup[64];        /**< 서버 그룹 이름 */

	u_int sp_count;              /**< sp_list의 개수 */
	port_info_t *sp_list;        /**< 검사 대상이 되는 Source Port 리스트 */

	unsigned int service_count;  /**< 적용 대상 서비스의 개수, 0: any, 기타: 적용대상 서비스 수 */
	ipport_info_t *service;      /**< 적용 대상 서비스의 IP/Port 정보 */

	u_int ex_sip_count;          /**< 예외 sip_list의 개수 */
	ip_info_t *ex_sip_list;      /**< 예외 검사 대상이 되는 Source IP리스트 */

	u_int ex_sp_count;           /**< 예외 sp_list의 개수 */
	port_info_t *ex_sp_list;     /**< 예외 검사 대상이 되는 Source Port 리스트 */

	u_int ex_oper_type;          /**< 예외 적용 타입, 0: AND조건, 1: OR조건 */

	u_int time_count;            /**< 시간 개체의 개수 */
	time_info_t *time_list;      /**< 시간 정보 */

	u_char action;               /**< 처리 방법, IPS의 기존 action과 동일 */
	u_char log_level;            /**< 로그 등급 */
	u_int  quarantine_time;      /**< 격리 시간 */

	char alert_msg[64];          /**< alert message */

	u_int activate_date;         /**< 룰 시작 일 */
	u_int activate_time;         /**< 룰 시작 시간 */
	u_int expire_date;           /**< 룰 종료 일 */
	u_int expire_time;           /**< 룰 종료 시간 */

	char etc[64];                /**< 기타 Snort룰 관련 표현 필드 */

	detect_session_t *history;   /**< 통계형 탐지룰을 위해서 존재하는 linked list */

	u_int  check_response;       /**< 1:응답만 체크한다. 0:요청만 체크한다. */
	u_int  bytes;                /**< 트래픽의 총 Bytes 량 */
	u_int  comment_count;        /**< 주석의 개수 */

	u_int  logic_type;           /**< 0: 검사전, 1: 정상, 2: 논리오류, 3: 검사회피, 4: 다중라인 */
	u_int  dbms_type;            /**< DBMS 타입 저장 */
	u_int  check_authentication:1;
	u_int  service_detector:1; 

	u_int  exist_where:1; 
	u_int  exist_select:1; 
	u_int  exist_union:1; 

	u_int  is_sql_injection:1; 

	u_int  is_fromdb:1; 
	u_int  min_rows;
	u_int  max_rows;
};


/*!
 \brief
  서비스 리스트 정보를 저장하는 구조체 
 */
typedef struct
{
	unsigned int  no;                 /**< 서비스 번호 */ 
	unsigned int  type;               /**< 서비스 형태, DB, SHELL, FTP */
	char service_ip[MAX_IPADDR_LEN];  /**< 서비스 IP주소 */
	char service_port[MAX_STR_LEN];   /**< 서비스 Port */
} service_list_t;


/*!
 \brief 
  에이전트 정보를 저장하는 구조체
 */
typedef struct
{
	unsigned int  is_live;            /**< 서비스 상태 */

	char service_ip[MAX_IPADDR_LEN];  /**< 서비스 IP주소 */
	char db_port[MAX_STR_LEN];        /**< DB Port */
	char shell_port[MAX_STR_LEN];     /**< Shell Port */
	char ftp_port[MAX_STR_LEN];       /**< FTP Port */

	char alias_crc[CRC_STR_SIZE];     /**< 그룹 정보 file의 CRC */
	char rule_crc[CRC_STR_SIZE];      /**< 접속 정책 file의 CRC */

	char updated_alias_crc[CRC_STR_SIZE];    /**< 이미 배포된 그룹 정보 file의 CRC */
	char updated_rule_crc[CRC_STR_SIZE];     /**< 이미 배포된 접속 정책 file의 CRC */

	int  is_alias_updated;            /**< 그룹 정책의 변경 여부를 기록하는 변수 */
	int  is_access_updated;           /**< 접속 정책의 변경 여부를 기록하는 변수 */
} agent_info_t;


/*!
 \brief
  로그 저장 구조체
 */
typedef struct _log_info_t
{
	unsigned int c_index;
	time_t       c_time;

	long long    policy_no;
	u_short      dbms_type;

	u_int        user_ip;
	u_int        service_no;
	u_int        server_ip;
	u_short      server_port;
	u_short      pkt_length;
	char         pkt_bin[1520];
	struct _log_info_t *next;
} log_info_t;


/*!
 \brief
  그룹정보를 저장하는 구조체
 */
typedef struct 
{
	char name[MAX_STR_LEN];          /**< IP 그룹명 */
	char ip_list[MAX_RULE_STR_LEN];  /**< IP 리스트 정보, 여러개의 IP는 '+'를 사이에 기록 */ 
} ip_alias_conf_t;



//////////////////////////////////////////////////////////////////////////////////////////////

/*---- GLOBAL FUNCTIONS FORWARD DECLARATION ----------------------------------*/


#endif 

