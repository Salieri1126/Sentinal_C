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
 *   - ��å ó�� ���� ����ü �� ���� ����
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

#define  MAX_IPADDR_LEN         16          /**< '\0'�� ������ IP�ּ��� �ִ� ���� */
#define  MAX_ARRAY_SIZE         4096        /**< �ִ� �迭 ���� */

/**< ���μ��� ���� �ñ׳� ����ȭ�� ���� �ڵ� */
#define  DO_NOTHING             0x0         /**< �ƹ��͵� ���� ���� ��� */
#define  DO_LOG_LISTENER        0x1         /**< log_listener ó�� �� */
#define  DO_NET_MONITOR         0x2         /**< net_monitor ó�� �� */
#define  DO_MAIN_THREAD         0x4         /**< main_thread ó�� �� */
#define  DO_EXIT                0x8         /**< ���� �ñ׳��� ���� ���� */

/* for session compare */
#define  SESSION_MASK_NONE      0x0000      /**< ���� �˻縦 ���� ����, �ʿ����� ���� */
#define  SESSION_MASK_ALL       0xFFFF      /**< ��� ���� �˻縦 ������, �ʿ����� ���� */
#define  SESSION_MASK_PORT      0x00F0      /**< port �˻縦 �� */
#define  SESSION_MASK_IP        0x0F00      /**< ip �˻縦 �� */
#define  SESSION_MASK_CONTENT   0xF000      /**< ���� �˻縦 �� */
#define  SESSION_MASK_PROTOCOL  0x0001      /**< protocol �� */
#define  SESSION_MASK_SP        0x0010      /**< source port�� �� */
#define  SESSION_MASK_DP        0x0020      /**< destination port�� �� */
#define  SESSION_MASK_SIP       0x0100      /**< source ip �ּ� �� */
#define  SESSION_MASK_DIP       0x0200      /**< destination ip �ּ� �� */

#define  SESSION_MASK_BOTH      0x0400      /**< IP�� ��Ʈ�� ���⼺�� ������� �� */

#define  SESSION_MASK_CONTENT1  0x1000      /**< content ��1 */
#define  SESSION_MASK_CONTENT2  0x2000      /**< content ��2 */

#define  MAX_ALIAS              2048        /**< IP/Port/Time alias�� ũ�� */

#ifndef ETH_P_8021Q
 #define  ETH_P_8021Q           0x8100      /**< VLAN�� ethernet type code */
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

#define  COMPARE_SINGLE         1           /**< IP�� Port�� 1���� �� */
#define  COMPARE_RANGE          2           /**< IP�� Port�� 2���� ���� �� */
#define  COMPARE_SKIP           0           /**< ������ ���� */

#define  IP_ADDRESS_STR_LEN     15          /**< IP�ּ� ���ڿ��� �ִ� ���� */
#define  IP_FULL_MASK           0xFFFFFFFF  /**< 4byte�� IP�ּ� ��ü�� ���� MASK */
#define  IP_SEGMENT_BITS        32          /**< IP�ּ� ��ü BIT�� */

#define  VALUE_STR_ANY         "ANY"        /**< any */
#define  VALUE_STR_any         "any"        /**< any */
#define  VALUE_STR_NOTHING     "NOTHING"    /**< nothing */

#define  ACTION_PASS           0            /**< ��� */
#define  ACTION_DROP           1            /**< ���� */
#define  ACTION_ALERT          2            /**< ��� ó�� == �α� ���� */
#define  ACTION_LOG            ACTION_ALERT /**< �α� ���� */

#define  VALUE_STR_PASS        "pass"        /**< ��� */
#define  VALUE_STR_DROP        "drop"        /**< ���� */
#define  VALUE_STR_LOG         "log"         /**< �α� ���� */
#define  VALUE_STR_ALERT       "alert"       /**< ���ó�� == �α� ���� */
#define  VALUE_STR_QUARANTINE  "quarantine"  /**< �ݸ� */

#define  DEFAULT_INTERFACE     "eth0"        /**< default bridge */

/* for snort rule */
#define  SIG_CONTENT_KEY       "content:\"" /**< snort rule�� content field name */
#define  SIG_MESSAGE_KEY       "msg:\""     /**< snort rule�� message field name */
#define  SIG_SID_KEY           "sid:"       /**< snort rule�� sid field name */
#define  SIG_DATE_KEY          "date:"      /**< date scheduling �� */
#define  SIG_TIME_KEY          "time:"      /**< time scheduling �� */
#define  SIG_END_KEY           "\";"        /**< snort rule���� field�� ���� ��Ÿ���� ���� */ 
#define  SIG_NEND_KEY          ";"          /**< snort rule���� sid, date, time field�� ���� ��Ÿ���� ���� */ 
#define  HEX_STR_LEN           10           /**< hexa code�� �۾��ϱ� ���� �߰� ������ ���� */
#define  MAX_CONTENT_LEN       1024         /**< content�ȿ� ���� signature�� �ִ� ���� */ 
#define  MAX_RULE_STR_LEN      2048         /**< 1���� ���� �ִ� bytes�� */
#define  MAX_RULE_NUMBER       1025         /**< �ִ� �� ����  */
#define  FIELD_DELIMITER       ",+; \t\r\n\0"  /**< field delimiter */

#define  PCAP_TIMEOUT          0            /**< default expire seconds, == configure_t.expire_seconds */

#define  CONSOLE_CMD_STOP      "STOP"       /**< �ֻܼ󿡼��� ���� ���� ��� */
#define  CONSOLE_CMD_START     "START"      /**< �ֻܼ󿡼��� ���� ���� ��� */
#define  CONSOLE_CMD_UPGRADE   "UPGRADE"    /**< �ֻܼ󿡼��� ���� ���׷��̵� ���� ��� */

#define  TABLENAME_POLICY_IPS_RULES "policy_ips_rules"     /**< DB���� ��å ���̺�� */
#define  ALERT_DELIMITER       "==="        /**< ���͸� �޽����� alert �޽����� �����ϴ� delimter */
#define  HEALTH_CHECK_FILE     "./var/server_agent.health"  /**< ���� ������Ʈ���� ���¸� ��ϵ� file path */
#define  ALERT_SERVER_UDP_PORT 3119         /**< ips_agent�� UDP ��Ʈ ��ȣ, ���� 3119, ACL 3133 */
#define  MAX_SERVICE_COUNT     2048         /**< ���� �ִ� ���� */

#define  AGENT_MANAGER_TIMER   3            /**< ����������Ʈ���� �α׸� �о���� ���� ���� �ð�(10��) */
#define  MAX_RECOVER_COUNT     10           /**< ���� �õ� �ִ� ȸ�� */

#define  MAX_PCAP_CHECK_COUNT  10           /**< PCAP �������̽� �Ҵ� ��õ� �ִ� ��, 10ȸ */
#define  MAX_QUARANTINE_TIME   60           /**< ���� �ݸ� 60�� */ 
#define  MAX_BLOCKING_TIME     8            /**< ���� ������ ���ؼ� ��Ŷ ���� �ִ� 8������ */
#define  IPS_MTU_SIZE          1520         /**< MTU(Maximum Transmission Unit) Size */

// Define ���� 2, Policy action - permit, deny, log.
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
 *   ȭ�� ��� ��� 
 */
typedef enum
{
	VIEW_SILENT_MODE = 0,               /**< ȭ�鿡 �ƹ��͵� ������� �ʴ� mode, option: default */
    VIEW_PRINT_MODE,                    /**< packet�� ȭ�鿡 ����ϴ� mode, option: -L */
	VIEW_SIMPLE_MODE                    /**< packet�� ȭ�鿡 ����ϵ� console(80*24) ũ�⿡ �°� ���, option: -l */
} view_mode_e;


/*! \brief
 *   Ž���� �ʵ��� �Ӽ� �з�
 *  \remark
 *   Ž������ �� �ʵ��� �Ӽ��� ũ�� ���ڿ�, ����, �ð��׷�, IP�׷�, Port�׷�� ������.
 */
typedef enum
{
    FIELD_TYPE_STRING2 = 0,             /**<  ���ڿ� �Ӽ� (default) */
    FIELD_TYPE_NUMBER,                  /**<  ���� �Ӽ� */
    FIELD_TYPE_TIMEGROUP,               /**<  �ð� �Ӽ� */
    FIELD_TYPE_IPGROUP,                 /**<  IP �ּ� �Ӽ� */
    FIELD_TYPE_PORTGROUP,               /**<  Port ��ȣ �Ӽ� */
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
 *   Port ��ȣ�� ���ϱ� ���� ����ü
 *  \remark
 *   count ���� �������� ������ �Ǵ� ���������� �� �� �ִ�.
 */
typedef struct
{
    unsigned char  count;               /**< count 0�̸� ������ ���ٴ� ���̰�, 0x1�� ������, 0x2�� ������ */
    unsigned short port_base;           /**< ���� port ��ȣ or FROM port */
    unsigned short port_max;            /**< �������� ����� �ִ� port ��ȣ */
} port_info_t;


/*! \brief
 *   ������ min�� max�� �����ϱ� ���� ����ü
 *  \remark
 *   ���� ���´� date�� ��� YYYYMMDD�� interger ���̸�,
 *   time�� ��� hhmmss�� interger ������ �Ѵ�. ������ �÷����� ���� �ð� ó�� �κ��� �ٸ� �� �ֱ� ����
 */
typedef struct
{
	unsigned int n_min;                 /**< �ּ� �� */
	unsigned int n_max;                 /**< �ּ� �� */
} range_int_t;


typedef struct
{
	u_int   type:2;                     /**< '0: do nothing, 1: include, 2:exclude' */
	char    *content;                   /**< ���� ���ڿ� */
	char    *unicode;                   /**< �����ڵ� ������ �� �ڸ� */
	u_short length;                     /**< content�� ���� */
	u_short offset1;                    /**< 0~1500 */
	u_short offset2;                    /**< 0~1500, �� txt_offset1���ٴ� ���ų� ū �� */ 
	u_short depth1;                     /**< 0~1500 */
	u_short depth2;                     /**< 0~1500, �� txt_depth2���ٴ� ���ų� ū �� */
	u_int   is_nocase;                  /**< 0:��ҹ��� �������� ����, 1:��ҹ��� ������ */
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
	u_char time_type;                   /**< 0: �Ⱓ �ȿ� ���� �ð� ���� �˻�, 1: �������� �ð��ð����� �������� ����ð����� */
	u_char week_mask;                   /**< 0x0: any, 0x01:��, 0x02:��, 0x04:ȭ, 0x08:��, 0x10:��, 0x20:��, 0x40:�� */ 
	u_int  time_begin;                  /**< ���۽ð� 00:00:00 �� �������� ���� �� */
	u_int  time_end;                    /**< ����ð� 00:00:00 �� �������� ���� �� */
	u_int  date_begin;                  /**< ���� �� YYYYMMDD */
	u_int  date_end;                    /**< ���� �� YYYYMMDD */
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
  ����� Ž������ ���ؼ� �����ϴ� linked list 
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
	u_int  type;               /**< ���� ����, DB, SHELL, FTP */
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
  ���� ��å ������ �����ϴ� ����ü 
 */
struct _rule_list_t
{
	int    is_skip;              /**< �����췯�� ���� 0(����), 1(����)�� �ٲ� �� ���� */
	long long rule_no;           /**< ��å ��ȣ */
	char   name[126];            /**< Ž���� �� */
	u_int  order;                /**< �켱 ���� */
	u_int  userdefine:1;         /**< 0: ������, 1:����� ���� �� */
	u_int  level:3;              /**< ���� ��� */
	char comment[255];           /**< ���� �� */
	u_int  base_sec;             /**< ������ */
	u_int  base_count;           /**< ���� �ݺ� Ƚ�� */

	u_int  length_min;           /**< ��Ŷ�� �ּ� ���� */
	u_int  length_max;           /**< ��Ŷ�� �ִ� ���� */
	
	u_int  flag_type:2;          /**, COMMENT 0: do nothing, 1:equal, 2:include */
	u_char flag;                 /** 'tcp flags' */

	pattern_content_t txt[3];    /**< ���� 3�� ���� */

	u_int sip_count;             /**< sip_list�� ���� */
	ip_info_t *sip_list;         /**< �˻� ����� �Ǵ� Source IP����Ʈ */
	char servergroup[64];        /**< ���� �׷� �̸� */

	u_int sp_count;              /**< sp_list�� ���� */
	port_info_t *sp_list;        /**< �˻� ����� �Ǵ� Source Port ����Ʈ */

	unsigned int service_count;  /**< ���� ��� ������ ����, 0: any, ��Ÿ: ������ ���� �� */
	ipport_info_t *service;      /**< ���� ��� ������ IP/Port ���� */

	u_int ex_sip_count;          /**< ���� sip_list�� ���� */
	ip_info_t *ex_sip_list;      /**< ���� �˻� ����� �Ǵ� Source IP����Ʈ */

	u_int ex_sp_count;           /**< ���� sp_list�� ���� */
	port_info_t *ex_sp_list;     /**< ���� �˻� ����� �Ǵ� Source Port ����Ʈ */

	u_int ex_oper_type;          /**< ���� ���� Ÿ��, 0: AND����, 1: OR���� */

	u_int time_count;            /**< �ð� ��ü�� ���� */
	time_info_t *time_list;      /**< �ð� ���� */

	u_char action;               /**< ó�� ���, IPS�� ���� action�� ���� */
	u_char log_level;            /**< �α� ��� */
	u_int  quarantine_time;      /**< �ݸ� �ð� */

	char alert_msg[64];          /**< alert message */

	u_int activate_date;         /**< �� ���� �� */
	u_int activate_time;         /**< �� ���� �ð� */
	u_int expire_date;           /**< �� ���� �� */
	u_int expire_time;           /**< �� ���� �ð� */

	char etc[64];                /**< ��Ÿ Snort�� ���� ǥ�� �ʵ� */

	detect_session_t *history;   /**< ����� Ž������ ���ؼ� �����ϴ� linked list */

	u_int  check_response;       /**< 1:���丸 üũ�Ѵ�. 0:��û�� üũ�Ѵ�. */
	u_int  bytes;                /**< Ʈ������ �� Bytes �� */
	u_int  comment_count;        /**< �ּ��� ���� */

	u_int  logic_type;           /**< 0: �˻���, 1: ����, 2: ������, 3: �˻�ȸ��, 4: ���߶��� */
	u_int  dbms_type;            /**< DBMS Ÿ�� ���� */
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
  ���� ����Ʈ ������ �����ϴ� ����ü 
 */
typedef struct
{
	unsigned int  no;                 /**< ���� ��ȣ */ 
	unsigned int  type;               /**< ���� ����, DB, SHELL, FTP */
	char service_ip[MAX_IPADDR_LEN];  /**< ���� IP�ּ� */
	char service_port[MAX_STR_LEN];   /**< ���� Port */
} service_list_t;


/*!
 \brief 
  ������Ʈ ������ �����ϴ� ����ü
 */
typedef struct
{
	unsigned int  is_live;            /**< ���� ���� */

	char service_ip[MAX_IPADDR_LEN];  /**< ���� IP�ּ� */
	char db_port[MAX_STR_LEN];        /**< DB Port */
	char shell_port[MAX_STR_LEN];     /**< Shell Port */
	char ftp_port[MAX_STR_LEN];       /**< FTP Port */

	char alias_crc[CRC_STR_SIZE];     /**< �׷� ���� file�� CRC */
	char rule_crc[CRC_STR_SIZE];      /**< ���� ��å file�� CRC */

	char updated_alias_crc[CRC_STR_SIZE];    /**< �̹� ������ �׷� ���� file�� CRC */
	char updated_rule_crc[CRC_STR_SIZE];     /**< �̹� ������ ���� ��å file�� CRC */

	int  is_alias_updated;            /**< �׷� ��å�� ���� ���θ� ����ϴ� ���� */
	int  is_access_updated;           /**< ���� ��å�� ���� ���θ� ����ϴ� ���� */
} agent_info_t;


/*!
 \brief
  �α� ���� ����ü
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
  �׷������� �����ϴ� ����ü
 */
typedef struct 
{
	char name[MAX_STR_LEN];          /**< IP �׷�� */
	char ip_list[MAX_RULE_STR_LEN];  /**< IP ����Ʈ ����, �������� IP�� '+'�� ���̿� ��� */ 
} ip_alias_conf_t;



//////////////////////////////////////////////////////////////////////////////////////////////

/*---- GLOBAL FUNCTIONS FORWARD DECLARATION ----------------------------------*/


#endif 

