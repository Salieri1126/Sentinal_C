/*
** (C) Copyright 2010. PNP Secure, Inc.
**
** Any part of this source code can not be copied with
** any method without prior written permission from
** the author or authorized person.
**
*/

/*---- FILE DESCRIPTION ------------------------------------------------------*/

/*! \file   dbms_ips.h
 *  \date   2010/03/12
 *  \note   N/A
 *  \author PHS(pak0302@gmail.com)
 *  \brief  dbms_ips 1.0
 *  \remark
 *   - packet sniffer
 *   - raw packet�� tcpdump�� tcpreplay�� ȣȯ�Ǵ� �������� ����
 *   - UI���� �ǽð����� dump�� ������ �� �� �ִ� ���� ���� ����
 */

#ifndef __DBMS_IPS_H_
#define __DBMS_IPS_H_


/*---- INCLUDES         ------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <pcap.h>

#include "version.h"
#include "getdbinfo.h"


/*---- GLOBAL DEFINES          -----------------------------------------------*/

#define MAX_INTERFACE_NUM      32           /**< �������� �������̽��� �ִ� ���� */
#define MAX_STR_LEN            255          /**< ��Ÿ �۾��� ���ڿ��� �ִ� ���� */

/*---- GLOBAL TYPEDEF/STRUCT/CLASS DECLARATION -------------------------------*/

/*! \brief
 *   ���α׷� ���ۿ� �ʿ��� ȯ�� ���� ���� ����Ǵ� buffer
 */
typedef struct
{
	int  ips_version;                      /**< IPS ���� ���� */
	pcap_t *pd[MAX_INTERFACE_NUM];         /**< sniffing �ϱ� ���� pcap_t ����Ʈ */
	time_t current_datetime;               /**< ���� �ð� (��) */

	int  manager_port;                     /**< ��å ������ ���� ��Ʈ : default(21113) */
	int  bind_address;                     /**< binding IP Address, : default(INADDR_ANY) */

	int  is_running;                       /**< 0: ����, 1:������ */
	int  is_write_mode;                    /**< Ž���� ��Ŷ�� ���Ϸ� ������ ������ ���� 1 or 0 */
	int  is_both_mode;                     /**< ���͸��� ������� �ϴ� �ɼ� */
	int  is_print_list;                    /**< Ž���� ��Ŷ�� ����Ʈ�� �ܼ� ȭ�鿡 ����ϴ� mode ���� */
	int  is_print_console;                 /**< Ž���� ��Ŷ�� ����Ʈ�� �ܼ� ȭ��ũ�⿡ ���� ����ϴ� mode ���� */
	int  is_print_hexa;                    /**< Ž���� ��Ŷ�� HEXA code�� �ܼ� ȭ�鿡 ����ϴ� mode ���� */
	int  is_ids_mode;                      /**< ħ��Ž����� */
	int  is_debug_mode;                    /**< �ý����� �̺�Ʈ�� ȭ�鿡 ����ϴ� ��� */
	int  is_safety_mode;                   /**< ���� ��� ���� ����, �̹� ���ӵǾ� �ִ� ������ ������Ű�� ��� */
	int  is_bypass_mode;                   /**< set Bypass mode */  
	int  is_log_mode;                      /**< debugging�� ���� log��� ��� */
	int  is_service_detector_mode;         /**< 0: ������� ����, 1: ���� �ڵ� ����, 2: ���� �ڵ� ����+��� */
	int  is_service_detector_type;         /**< Ư�� ���� Ÿ�Ը� ������ �� ���� */
	char language_type;                    /**< ��� ���� */

	int  check_authen_index;               /**< ���� ���� �˻� ���� ��ġ */

	int  input_type;                       /**< 0: network, 1: ����, 2: DB */
	int  is_run_dblog;                     /**< DB Scan ����� ips_log DB�� �� ���ΰ� 0: ȭ�� ���, 1: ips_log_xx�� ��� */

	int  fail_open_time;                   /**< IPS ��ֽ� fail-open ���� �ð�(��) */

	char conf_file_name[MAX_STR_LEN];      /**< server_agent ������ ���� ȯ�� �������� ����� file�� ���*/
	char dump_file_name[MAX_STR_LEN];      /**< Ž���� ��Ŷ���� ����� ��� */
	char dump_file_info[MAX_STR_LEN];      /**< Ž���� ��Ŷ�� ��� ������ ����� ��� */
	char rule_file_name[MAX_STR_LEN];      /**< ���͸� �� file path */
	char alias_file_name[MAX_STR_LEN];     /**< alias(group) ���� file path */

	int  ids_on;                           /**< IDS On/Off */

	char alias_crc[64];                    /**< alias.conf�� CRC�� ���� */
	char rule_crc[64];                     /**< access.rule�� CRC�� ���� */

	char platform_os[32];                  /**< ��ġ�� OS ���� */
	char platform_ver[32];                 /**< ��ġ�� OS�� ���� ���� */

	CONFIGURE_SET2_T dbinfo;               /**< MySQL ���� ���� */
	int  interface_count;                  /**< ������ �����̽��� ���� */
	char interface_name[MAX_INTERFACE_NUM][MAX_STR_LEN];      /**< ��Ŷ�� ������ �������̽� �̸�, �������̽��� 32������ ���� ���� */
	int  reset_socket[MAX_INTERFACE_NUM];  /**< ��Ŷ�� ������ �������̽� �̸�, �������̽��� 32������ ���� ���� */

	u_int service_ip;                      /**< �ڱ� �ڽ��� IP�ּ�, service_ip.conf���� �о� �� */
	unsigned int  dbscan_cycle;            /**< �ֱ������� DB LOG�� ����� �����͸� ��ĵ�� �������� �����ϴ� �ɼ� */

	pthread_mutex_t sync_mutex;            /**< �� ������Ʈ�� Ž�������� �������� �ʵ��� �ϱ����� mutex */

	char targetIp[15];
	char targetPort[6];

	int is_writing_log;
} configure_t;


/*---- GLOBAL FUNCTIONS FORWARD DECLARATION ----------------------------------*/

void *init_net_monitor(int nic_index);        /**< traffic ������ ���� thread */
void exit_prog(int sig);                   /**< ���α׷� ���� �Լ� */

#endif 

