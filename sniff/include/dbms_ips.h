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
 *   - raw packet을 tcpdump나 tcpreplay와 호환되는 형식으로 저장
 *   - UI에서 실시간으로 dump된 내용을 볼 수 있는 파일 구조 제공
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

#define MAX_INTERFACE_NUM      32           /**< 스니핑할 인터페이스의 최대 개수 */
#define MAX_STR_LEN            255          /**< 기타 작업용 문자열의 최대 길이 */

/*---- GLOBAL TYPEDEF/STRUCT/CLASS DECLARATION -------------------------------*/

/*! \brief
 *   프로그램 동작에 필요한 환경 설정 값이 저장되는 buffer
 */
typedef struct
{
	int  ips_version;                      /**< IPS 버전 정보 */
	pcap_t *pd[MAX_INTERFACE_NUM];         /**< sniffing 하기 위한 pcap_t 리스트 */
	time_t current_datetime;               /**< 현재 시간 (초) */

	int  manager_port;                     /**< 정책 연동연 관리 포트 : default(21113) */
	int  bind_address;                     /**< binding IP Address, : default(INADDR_ANY) */

	int  is_running;                       /**< 0: 멈춤, 1:동작중 */
	int  is_write_mode;                    /**< 탐지된 패킷을 파일로 저장할 것인지 여부 1 or 0 */
	int  is_both_mode;                     /**< 필터링을 양방으로 하는 옵션 */
	int  is_print_list;                    /**< 탐지된 패킷의 리스트를 콘솔 화면에 출력하는 mode 지정 */
	int  is_print_console;                 /**< 탐지된 패킷의 리스트를 콘솔 화면크기에 맞춰 출력하는 mode 지정 */
	int  is_print_hexa;                    /**< 탐지된 패킷의 HEXA code를 콘솔 화면에 출력하는 mode 지정 */
	int  is_ids_mode;                      /**< 침입탐지모드 */
	int  is_debug_mode;                    /**< 시스템의 이벤트를 화면에 출력하는 모드 */
	int  is_safety_mode;                   /**< 안전 모드 동작 여부, 이미 접속되어 있는 세션을 유지시키는 방식 */
	int  is_bypass_mode;                   /**< set Bypass mode */  
	int  is_log_mode;                      /**< debugging을 위한 log기록 모드 */
	int  is_service_detector_mode;         /**< 0: 사용하지 않음, 1: 서비스 자동 검출, 2: 서비스 자동 검출+등록 */
	int  is_service_detector_type;         /**< 특정 서비스 타입만 지정할 수 있음 */
	char language_type;                    /**< 언어 선택 */

	int  check_authen_index;               /**< 접속 실패 검사 룰의 위치 */

	int  input_type;                       /**< 0: network, 1: 파일, 2: DB */
	int  is_run_dblog;                     /**< DB Scan 결과를 ips_log DB에 쓸 것인가 0: 화면 출력, 1: ips_log_xx에 기록 */

	int  fail_open_time;                   /**< IPS 장애시 fail-open 동작 시간(초) */

	char conf_file_name[MAX_STR_LEN];      /**< server_agent 동작을 위한 환설 설정값이 저장된 file의 경로*/
	char dump_file_name[MAX_STR_LEN];      /**< 탐지된 패킷들이 저장될 경로 */
	char dump_file_info[MAX_STR_LEN];      /**< 탐지된 패킷의 요약 정보가 저장될 경로 */
	char rule_file_name[MAX_STR_LEN];      /**< 필터링 룰 file path */
	char alias_file_name[MAX_STR_LEN];     /**< alias(group) 정의 file path */

	int  ids_on;                           /**< IDS On/Off */

	char alias_crc[64];                    /**< alias.conf의 CRC값 저장 */
	char rule_crc[64];                     /**< access.rule의 CRC값 저장 */

	char platform_os[32];                  /**< 설치된 OS 종류 */
	char platform_ver[32];                 /**< 설치된 OS의 세부 버전 */

	CONFIGURE_SET2_T dbinfo;               /**< MySQL 접속 정보 */
	int  interface_count;                  /**< 스니핑 인퍼이스의 개수 */
	char interface_name[MAX_INTERFACE_NUM][MAX_STR_LEN];      /**< 패킷을 수집할 인터페이스 이름, 인터페이스는 32개까지 지정 가능 */
	int  reset_socket[MAX_INTERFACE_NUM];  /**< 패킷을 수집할 인터페이스 이름, 인터페이스는 32개까지 지정 가능 */

	u_int service_ip;                      /**< 자기 자신의 IP주소, service_ip.conf에서 읽어 옴 */
	unsigned int  dbscan_cycle;            /**< 주기적으로 DB LOG에 저장된 데이터를 스캔할 것인지를 결정하는 옵션 */

	pthread_mutex_t sync_mutex;            /**< 룰 업데이트시 탐지엔진이 동작하지 않도록 하기위한 mutex */

	char targetIp[15];
	char targetPort[6];

	int is_writing_log;
} configure_t;


/*---- GLOBAL FUNCTIONS FORWARD DECLARATION ----------------------------------*/

void *init_net_monitor(int nic_index);        /**< traffic 수집을 위한 thread */
void exit_prog(int sig);                   /**< 프로그램 종료 함수 */

#endif 

