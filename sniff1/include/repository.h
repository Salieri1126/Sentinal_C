/*
 * (C) Copyright 2010. PNP Secure, Inc.
 *
 * Any part of this source code can not be copied with
 * any method without prior written permission from
 * the author or authorized person.
 *
 */

/*---- FILE DESCRIPTION ------------------------------------------------------*/

/*! \file   repository.h
 *  \date   2008/09/11
 *  \author JST(zalhae@pnpsecure.com)
 *  \brief  dbms_ips_manager의 공통 정의
 *  \remark
 *   - 
 */

#ifndef __REPOSITORY_H__
#define __REPOSItory_H__

/*---- INCLUDES         ------------------------------------------------------*/

/*---- GLOBAL DEFINES          -----------------------------------------------*/

#define POLICY_LISTENER_PORT   21119                         /**< ips_agent가 정책 변경 여부를 전송하는 TCP&UDP Port */

#define SERVICE_IPS_MANAGER_PID_FILE    "var/" IPS_MANAGER_NAME ".pid"  /**< ips_manager의 PID가 저장된 file */
#define LOG_IPC_SOCK_PATH      IPS_MANAGER_NAME".uds"    /**< ips_policy_manager와 ips_server_agent간의 UDS path */

#define QRY_STATISTICS_PATH    "./log/" IPS_MANAGER_NAME "/qry_statis_%02d.dat"   /**< 쿼리 패턴의 통계 값을 계산한 데이터 파일 */
#define USR_STATISTICS_PATH    "./log/" IPS_MANAGER_NAME "/usr_statis_%02d.dat"   /**< UserID별 쿼리 패턴의 통계 값을 계산한 데이터 파일 */
#define IPS_MANAGER_CONF       IPS_MANAGER_NAME ".conf"        /**< NIC 1개에 여러 개의 IP를 할당한 경우의 리스트 저장 */
#define IPS_PID_PATH           "./var/.ips_manager.run"

#define DEFAULT_FAIL_OPEN_TIME 300                           /**< 비정상 동작시 자동으로 bypass시키는 기준 시간(초) */

/*---- GLOBAL TYPEDEF/STRUCT/CLASS DECLARATION -------------------------------*/

/*---- GLOBAL FUNCTIONS FORWARD DECLARATION ----------------------------------*/

#endif /* __REPOSITORY_H__ */
