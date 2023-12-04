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
 *  \brief  dbms_ips_manager�� ���� ����
 *  \remark
 *   - 
 */

#ifndef __REPOSITORY_H__
#define __REPOSItory_H__

/*---- INCLUDES         ------------------------------------------------------*/

/*---- GLOBAL DEFINES          -----------------------------------------------*/

#define POLICY_LISTENER_PORT   21119                         /**< ips_agent�� ��å ���� ���θ� �����ϴ� TCP&UDP Port */

#define SERVICE_IPS_MANAGER_PID_FILE    "var/" IPS_MANAGER_NAME ".pid"  /**< ips_manager�� PID�� ����� file */
#define LOG_IPC_SOCK_PATH      IPS_MANAGER_NAME".uds"    /**< ips_policy_manager�� ips_server_agent���� UDS path */

#define QRY_STATISTICS_PATH    "./log/" IPS_MANAGER_NAME "/qry_statis_%02d.dat"   /**< ���� ������ ��� ���� ����� ������ ���� */
#define USR_STATISTICS_PATH    "./log/" IPS_MANAGER_NAME "/usr_statis_%02d.dat"   /**< UserID�� ���� ������ ��� ���� ����� ������ ���� */
#define IPS_MANAGER_CONF       IPS_MANAGER_NAME ".conf"        /**< NIC 1���� ���� ���� IP�� �Ҵ��� ����� ����Ʈ ���� */
#define IPS_PID_PATH           "./var/.ips_manager.run"

#define DEFAULT_FAIL_OPEN_TIME 300                           /**< ������ ���۽� �ڵ����� bypass��Ű�� ���� �ð�(��) */

/*---- GLOBAL TYPEDEF/STRUCT/CLASS DECLARATION -------------------------------*/

/*---- GLOBAL FUNCTIONS FORWARD DECLARATION ----------------------------------*/

#endif /* __REPOSITORY_H__ */
