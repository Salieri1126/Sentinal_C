/*
** (C) Copyright 2010. PNP Secure, Inc.
**
** Any part of this source code can not be copied with
** any method without prior written permission from
** the author or authorized person.
**
*/

/*---- FILE DESCRIPTION ------------------------------------------------------*/

/*! \file   dbms_ips_manager.h
 *  \date   2010/04/05
 *  \author PHS(pak0302@gmail.com)
 *  \brief  dbms_ips_manager header
 *  \remark
 */

#ifndef __IPS_MANAGER_H
#define __IPS_MANAGER_H


/*---- INCLUDES         ------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <pthread.h>
#include <net/if.h>

#include "config.h"
#include "repository.h"


/*---- GLOBAL DEFINES          -----------------------------------------------*/
#define SERVICE_TYPE_ORACLE                 0x0001u
#define SERVICE_TYPE_FTP                    0x0002u
#define SERVICE_TYPE_TELNET                 0x0004u
#define SERVICE_TYPE_SSH                    0x0008u
#define SERVICE_TYPE_TP                     0x0010u
#define SERVICE_TYPE_BYPASS                 0x0020u
#define SERVICE_TYPE_SYBASE                 0x0080u
#define SERVICE_TYPE_SYBASE_IQ              0x0100u
#define SERVICE_TYPE_MSSQL_2000             0x0200u
#define SERVICE_TYPE_MSSQL_2003             0x0300u
#define SERVICE_TYPE_MSSQL_2005             0x0800u
#define SERVICE_TYPE_INFORMIX               0x0003u
#define SERVICE_TYPE_ALTIBASE               0x0005u
#define SERVICE_TYPE_TERADATA               0x0006u
#define SERVICE_TYPE_UDB                    0x0007u
#define SERVICE_TYPE_MYSQL                  0x0009u
#define SERVICE_TYPE_TIBERO                 0x000Au
#define SERVICE_TYPE_CUBRID                 0x000Bu
#define SERVICE_TYPE_POSTGRESQL             0x000Cu
#define SERVICE_TYPE_CRIS                   0x000Du

        
#define SERVICE_TYPE_BRIDGE_OPT             0x0040u
#define SERVICE_TYPE_SNIFFING_OPT           0x4000u
#define SERVICE_TYPE_PASS_OPT               0x2000u
#define SERVICE_TYPE_STANDALONE_OPT         0x8000u

#define SERVICE_TYPE_MASK_OPT               (SERVICE_TYPE_BRIDGE_OPT|SERVICE_TYPE_SNIFFING_OPT|SERVICE_TYPE_PASS_OPT|SERVICE_TYPE_STANDALONE_OPT)
#define SERVICE_TYPE_MASK_SERVICE           (~(SERVICE_TYPE_BRIDGE_OPT|SERVICE_TYPE_SNIFFING_OPT|SERVICE_TYPE_PASS_OPT|SERVICE_TYPE_STANDALONE_OPT))


/*---- GLOBAL TYPEDEF/STRUCT/CLASS DECLARATION -------------------------------*/

/*!
 \brief
  통신 인터페이스에 대한 정보를 저장하는 구조체
 */
typedef struct _ifinfo 
{ 
    struct sockaddr_in *sin; 
    char ifname[40]; 
    int  fd;     
    struct ifreq *ifr; 
    struct ifconf ifcfg; 
    int  ifnum; 
} ifinfo_t; 


/*----  FUNCTIONS FORWARD DECLARATION ----------------------------------*/

void stop_processor(int sig);

#endif /* __IPS_MANAGER_H */
