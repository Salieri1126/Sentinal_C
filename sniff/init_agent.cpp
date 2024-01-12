/*
 * (C) Copyright 2010. PNP Secure, Inc.
 *
 * Any part of this source code can not be copied with
 * any method without prior written permission from
 * the author or authorized person.
 *
 */

/*---- FILE DESCRIPTION ------------------------------------------------------*/

/*
 * File ID: $Id$
 */

/*! \file   init_agent.c
 *  \date   2010.07.12
 *  \note   N/A
 *  \author PHS(pak0302@gmail.com)
 *  \brief  프로그램 구동에 필요한 메모리 초기화 및 환경 변수 값을 읽어 오기 
 */


/*---- INCLUDES          ------------------------------------------------------*/

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/utsname.h>

#include "init_agent.h"
#include "util.h"
 
/*! 
  \addtogroup  init_agent 
  \{ 
*/

/*---- DEFINES		  ------------------------------------------------*/


/*---- LOCAL TYPEDEF/STRUCT DECLARATION -------------------------------*/


/*---- STATIC VARIABLES -----------------------------------------------*/


/*---- GLOBAL VARIABLES -----------------------------------------------*/


/*---- FUNCTIONS          ------------------------------------------------------*/


#define PCAP_DEFAULT_TIMEOUT 20000

static pcap_t *create_pcap_handler(const char * device, char * errBuf) 
{
    pcap_t *p = pcap_create(device, errBuf);
    if ( p == NULL ) 
        return NULL;

    do {
        int status = pcap_set_snaplen(p, ETH_FRAME_LEN);
        if (status < 0 ) 
            break;

        status = pcap_set_promisc(p, 1);
        if ( status < 0 ) 
            break;

        status = pcap_set_immediate_mode(p, 1);
        if ( status < 0 ) 
            break;

        status = pcap_set_timeout(p, PCAP_DEFAULT_TIMEOUT);
        if ( status < 0 ) 
            break;

        status = pcap_activate(p);
        if ( status < 0 ) 
            break;

        return p;
    } while (false);

    pcap_close(p);
    p = NULL;

    return NULL;
}


/*! 
  \brief 
    프로그램 초기화 
  \param conf 
    동작을 위한 환경 설정 값이 저장될 매개 변수
  \remarks 
    초기화 실패하면 에러 로그를 남기고 프로그램을 종료시킨다. 
  \return 
    - fail : ERR_UNKNOWN, ERR_FREAD, ERR_FORK
    - success : ERR_SUCCESS
*/ 
int init_server_agent (
	configure_t *conf   /**< 동작을 위한 환경 설정 값이 저장될 매개 변수 */
	)
{
	char errbuf[MAX_STR_LEN] = "";
	int ret_num = ERR_UNKNOWN;

	memset(conf->pd, 0, sizeof(conf->pd));

	/* sniff driver 생성 */
	/* pcap_open_live를 child thread에서 수행하면 AIX5.2에서 열리지 않는 문제 때문에 이곳으로 옮겼음 */
#if 1
	conf->pd[0] = create_pcap_handler(conf->interface_name[0], errbuf);
#else
	// RockyLinux 이외의 오래된 OS의 경우는 아래의 코드 필요  
	conf->pd[0] = pcap_open_live(conf->interface_name[0], ETH_FRAME_LEN, 1, 10, errbuf);
#endif
	if ( conf->pd[0] == NULL )
	{
		fprintf(stderr, "pcap_open_live() error %s, NIC=%s\n", errbuf, conf->interface_name[0]);
		return ret_num;
	}

	// 패킷 수집 모듈 호출
	init_net_monitor(0);

	return ERR_SUCCESS;
}


/** \}*/

