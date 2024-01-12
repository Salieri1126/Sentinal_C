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
 *  \brief  ���α׷� ������ �ʿ��� �޸� �ʱ�ȭ �� ȯ�� ���� ���� �о� ���� 
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
    ���α׷� �ʱ�ȭ 
  \param conf 
    ������ ���� ȯ�� ���� ���� ����� �Ű� ����
  \remarks 
    �ʱ�ȭ �����ϸ� ���� �α׸� ����� ���α׷��� �����Ų��. 
  \return 
    - fail : ERR_UNKNOWN, ERR_FREAD, ERR_FORK
    - success : ERR_SUCCESS
*/ 
int init_server_agent (
	configure_t *conf   /**< ������ ���� ȯ�� ���� ���� ����� �Ű� ���� */
	)
{
	char errbuf[MAX_STR_LEN] = "";
	int ret_num = ERR_UNKNOWN;

	memset(conf->pd, 0, sizeof(conf->pd));

	/* sniff driver ���� */
	/* pcap_open_live�� child thread���� �����ϸ� AIX5.2���� ������ �ʴ� ���� ������ �̰����� �Ű��� */
#if 1
	conf->pd[0] = create_pcap_handler(conf->interface_name[0], errbuf);
#else
	// RockyLinux �̿��� ������ OS�� ���� �Ʒ��� �ڵ� �ʿ�  
	conf->pd[0] = pcap_open_live(conf->interface_name[0], ETH_FRAME_LEN, 1, 10, errbuf);
#endif
	if ( conf->pd[0] == NULL )
	{
		fprintf(stderr, "pcap_open_live() error %s, NIC=%s\n", errbuf, conf->interface_name[0]);
		return ret_num;
	}

	// ��Ŷ ���� ��� ȣ��
	init_net_monitor(0);

	return ERR_SUCCESS;
}


/** \}*/

