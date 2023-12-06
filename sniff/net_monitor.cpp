/*
 * (C) Copyright 2010. PNP Secure, Inc.
 *
 * Any part of this source code can not be copied with
 * any method without prior written permission from
 * the author or authorized person.
 *
 */
 
/*---- FILE DESCRIPTION ------------------------------------------------------*/

/*! 
 * \file   net_monitor.c
 * \date   2010.07.12
 * \note   N/A
 * \author JST(zalhae@pnpsecure.com)
 * \brief  TCP/IP packet sniffer
 * \remark
 *  TODO: ��Ƽ CPUȯ�濡�� �� �����ϵ��� ���� (CPU Channel ���� ����)
 *  ���� �������� ������ ���� ���� �ҽ� ��Ʈ�����Ծ� �ϴ� ��쿡 ���� ó�� 
 */


/*---- INCLUDES		 ------------------------------------------------------*/

#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>

#include "dbms_ips.h"
#include "dbms_ips_manager.h"
#include "policy.h"
#include "util.h"
#include "match.h"
#include "session.h"
#include "log.h"
#include "thread_manage.h"

/**
  \addtogroup  net_monitor
  \{
*/

/*---- GLOBAL DEFINES		  -----------------------------------------------*/
#define MAX_HASH_SIZE        0x0000FFFF


/*---- LOCAL TYPEDEF/STRUCT DECLARATION -------------------------------*/


/*---- GLOBAL VARIABLES ------------------------------------------------------*/
extern configure_t g_conf;             ///< ��ü �ý��� ���� ȯ�� ���� 
extern IpsMatch rules;
extern IpsLog logs;
extern IpsSession sess;

/*---- STATIC VARIABLES ------------------------------------------------------*/

/*---- STATIC FUNCTIONS FORWARD DECLARATION ----------------------------------*/

static void packet_sniff(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
static int  get_ipmac_from_ippkt(const u_char *packet, packet_t *p);
static int  packet_filter(u_char *packet, packet_t *p, int nic_index);
static int is_skip_port(unsigned short port);
static int decode_packet(packet_t *p, int size, const u_char *packet);
static int setFlow(packet_t *p);

/*---- FUNCTIONS		------------------------------------------------------*/

/*! \brief	
 *   BPF_FILTER�κ��� packet�� ������ �� �ִ� device�� ������, packet ó���� �ʿ��� �޸𸮸� �Ҵ��� �ش�.
 *  \param void *arg : ȯ�� ���� ���� ����� ����ü�� �ּҰ� 
 *  \return   ���� ���� 	
 */
void *init_net_monitor(int nic_index)
{
	u_char u_nic_index = 0;

	if ( !g_conf.pd[nic_index] )
		return NULL;

	if ( g_conf.is_debug_mode )
		fprintf(stderr,"%s,%d: net_monitor(%d, %s)-start\n", __func__, __LINE__, nic_index, g_conf.interface_name[nic_index]);

	g_conf.reset_socket[nic_index] = init_resetpacket(g_conf.interface_name[nic_index]);

	/* set callback function */
	u_nic_index = (u_char)nic_index&0xff;
	
	/////////////////////////////////////////////////
	//	Session�� 1�и��� ����ϱ� ���� ������ ����
	pthread_t printSession_thread;

	if( pthread_create( &printSession_thread, NULL, &IpsSession::printSessionWrapper, &sess ) != 0 ){
		printf("printSession thread make fail\n");
		return NULL;
	}
	/////////////////////////////////////////////////
	
	pcap_loop(g_conf.pd[nic_index], NEVER_ENDING_MODE, packet_sniff, (u_char*)&u_nic_index);

	g_conf.is_running = 0;

	if ( g_conf.is_debug_mode )
		fprintf(stderr,"%s,%d: pcap_close() .. net_monitor()\n", __func__, __LINE__);

	/* cleanup */
	pcap_close(g_conf.pd[nic_index]);
	
	return NULL;
} 


/*! \brief
 *   ������ raw packet�� �ؼ��ϴ� ��� 
 *  \param  args : ������� ���� 
 *  \param  header : pcap_pktheader
 *  \param  packet : raw packet pointer
 *  \return none
 */
static void packet_sniff(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int nic_index = 0;
	nic_index = (int)(*args & 0xff);

	if ( !g_conf.is_bypass_mode && g_conf.is_running && header && packet ) 
	{
		packet_t p;

		if ( decode_packet(&p, header->caplen, packet) != ERR_SUCCESS )
			return;
	

		// ���� ���ʿ䰡 ���� ��Ŷ�� �����Ѵ�.
		if ( is_skip_port(p.sp) || is_skip_port(p.dp) )
			return;

		p.dsize = p.caplen - (((p.tcph->th_offx2>>4) + (p.iph->ip_verhl&0x0f))<<2) - 14;

		if ( p.dsize == 0 && p.tcph->th_flags == R_ACK ) 
			return; 

		// Windows �÷������� �߻��� ��Ŷ���� Ȯ��
		if ( p.iph->ip_ttl > 64 && p.iph->ip_ttl < 129 )
			p.is_windows = 1;
		else
			p.is_windows = 0;

		if ( packet_filter((u_char*)packet, &p, nic_index) == ACTION_PASS )
			return;

		/* ȭ�� ��� */
		if ( g_conf.is_print_list )
			print_to_console(&p, packet, g_conf.is_print_console, g_conf.is_print_hexa);
	}
}


/*! \brief
 *   packet decoder
 *  \param  p : decoding data�� ����� ����ü ������
 *  \param  size : packet size
 *  \param  packet : raw packet data
 *  \return int : 0(��ġ���� ����), 1(��ġ��)
 */
static int decode_packet(packet_t *p, int size, const u_char *packet)
{
	/* �̰����� ������ packet decoding�� ���� */
	p->eh   = (struct ethhdr*)(packet);
	p->tcph = NULL;
	p->iph  = NULL;

	if ( ntohs(p->eh->h_proto) == ETH_P_IP )
	{
		if ( get_ipmac_from_ippkt(packet, p) ) 
		{
			p->caplen = size;
			p->vlan_id = -1;
			return ERR_SUCCESS;
		}
		return ERR_UNKNOWN;
	}

	/* VLAN���� encapsulation�� ethernet packet�� �����Ͽ� ���߿��� ARP �� RARP ��Ŷ ó�� */
	if ( ntohs(p->eh->h_proto) == ETH_P_8021Q )
	{
		/* ���������� ũ���� packet�� skip */
		if ( size < (ARP_HEADER_SIZE + ETH_HLEN + VLAN_HEADER_SIZE) ) 
		   	return ERR_UNKNOWN;

		p->vh = (sniff_vlan_t*)(packet + ETH_HLEN);

		if ( ntohs(p->vh->vth_proto) != ETH_P_IP )
		   	return ERR_UNKNOWN;
		
		if ( get_ipmac_from_ippkt(packet+ VLAN_HEADER_SIZE, p) )
		{
			p->caplen = size;
			p->vlan_id = GET_VLAN_ID(p->vh);
			return ERR_SUCCESS;
		}
	}

   	return ERR_UNKNOWN;
}


/*! \brief
 *   get ip/mac/vlan_id from tcp syn packet 
 *  \param packet : raw packet
 *  \param len : length of packet
 *  \param p : decoding data�� ����� ����ü ������
 *  \remark
 *   arp ��Ŷ������ ip/mac/vlan_id�� ������ ��� ��쿡 ���� ������ �������� ���� ��쵵 �����Ƿ�
 *   tcp syn packet������ ������ ���� �Ѵ�. 
 *  \return int:
 *	 0: �ش� ��Ŷ���� ip/mac/vlan_id �������� ���� ��� 
 *	 1: �ش� ��Ŷ���� ip/mac/vlan_id ������ ��� 
 */
static int get_ipmac_from_ippkt(const u_char *packet, packet_t *p)
{
	u_int32_t hlen;   /* ip header length */

	p->iph = (sniff_ip_t*)(packet + ETH_HLEN);

	if ( IP_VER(p->iph) != IPV4_NUM )
		return 0;

	/* set the IP header length */
	hlen = IP_HLEN(p->iph) << 2;
		
	/* header length sanity check */
	if(hlen < IP_HEADER_SIZE)
		return 0;

	if ( p->iph->ip_proto != IPPROTO_TCP )
		return 0;
	
	p->tcph = (sniff_tcp_t*)(packet + ETH_HLEN + hlen);
	p->sp = ntohs(p->tcph->th_sport);
	p->dp = ntohs(p->tcph->th_dport);

	memcpy(&p->sip, &p->iph->ip_src, sizeof(unsigned int));
	memcpy(&p->dip, &p->iph->ip_dst, sizeof(unsigned int));

	// ��κ��� DBMS ��� ��Ʈ�� well-known port �뿪 �̻��̴�.
	// �Ǵ� linux���� ������ ����� ���� ��Ʈ �뿪�� �Ѵ� ��츦 ����
	if ( p->sp < 1024 || p->dp < 1024 )
		return 0;

	return 1;
}


/*! \brief
 *   �˻��� �ʿ䰡 ���� ��Ʈ���� Ȯ���ϴ� �Լ�
 * \param port : TCP ��Ʈ ��ȣ
 * \return 0: �˻� ��Ʈ, 1: ���� ��Ʈ
 */
static int is_skip_port(unsigned short port)
{
	switch (port)
	{
		case 20:
		case 21:
		case 22:
		case 23:
		case 25:
		case 80:
		case 110:
		case 139:
		case 443:
		case 445:
		case 512:
		case 8001:
		case 8080:
		case 3118:
		case 3389:
		case 21113:
			return 1;
	}
	return 0;
}

/*! \brief
 *   ������ filtering ��å�� ���Ͽ� ��Ŷ�� �����ϰų� �α׸� ����ϴ� �Լ�
 *  \param  u_char packet : raw packet data
 *  \param  packet_t* p : �� ���� ��Ŷ ����ü ����
 *  \param  int nic_index : ��Ŷ�� ������ NIC�� ����
 *  \return int : 0 ���, 1 ����, 2 ���, 4 �ݸ�
 */
static int packet_filter(u_char *packet, packet_t *p, int nic_index)
{
	//////////////////////////////////////////////////////
	// flow Ȯ�� �� ����
	if ( setFlow(p) == -1 )
		return ACTION_PASS;

	if ( g_conf.is_debug_mode && p->reverse_flow != -1 )
		fprintf(stderr, "%s,%d: Flow(%d) %x:%d -> %x:%d dsize:%d\n", __func__, __LINE__, p->reverse_flow, p->sip, p->sp, p->dip, p->dp, p->dsize);

	if( sess.checkSession(p) ) 
		return ACTION_PASS;

	int ruleIndex = rules.ruleFilter(p, preBuildData(packet, p->caplen - p->dsize));
	if ( ruleIndex != -1 && p->reverse_flow == 0){
		rule_t match = rules.getRule(ruleIndex);
		printf("(Detect_Name : %s) ", match.deName); 
		logs.insert_log(packet, p, ruleIndex);
		return ACTION_LOG;
	}
	
	return ACTION_PASS;
}

/*
 *! \brief
 *	 ��Ŷ�� ������ �����ϴ� �Լ�
 *	\param packet_t* p : ĸ�� ��Ŷ
 *	\return int : 0 �����Ϸ�, 1 ��������
 *	\detail
 *		������ : DB�� ������ ��Ŷ reverse_flow = 0
 *		������ : DB���� ������ ��Ŷ reverse_flow = 1
 *		DB�� ���þ��� ��Ŷ�� reverse_flow = -1
 */
static int setFlow(packet_t *p){
	
	if (!p)
		return -1;

	u_int dbIp = inet_addr(g_conf.targetIp);
	u_int dbPort = atoi(g_conf.targetPort);

	if( p->sip == dbIp && p->sp == dbPort ){
		p->reverse_flow = 1;
		return 0;
	}

	if( p->dip == dbIp && p->dp == dbPort ){
		p->reverse_flow = 0;
		return 0;
	}

	p->reverse_flow = -1;
	
	return -1;
}

/** \}*/

