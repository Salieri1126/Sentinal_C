/*
** (C) Copyright 2010. PNP Secure, Inc.
**
** Any part of this source code can not be copied with
** any method without prior written permission from
** the author or authorized person.
**
*/


/*---- FILE DESCRIPTION ------------------------------------------------------*/

/*
 * File ID: $Id$
 */

/*! \file   packet.h
 *  \date   2023/08/23
 *  \note   N/A
 *  \author JST(zalhae@pnpsecure.com)
 *  \brief  net_monitor
 */

#ifndef __PACKET_H__
#define __PACKET_H__


/*---- INCLUDES         ------------------------------------------------------*/

#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef ETH_FRAME_LEN
 #define ETH_ALEN        6       /**< Octets in one ethernet addr   */
 #define ETH_HLEN        14      /**< Total octets in header.   */
 #define ETH_DATA_LEN    1500    /**< Max. octets in payload    */
 #define ETH_FRAME_LEN   1514    /**< Max. octets in frame sans FCS */

/*!
 * \brief 
 * This is an Ethernet frame header.
 */
struct ethhdr
{
	unsigned char   h_dest[ETH_ALEN];   /* destination eth addr */
	unsigned char   h_source[ETH_ALEN]; /* source ether addr    */
	unsigned short  h_proto;        /* packet type ID field */
};
#endif
 

/*---- GLOBAL DEFINES          -----------------------------------------------*/

#define PAGE_SIZE2             50                       /**< page size */

#define IP_HEADER_SIZE         20                       /**< IP header size */
#define TCP_HEADER_SIZE        20                       /**< TCP header size */
#define ARP_HEADER_SIZE        12                       /**< ARP header size */
#define VLAN_HEADER_SIZE       4                        /**< VLAN header size */
#define NEVER_ENDING_MODE      -1                       /**< continuous mode code */
#define IPV4_NUM               4                        /**< IPv4 version */

#define PROMISCUOUS_MODE       1                        /**< promiscuous mode code */

#define ETHERNET_MAX_LEN_ENCAP (ETH_FRAME_LEN+4)        /**< 802.3 (+LLC) or ether II ? */
#define SNAP_LEN               ETHERNET_MAX_LEN_ENCAP   /**< default snap length (maximum bytes per packet to capture) */

#define IP_HLEN(iph)           ((iph)->ip_verhl & 0x0f) /**< header length */
#define IP_VER(iph)            (((iph)->ip_verhl & 0xf0) >> 4)   /**< IP version */

#define L4_OFFSET              (ETH_HLEN+IP_HEADER_SIZE)         /**< MAC+IP header size */

#define GET_VLAN_ID(vh)        ((ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF))       /**< VLAN ID */
#define GET_VLAN_PRIORITY(vh)  ((ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13) /**< VLAN Priority number */


#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20
#define R_RES2         0x40
#define R_RES1         0x80

/*---- GLOBAL TYPEDEF/STRUCT/CLASS DECLARATION -------------------------------*/

/*! \brief
 *   vlan tagging header structure
 */
typedef struct  {
	u_int16_t vth_pri_cfi_vlan;    /**< vlan priority + id */
	u_int16_t vth_proto;           /**< protocol field... */
} sniff_vlan_t;

/*! \brief
 *   arp header structure
 */
typedef struct  {
	u_int16_t ar_hrd;              /**< format of hardware address   */
	u_int16_t ar_pro;              /**< format of protocol address   */
	u_int8_t  ar_hln;              /**< length of hardware address   */
	u_int8_t  ar_pln;              /**< length of protocol address   */
	u_int16_t ar_op;               /**< ARP opcode (command)         */
	u_int8_t arp_sha[6];           /**< sender hardware address */
	u_int8_t arp_spa[4];           /**< sender protocol address */
	u_int8_t arp_tha[6];           /**< target hardware address */
	u_int8_t arp_tpa[4];           /**< target protocol address */
} sniff_arp_t;

/*! \brief
 *   ip header structure
 */
typedef struct  {
	u_int8_t ip_verhl;             /**< version & header length */
	u_int8_t ip_tos;               /**< type of service */
	u_int16_t ip_len;              /**< datagram length */
	u_int16_t ip_id;               /**< identification  */
	u_int16_t ip_off;              /**< fragment offset */

	u_int8_t ip_ttl;               /**< time to live field */
	u_int8_t ip_proto;             /**< datagram protocol */
	u_int16_t ip_csum;             /**< checksum */
	struct in_addr ip_src;         /**< source IP */
	struct in_addr ip_dst;         /**< dest IP */
} sniff_ip_t;

/*! \brief
 *   tcp header structure
 */
typedef struct  {
	u_int16_t th_sport;            /**< source port */
	u_int16_t th_dport;            /**< destination port */
	u_int32_t th_seq;              /**< sequence number */
	u_int32_t th_ack;              /**< acknowledgement number */
	u_int8_t th_offx2;             /**< offset and reserved */
	u_int8_t th_flags;             /**< tcp flags */
	u_int16_t th_win;              /**< window */
	u_int16_t th_sum;              /**< checksum */
	u_int16_t th_urp;              /**< urgent pointer */
} sniff_tcp_t;

/*! \brief
 *   udp header structure
 */
typedef struct  {
	u_int16_t uh_sport;            /**< source port */
	u_int16_t uh_dport;            /**< destination port */
	u_int16_t uh_len;              /**< payload length */
	u_int16_t uh_chk;              /**< udp checksum */
} sniff_udp_t;

/*! \brief
 *   icmp header structure
 */
typedef struct  {
	u_char icmp_type;              /**< type */
	u_char icmp_code;              /**< code */
	u_short icmp_checksum;         /**< checksum */
	u_short icmp_id;               /**< identifier */
	u_short icmp_seq;              /**< sequence number */
} sniff_icmp_t;

/*! \brief
 *   packet decode structure
 */
typedef struct 
{
	struct timeval tv;             /**< time */
	unsigned short caplen;         /**< captured length */

	short vlan_id;                 /**< vlan id */

	unsigned short sp;             /**< source port */
	unsigned short dp;             /**< destination port */
	unsigned int   sip;            /**< source ip */
	unsigned int   dip;            /**< destination ip */

	unsigned short client_port;    /**< source port */
	unsigned short server_port;    /**< destination port */

	unsigned int   client_ip;      /**< source ip */
	unsigned int   server_ip;      /**< destination ip */

	struct ethhdr  *eh;            /**< ethernet header */
	sniff_vlan_t *vh;              /**< vlan header */
	sniff_ip_t   *iph;             /**< ip header */
	sniff_tcp_t  *tcph;            /**< tcp header */

	short reverse_flow;            /**< 0:순방향, 1:역방향, -1: 알수 없음 */
	u_int object_index;            /**< 탐지된 대상 서비스의 순번 */

	unsigned short dsize;          /**< payload의 길이 */
	u_int is_windows:1;            /**< 0:윈도우즈 이외의 플랫폼, 1:원도우즈에서 발생된 패킷 */
	u_int type;                    /**< 서비스 타입이 저장됨 */

	u_int is_logic_type;           /**< 0: 검사전, 1: 일반, 2: logical manipulation, 3: blindfolded, 4: multi-query */

	short exist_where;
	short exist_select;
	short exist_union;

	u_int   comment_count;
	u_int   is_auth_fail:1;        /**< 1: 인증 실패, 0: 기타 */
	u_int   is_web:1;              /**< 1: web 트래픽, 0: 일반 */

	u_char nocase[4096];
	unsigned short nocase_size;    /**< 유니코드와 대소문자가 정리된 저장소의 길이 */
} packet_t;


/*! \brief
 *   tcpdump_header_t 
 *  \remark
 *   default value 
 *   0xa1b2c3d4, 0x2, 0x4, 0, 0, 0, 0xffff, 0x1, 0x0
 */
typedef struct
{
	unsigned int byte_order_magic; /**< magic code (tcpdump) */
	unsigned short major_version;  /**< major version */
	unsigned short minor_version;  /**< minor version */
	unsigned int section_length;   /**< section length */
		
	unsigned short linktype;       /**< link type */
	unsigned short reserved;       /**< reserved filed */
	unsigned int snaplen;          /**< snap length */
		
	unsigned short interface_id;   /**< interface id */
	unsigned short drop_count;     /**< drop_count */

} tcpdump_header_t;

#endif
