/*
** (C) Copyright 2010. PNP Secure, Inc.
**
** Any part of this source code can not be copied with
** any method without prior written permission from
** the author or authorized person.
**
*/

/*---- FILE DESCRIPTION ---------------------------------------------*/

/**
 * @file util.c
 * @author PHS(pak0302@gmail.com)
 * @brief �÷����� ������� �����ϵ��� �����ϱ� ���� ���� �Լ� ����
 * @remark
 *  �ֿ� �Լ�:  getopt_long(), send_reset(), get_dump_conf()
 */

/*---- INCLUDES		 -------------------------------------------------*/

#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <errno.h>

#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "config.h"
#include "dbms_ips.h"
#include "util.h"
#include "policy.h"


/*---- DEFINES		  ------------------------------------------------*/

/*---- LOCAL TYPEDEF/STRUCT DECLARATION ------------------------------*/

/*---- GLOBAL VARIABLES ----------------------------------------------*/

const char *g_license_string = "(c)2010 PNPSecure Corporation, 4b120-088-4825934-61611";


/*---- STATIC FUNCTIONS FORWARD DECLARATION --------------------------*/

static unsigned short in_cksum(u_short *addr, int len);
static int parse_alias(char *str_value, void *alias_list, int type, char *conf_file_name);


/*---- FUNCTIONS -----------------------------------------------------*/

/*! 
 * \brief
 *  display version
 * \param progname ���� ���α׷��� �̸�
 */
void display_version(char *progname)
{
	char *name = strchr(progname, '/');
	if ( name )
		name++;
	else
		name = progname;
	fprintf(stderr, "* Version: %s-%s\n", name, VERSION );
}


/*!
 \brief
  ��Ŷ ���� �Լ�
 \param int raw_sock: ��Ŷ�� ������ ���� FD
 \param u_char* packet: raw ��Ŷ ������ 
 \param packet_t *p: �ؼ��� ��Ŷ ����ü�� ������
 \param int is_pypass_mode: �����н� ����
 \return 0:����, ��Ÿ:����
 */
int send_reset(int raw_sock, const u_char *packet, const packet_t *p, int is_bypass_mode)
{
	static unsigned char packet_tmp[sizeof(sniff_ip_t)+sizeof(sniff_tcp_t)];
	struct sockaddr_in target_addr;
	
	char flags;
	
	sniff_ip_t *ip = (sniff_ip_t *)packet_tmp;
	sniff_tcp_t *tcp = (sniff_tcp_t *)(packet_tmp+sizeof(sniff_ip_t));
	pseudohdr_t *pseudo = (pseudohdr_t *)(packet_tmp+sizeof(sniff_ip_t)-sizeof(pseudohdr_t));
	
	if ( p->caplen < (IP_HEADER_LEN + TCP_HEADER_LEN + sizeof(struct ethhdr)) || NULL == p->tcph )
		return ERR_UNKNOWN;
	
	flags = p->tcph->th_flags;
	if ( (flags & R_RST) || (flags & R_FIN) )
		return ERR_UNKNOWN;
	
	memset(packet_tmp,0, sizeof(packet_tmp));
	
	/* The data is in place, all headers are zeroed. */
	pseudo->saddr = p->iph->ip_src.s_addr;
	pseudo->daddr = p->iph->ip_dst.s_addr;
	pseudo->protocol = IPPROTO_TCP;
	pseudo->tcplength = htons(sizeof(sniff_tcp_t));
	
	/* The TCP pseudo-header was created. */
	tcp->th_sport = p->tcph->th_sport;
	tcp->th_dport = p->tcph->th_dport;
	tcp->th_offx2 = 0x50; /* 20 bytes, (no options) */
	tcp->th_flags = R_RST;
	/* �ӽ� tcp->th_seq = p->tcph->th_seq; */
	tcp->th_seq = htonl(ntohl(p->tcph->th_seq)+sizeof(struct ethhdr) + sizeof(sniff_ip_t) + sizeof(sniff_tcp_t));
	tcp->th_ack = p->tcph->th_ack;
	tcp->th_win = htons(65535); /*p->tcph->th_win */;
	
	/* The necessary TCP header fields are set. */
	tcp->th_sum = in_cksum((u_short*)pseudo, sizeof(pseudohdr_t)+sizeof(sniff_tcp_t));
	
	memset(packet_tmp, 0, sizeof(sniff_ip_t));
	/* The pseudo-header is wiped to clear the IP header fields */
	
	ip->ip_src.s_addr = p->iph->ip_src.s_addr;
	ip->ip_dst.s_addr = p->iph->ip_dst.s_addr;
	ip->ip_verhl = 0x45;
	ip->ip_ttl = 64;
	/*�ӽ�ip->ip_id = random()%1996;// htons(ntohs(p->iph->ip_id)+1); */
	ip->ip_id = htons(ntohs(p->iph->ip_id)+1);
	ip->ip_proto = IPPROTO_TCP; /* should be 6 */
	ip->ip_len = htons(sizeof(sniff_ip_t) + sizeof(sniff_tcp_t));
	ip->ip_csum = in_cksum((u_short*)packet_tmp, sizeof(sniff_ip_t));
	
	target_addr.sin_family = AF_INET;
	target_addr.sin_addr.s_addr = p->iph->ip_dst.s_addr;
	target_addr.sin_port = tcp->th_dport;

	if ( is_bypass_mode )
		return ERR_SUCCESS;
	
	if ( sendto(raw_sock,(void*)packet_tmp, sizeof(packet_tmp),0,(struct sockaddr *)&target_addr, (size_t)sizeof(struct sockaddr)) < 1 )
		return ERR_UNKNOWN;

	return ERR_SUCCESS;
}
	

/*! \brief
 *   ���ڿ��� ��� �ִ��� ���θ� Ȯ���ϴ� �Լ�
 *  \param  str : �˻� ����� �Ǵ� ���ڿ� ����
 *  \return int : 1�̸� ����ְų�, NULL�� ���, 0�� ���ڿ��� �ִ� ���
 */
int is_empty_string(const char *str)
{
    if ( NULL == str )
        return 1;
    if ( '\0' == str[0] )
        return 1;
#ifdef __x86_64__
    if ( 0xFFFFFFFFFFFFFFFF == (unsigned long long)str )
        return 1;
    if ( 0xCCCCCCCCCCCCCCCC == (unsigned long long)str )
        return 1;
#else
    if ( 0xFFFFFFFF == (unsigned int)str )
        return 1;
    if ( 0xCCCCCCCC == (unsigned int)str )
        return 1;
#endif
    return 0;
}


/*! \brief
 *   Linux�� GNU utility�� getopt_long�� �⺻ ����� �����ϴ� �Լ�
 *   ���� ����� �Է� �Ű� ������ �������� ���� ������� ó�����ִ� �Լ�
 *  \param  argc : �Է� �Ű� ������ ����
 *  \param  argv : �Է� �Ű� ���� ����Ʈ�� ����� ���ڿ� �迭
 *  \param  options : ó���ϰ��� �ϴ� �ɼ��� ����Ʈ
 *  \param  longopts : ó���ϰ��� �ϴ� �ɼ��� ����Ʈ
 *  \param  reserved : ������� �ʴ� �ɼ�
 *  \param  optarg : getopt() ó�� �ɼ� ���ڿ� ��ȯ �����
 *  \return char : -1�̸� ����, �������� �ɼ��� Ű ����(char) ��ȯ
 *  \remark 
 *   ���� getopt_long�� ������̹Ƿ� �⺻ ����� �����ϳ�, ��Ÿ �� ����� �������� ����
 */
char getopt_long2(int argc, char *argv[], char *options, const struct option2 longopts[], int *reserved, char **optarg)
{
	int i;
	int ret = (char)-1;
	static int loop_count = 1;

	if ( loop_count >= argc )
		return (char)-1;

	if ( NULL == argv[loop_count] )
		return (char)-1;

	if ( *argv[loop_count] != '-' )
	{
		loop_count++;
		return (int)'?'; 
	}
	if ( strlen(argv[loop_count]) < 2  )
	{
		loop_count++;
		return (char)-1; 
	}

	/* --�� �����ϴ� full string�� �ɼ� ó�� */
	if ( argv[loop_count][1] == '-' )	
	{
		for ( i = 0 ; longopts[i].name != NULL && longopts[i].name[0] != '\0' ; i++ )
		{
			if ( longopts[i].name != NULL && strcmp(longopts[i].name, &argv[loop_count][2]) == 0 )
			{
				ret = longopts[i].val;
				break;
			}
		}
	}
	else
	{
		/* -�θ� �Ǿ� �ִ� ���� �ɼ� ó�� */
		for ( i = 0 ; longopts[i].name != NULL && longopts[i].name[0] != '\0' ; i++ )
		{
			if ( longopts[i].val == argv[loop_count][1] )
			{
				ret = longopts[i].val;
				break;
			}
		}
	}
	
	if ( ret != (char)-1 )
	{
		/* �ɼ� �߿��� ���� �Է� �ɼ��� �ִ� ��� optarg�� �ּҰ��� ������ */
		if ( longopts[i].has_arg == required_argument && (loop_count+1) < argc )
		{
			*optarg = (char*)argv[loop_count+1];
			loop_count++;
		}
	}

	loop_count++;
	return ret;
}

/*! \brief
 *   ���ڿ� �յ��� ���� �� ���ʿ� ���� ���� �Լ�
 *  \param  source : �˻� ��� ���ڿ�
 *  \return none
 */
void strim_both(char *source)
{
    int len;
    int i;
    char copy_buf[MAX_STR_SIZE];
    char *tmp;

    if ( NULL == source || (len = strlen(source)) < 1 ) 
        return;

    memset(copy_buf, 0, len+1);
    strcpy(copy_buf, source);

    tmp = copy_buf;
    while ( *tmp == ' ' || *tmp == '\t' || *tmp == '\r' || *tmp == '\n' || *tmp == '\'' || *tmp == '\"' ) 
		tmp++;

   	for ( i = strlen(tmp)-1; i > 0 ; )
    {
    	i = strlen(tmp)-1;
        switch ( tmp[i] )
        {
            case ' ':
            case '\'':
            case '\"':
            case '\t':
            case '\r':
            case '\n':
                tmp[i] = '\0';
                break;
            default:
                i = 0;
                break;
        }
    }
    memset(source, 0, len);
    strcpy(source, tmp);
}


/* 
 * send reset packet
 */

/*! \brief
 *   packet spoofing�� ���� socket ����
 *  \param  char* interface : NIC �̸�, ex) eth0
 *  \return int ������ socket ��ȣ, ���� ���н� ERR_UNKNOWN ��ȯ 
 */
int init_resetpacket(const char *interface)
{
	int raw_socket;
	unsigned int on = 1;

	if ((raw_socket=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))==-1)
	{
		perror("Can not create raw socket.:");
		return ERR_UNKNOWN;
	}

	if (setsockopt(raw_socket,IPPROTO_IP,IP_HDRINCL,(void*)&on,sizeof(on)) < 0) 
	{
		close(raw_socket);
		perror("setsockopt: IP_HDRINCL");
		return ERR_UNKNOWN;
	}

#ifdef SIOCSIFFLAGS
	if ( NULL != interface )
	{
		struct ifreq ifr;
		strcpy(ifr.ifr_name, interface);
		if ( ioctl(raw_socket, SIOCGIFFLAGS, &ifr) < 0 )
		{
			close(raw_socket);
			perror("ioctl SIOCGIFFLAGS: ");
			return ERR_UNKNOWN;
		}     
		strcpy(ifr.ifr_name, interface);
		if ( ioctl(raw_socket, SIOCSIFFLAGS, &ifr) < 0 )
		{
			close(raw_socket);
			perror("ioctl SIOCSIFFLAGS: ");
			return ERR_UNKNOWN;
		}     
	}
#endif

	return raw_socket;
}

/*! \brief
 * TCP/IP ����� checksum�� ���ϴ� �Լ� 
 *  \param  header checksum�� ���� header�� pointer
 *  \param  len checksum�� ���ϱ� ���� header�� ����
 *  \return int �Է� header�� checksum
 */
static unsigned short in_cksum(u_short *header, int len)
{
	int sum=0;
	int nleft=len;
	u_short *w=header;
	u_short answer=0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16); 
	answer = ~sum; 

	return answer;
}


/*! \brief
 *   traffic dump�� �ϱ����� �⺻ ȯ�� ���� ���� �о���� ���� �Լ�
 *  \param  file_name : ȯ�� �������� �̸�
 *  \param  field_name : �ʵ� �̸�
 *  \param  output : �о�� ȯ�� �������� ����� ����
 *  \param  max_size : ����� ������ �ִ� ����
 *  \return int : 0�̸� content�� ���ų� ���⿡ ������ ���, �������� ����
 */
int get_dump_conf(const char* file_name, const char* field_name, char *output, int max_size)
{
	FILE *fp = NULL;

	char *line_p  = NULL;
	char *field_p = NULL;
	char *index   = NULL;
	char buf[MAX_STR_SIZE] = "";
	char fname_buf[MAX_STR_LEN] = "";

	unsigned int len;

	int  is_find_key = 0;
		
	if( file_name == NULL || *file_name == '\0' ) 
		return ERR_NULL;

	if( max_size <= 0 ) 
		return ERR_INVAL;

	memset(output, 0, max_size);
	while ( 1 ) 
	{
		if ( (fp = fopen( file_name, "r" )) != NULL ) 
		{
			strncpy(fname_buf, file_name, sizeof(fname_buf)-1);
			break;
		}

		if( NULL != fp )
			break;
		
		snprintf(fname_buf, sizeof(fname_buf), "%s%s", CONF_DIR_DS2, file_name);
		fp = fopen( fname_buf, "r" );
		if ( fp )
			break;

		snprintf(fname_buf, sizeof(fname_buf), "%s%s", CONF_DIR_ETC, file_name);
		fp = fopen( fname_buf, "r" );
		if ( fp )
			break;

		break;	 /* ������ 1���� ���� */
	}

	if ( NULL == fp )
	{
		/* dump.conf�� ��� ���� �����ؾ� �Ѵ�. */
		return ERR_NULL;
	}

	memset(output, 0, max_size);
										
	while ( fgets(buf, sizeof(buf), fp) != NULL )
	{
		index = buf;
		while( *index != '\0' && (*index == '\t' || *index == ' ') ) 
		{
			index++;
		}
																		
		index = buf;
		if( *index == '#' || strlen(buf) < 1 )
			continue;

		// Windows INI ������ ȯ�漳�� ������ ó���ϴ� �κ�
		if ( field_name && field_name[0] == '[' && strchr(field_name, ']') )
		{
			strim_both(index);

			if ( strlen(index) < 1 )
				continue;

			if( !is_find_key && strncmp(index, field_name, strlen(field_name)) == 0 )
			{
				is_find_key = 1;
			}
			else if ( is_find_key )
			{
				if ( *index == '[' )
					break;

				if ( (int)(strlen(output)+1) >= max_size )
					break;

				strncat(output, index, max_size - strlen(output) );
				strcat(output, "\n");
			}

			continue;
		}

		if( strlen(index) <= MIN_FIELD_SIZE ) 
			continue;

		field_p = strtok_r(index, CONF_DELIMITER, &line_p);

		while( (len=strlen(field_p)) > 0)
		{
			if (field_p[len-1] == ' ' )
				field_p[len-1] = '\0';
			else
				break;
		}

		if ( NULL == field_name )
		{
			strncpy(output, field_p, max_size);
			break;
		}

		if( strlen(field_name) == strlen(field_p) && strcmp(field_p, field_name) == 0 )
		{
			field_p = strtok_r(NULL, CONF_FIELD_DELIMITER, &line_p);
			if(field_p == NULL || field_p[0] == '\n' || field_p[0] == '\r')
			{
				fclose(fp);
				return ERR_NULL;
			}

			while ( ' ' == *field_p  )
				field_p++;

			if ( output[0] ) 
			{
				index = strstr(output, field_p);

				if ( NULL == index || (NULL != index && isdigit((int)index[strlen(field_p)])) )
				{
					strncat(output, "+", max_size);
					strncat(output, field_p, max_size);
				}
				else
					strncpy(output, field_p, max_size);
			}
			else
				strncpy(output, field_p, max_size);
		}
		memset(buf, 0, sizeof(buf));
	}
											
	fclose(fp);
	if ( output[0] )
	{
		strim_both(output);
		return ERR_SUCCESS;
	}

	return ERR_FREAD;
}


/*! \brief
 *   flow ���
 *  \param  field_value : �� ���Ͽ� ��ϵ� �ʵ� ��
 *  \param  ip_list : IP�׷��� ���Ǹ� ��� ip_info_t ����ü �迭
 *  \return int : 0�̸� content�� ���ų� ���⿡ ������ ���, �������� ����
 */
int parse_flow(char *field_value, unsigned char *flow)
{
	strim_both(field_value);

	*flow = FILTER_FLOW_RIGHT;
    if ( is_empty_string(field_value) || '0' == field_value[0] )
        return 0;

    if ( strcmp(field_value, "<-") == 0 || strcasecmp(field_value, "LEFT") == 0 )
		*flow = FILTER_FLOW_LEFT;
    else if ( strcmp(field_value, "<->") == 0 || strcmp(field_value, "<>") == 0 || strcasecmp(field_value, "BOTH") == 0 )
		*flow = FILTER_FLOW_BOTH;
	else
	{
		/* do nothing */
	}

    return  1;
}


/*! \brief
 *   IP or Port �׷��� ���
 *  \param  char* str_value : �� ���Ͽ� ��ϵ� �ʵ� ��
 *  \param  void* alias_list : �׷��� ���Ǹ� ��� ip_info_t or port_info_t ����ü �迭
 *  \param  int type : IP���� Port������ �����ϴ� Ÿ��
 *  \param  char* conf_file_name : ȯ�漳�� ���� ��θ�
 *  \return int : 0�̸� content�� ���ų� ���⿡ ������ ���, �������� ����
 */
int parse_alias_list(const char *str_value, void *alias_list, int type, char *conf_file_name)
{
    char *temp;
    int  alias_count;
    int  alias_temp;
    char *field_p = NULL;
    char *line_p  = NULL;

    if ( type != FIELD_TYPE_IPGROUP && type != FIELD_TYPE_PORTGROUP ) 
        return 0;

    if ( strstr(str_value, VALUE_STR_ANY) || strstr(str_value, VALUE_STR_any) ) 
    {
        if ( type == FIELD_TYPE_IPGROUP ) 
		{
            ((ip_info_t*)alias_list)[0].ip_seg = COMPARE_SKIP;
            ((ip_info_t*)alias_list)[0].ip_base = 0;
            ((ip_info_t*)alias_list)[0].ip_max  = IP_FULL_MASK;
        }
        else 
		{
            ((port_info_t*)alias_list)[0].count = COMPARE_SKIP;
        }
        return 0;
    }

    temp = (char*)str_value;
    while ( *temp == ' ' || *temp == '\t' )
        temp++;

    for ( alias_count = 0; alias_count < MAX_ALIAS; alias_count += alias_temp, temp = line_p)
    {
        field_p = (char*)strtok_r(temp,FIELD_DELIMITER,&line_p);

        if ( NULL == field_p )
            break;
        
        if ( type == FIELD_TYPE_IPGROUP )
        {
            alias_temp = parse_alias(field_p, (void*)&(((ip_info_t*)alias_list)[alias_count]), type, conf_file_name);
            if ( 0 == alias_temp )
            {
                log_printf(IPS_MANAGER_NAME, "%s() %d: Invalid IP string(%s)\n", __func__, __LINE__, field_p);
                break;
            }
        }
        else
        { 
            alias_temp = parse_alias(field_p, (void*)&(((port_info_t*)alias_list)[alias_count]), type, conf_file_name);
            if ( 0 == alias_temp )
            {
                log_printf(IPS_MANAGER_NAME, "%s() %d: Invalid Port string(%s)\n", __func__, __LINE__, field_p);
                break;
            }
        }
    }

    return alias_count;
}


/*! \brief
 *   IP ���ڿ��� ��ġ������ �����ͷ� ��ȯ�ϴ� �Լ�
 *  \param  str_value : ������ IP�ּ�
 *  \param  alias_list : �ؼ��� �׷��� ���Ǹ� ��� ip_info_t �Ǵ� port_info_t ����ü �迭
 *  \param  type : IP or Port type
 *  \param  conf_file_name : configure file path
 *  \return int : 0�̸� content�� ���ų� ���⿡ ������ ���, 1�̻��̸� ����� IP�ּ��� ��
 *  \remark
 *   ip type data: 1.1.1.1 or 1.1.1.0/24 or 1.1.1.1-1.1.1.22 or alias_name
 *   port type data: 1111 or 111:2000 or 111-2222, or alias_name
 */
static int  parse_alias(char *str_value, void *alias_list, int type, char *conf_file_name)
{
    char str_temp[MAX_STR_SIZE] = "";
    char *index;
    unsigned int temp_num1;
    unsigned int temp_num2;
    int i;

    if ( NULL == alias_list || NULL == str_value || strlen(str_value) < 1 ) 
		return 0;

    if ( FIELD_TYPE_IPGROUP == type ) 
        ((ip_info_t*)alias_list)->ip_seg = COMPARE_SKIP;
    else 
        ((port_info_t*)alias_list)->count = COMPARE_SKIP;

    strncpy(str_temp, str_value, sizeof(str_temp)-1);

    if ( (index = strchr(str_temp, '/')) )
    {
        /* segment type, ex) 172.16.0.0/16 */
        int   segment_num;

        if ( FIELD_TYPE_IPGROUP != type)
			return 0;

        index[0] = '\0';
        index++;

        if ( (strlen(index) == 1 && isdigit((int)index[0]) ) || (strlen(index) == 2 && isdigit((int)index[0]) && isdigit((int)index[1]) ) )
        {
            ((ip_info_t*)alias_list)->ip_seg = COMPARE_RANGE;

            segment_num = IP_SEGMENT_BITS - atoi(index);
            if ( 0 > segment_num )
                segment_num = 0;
            else if ( segment_num > IP_SEGMENT_BITS )
                segment_num = IP_SEGMENT_BITS;

            temp_num1 = inet_addr(str_temp);
            ((ip_info_t*)alias_list)->ip_base = ntohl((temp_num1 & (IP_FULL_MASK >> segment_num)) & IP_FULL_MASK);
            ((ip_info_t*)alias_list)->ip_max  = ntohl(temp_num1 | (IP_FULL_MASK ^ (IP_FULL_MASK >> segment_num)));

			return 1;
        }
    }
    else if ( (index = strchr(str_temp, '-')) || (index = strchr(str_temp, ':')) )
    {
        index[0] = '\0';
        index++;

        if ( FIELD_TYPE_IPGROUP == type )
        {
            /* range type, ex) 172.16.1.1-172.16.1.255 */
            temp_num1 = inet_addr(str_temp);
            temp_num2 = inet_addr(index);

            if ( temp_num1 == INADDR_NONE || temp_num2 == INADDR_NONE )
				return 0;

            ((ip_info_t*)alias_list)->ip_seg = COMPARE_RANGE;
            ((ip_info_t*)alias_list)->ip_base = ntohl(temp_num1);
            ((ip_info_t*)alias_list)->ip_max = ntohl(temp_num2);
        }
        else
        {
            /* range type, ex) 135:139 or 1024-65535 */
            for ( i = 0; str_temp[i] != '\0'; i++ )
            {
                if ( !isdigit((int)str_temp[i]) )
					return 0;
            }
            for ( i = 0; index[i] != '\0'; i++ )
            {
                if ( !isdigit((int)index[i]) )
					return 0;
            }

            ((port_info_t*)alias_list)->count = COMPARE_RANGE;
            ((port_info_t*)alias_list)->port_base = atoi(str_temp);
            ((port_info_t*)alias_list)->port_max = atoi(index);
        }
        index--;
        index[0] = '-';

        return 1;
    }
    else if ( (temp_num1  = (unsigned int)inet_addr(str_temp)) != INADDR_NONE && strchr(str_temp, '.') )
    {
        /* single ip type, ex) 172.16.1.1 */
        if ( FIELD_TYPE_IPGROUP != type )
			return 0;

        ((ip_info_t*)alias_list)->ip_seg = COMPARE_SINGLE;
        ((ip_info_t*)alias_list)->ip_base = ntohl(temp_num1);
        ((ip_info_t*)alias_list)->ip_max = 0;

		return 1;
    }

    if ( FIELD_TYPE_PORTGROUP == type )
    {
        for ( i = 0; str_temp[i] != '\0'; i++ )
        {
            if ( !isdigit((int)str_temp[i]) )
                break;
        }

        if ( '\0' ==  str_temp[i] )
        {
            /* single port type, ex) 445 */
            ((port_info_t*)alias_list)->count = COMPARE_SINGLE;
            ((port_info_t*)alias_list)->port_base = atoi(str_temp);
            ((port_info_t*)alias_list)->port_max = 0;

			return 1;
        }
    }

    /* alias name type or error */
    memset(str_temp, 0, sizeof(str_temp));

    if ( conf_file_name && ERR_SUCCESS == get_dump_conf(conf_file_name, str_value, str_temp, sizeof(str_temp)-1) )
    {
        return parse_alias_list(str_temp, alias_list, type, conf_file_name);
    } 

    return 0;
}


/* ------------------------------ ���� �α׸� ����� �ִ� �Լ� --------------------------------- */

/** 
 @brief
  ./log/process_name ���Ͽ� ������ �����α׸� ����� �Լ�
 @param pname process name
 @param pre_fmt print format
 @return int ERR_SUCCESS ����, ��Ÿ ����
*/
int	log_printf (char *pname, const char *pre_fmt , ... )
{
	va_list	local_mylist;
	char	local_buff[MAX_STR_LEN];
	char	local_logfilename[MAX_STR_LEN];
	FILE	*local_fp;
	time_t	local_get_now;
	static time_t	old_local_get_now = 0;
	static char	old_local_buff[MAX_STR_SIZE] = "";

	struct tm local_tm;
	int     len;
	char    *index = pname;

	if ( NULL == index )
	{
		return ERR_NULL;
	}

	for ( ; isalpha((int)*index) == 0 && strlen(index) > 0;  )
	{
		index++;
	}
	
	local_get_now = time(NULL);
	localtime_r ( &local_get_now , &local_tm );
	
	snprintf( local_logfilename, sizeof(local_logfilename), "log/%s/%04d/%02d/%02d/%04d%02d%02d.log" 
		, index, local_tm.tm_year+1900 , local_tm.tm_mon+1 , local_tm.tm_mday
		, local_tm.tm_year+1900 , local_tm.tm_mon+1 , local_tm.tm_mday);

	if ( ( local_fp = fopen ( local_logfilename , "a" ) ) == NULL )
	{
		char	tmp[MAX_STR_LEN];

		mkdir("log", 0644);
		snprintf( tmp, sizeof(tmp), "log/%s", index);
		mkdir(tmp, 0644);
		snprintf( tmp, sizeof(tmp), "log/%s/%04d", index, local_tm.tm_year+1900);
		mkdir(tmp, 0644);
		snprintf( tmp, sizeof(tmp), "log/%s/%04d/%02d", index, local_tm.tm_year+1900, local_tm.tm_mon+1);
		mkdir(tmp, 0644);
		snprintf( tmp, sizeof(tmp), "log/%s/%04d/%02d/%02d", index, local_tm.tm_year+1900, local_tm.tm_mon+1, local_tm.tm_mday);
		mkdir(tmp, 0644);

		if ( ( local_fp = fopen ( local_logfilename , "w" ) ) == NULL )
		{
			return ERR_NULL;		
		}
	}

	local_buff[sizeof(local_buff)-1] = '\0';

	va_start ( local_mylist , pre_fmt );
	vsnprintf( local_buff , sizeof(local_buff), pre_fmt , local_mylist );
	va_end ( local_mylist );

	/* printf -> log_printf �Ѱ�쿡 ���ϵ��� '\n' ���� �����Ѵ�. */
	len=strlen(local_buff);
	if( len > 0 && (local_buff[len-1] == '\n' || local_buff[len-1] == '\r') )
	{
		len--;
		local_buff[ len ] = '\0';
	}

	/* 2009-01-06, ª�� �ð��� ���� �߻��� �ߺ� �α״� ������� �ʴ´�. */
	if ( strncmp( old_local_buff, local_buff, sizeof(old_local_buff)-1) == 0 )
	{
		if ( old_local_get_now == local_get_now )
		{
			fclose ( local_fp );
			return ERR_SUCCESS;			
		}
	}
	else
	{
		strncpy( old_local_buff, local_buff, sizeof(old_local_buff)-1);
	}

	old_local_get_now = local_get_now;

	fprintf( local_fp , "[%.2d:%.2d:%.2d] %s\n" , local_tm.tm_hour , local_tm.tm_min , local_tm.tm_sec ,local_buff );
	fclose ( local_fp );

	return ERR_SUCCESS;
}


/* ------------------------------ �޸� ������ ó�� ���� �Լ� --------------------------------- */

/*!
 \brief
  �޸� �Ҵ� ���н� �α׸� ����� �Ŀ� �����ϴ� �Լ�
 \param size_t nSize : �޸� �Ҵ��� ũ��
 \param char* pFname : �ҽ� �ڵ� �̸�
 \param int nLine : �ҽ� �ڵ� ��ġ (����)
 \return void* : �Ҵ�� �޸� �ּ� ��ȯ
 */
void *malloc_n_exit(size_t nSize, const char *pFname, int nLine)
{
	void *pVoid = malloc(nSize);
	if ( !pVoid )
	{
		log_printf(IPS_MANAGER_NAME, "%s()-%d: Size(%d), %s", pFname, nLine, nSize, strerror(errno));
		exit(-1);
		return NULL;
	}

	return pVoid;
}


/*!
 * \brief
 *  �Է� ���ۿ� Ư�� Ű���尡 �ִ��� ã�� �Լ�
 * \param buff : �˻� ��� ������ char ������ ��
 * \param buff_len : �˻� ��� ������ ����
 * \param keyword : �˻� Ű����
 * \param keyword_len : �˻� Ű������ ����
 * \return int : �˻� Ű������ ������ ��ġ�� ��ȯ�ϰ�, ������ 0�� ��ȯ
 */
int search_mem_keyword(char *buff, int buff_len, char *keyword, int keyword_len)
{
    int i, j;

    for ( i = 0, j= 0; i < buff_len; i++ )
    {
        if ( keyword[j++] != buff[i] )
        {
            j = 0;
            continue;
        }

        if ( j == keyword_len )
            return i;
    }

    return 0;
}


/*!
 * \brief
 *  strncpy()
 *  ������ ���� ������ ���� �ۼ�
 */
char *strncpy2(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n && src[i] != '\0'; i++)
		dest[i] = src[i];
	dest[i] = '\0';

	return dest;
}


/*
 \brief
  ��� ��ϵ� ��Ʈ��ũ ����Ʈ�� ȭ�鿡 ����� �ִ� �Լ�
 \return void
 */
void print_interface()
{
        int nRet;
        const char *pszCmd = "ifconfig -a | egrep 'Link|addr' | grep -v inet";
        nRet = system(pszCmd);
        if ( nRet < 0 )
        {
                log_printf(IPS_MANAGER_NAME, "%s()-%d: ERROR: %s", __func__, __LINE__, pszCmd);
        }
}


/*! \brief
 *   ������ raw packet�� ȭ�鿡 ����ϴ� �Լ�
 *  \param  p : packet_t ����ü ������
 *  \param  packet : raw packet
 *  \return none
 */
void print_to_console(const packet_t *p, const u_char *packet, int is_print_console, int is_print_hexa)
{
	struct in_addr *ip_src = (struct in_addr*)&p->sip;
	struct in_addr *ip_dst = (struct in_addr*)&p->dip;
	struct tm *lt;
	struct protoent *pt;
	int i, j;
	unsigned char ch;
	char *proto_str;
	char flag;

	if ( NULL == p || NULL == packet )
		return;

	ip_src = (struct in_addr*)&p->sip;
	ip_dst = (struct in_addr*)&p->dip;
	lt = gmtime((time_t *)&(p->tv.tv_sec));

	proto_str = "_";
	if ( p->iph != NULL ) 
	{
		pt = (struct protoent*)getprotobynumber(p->iph->ip_proto);
		proto_str = pt->p_name;
	}

	if ( is_print_console )
	{
		printf("[%02i:%02i:%02i] %04x-%s %s:%d", lt->tm_hour, lt->tm_min, lt->tm_sec, ntohs(p->eh->h_proto), proto_str, inet_ntoa(*ip_src), p->sp);
		printf(" > %s:%d len:%d", inet_ntoa(*ip_dst), p->dp, p->caplen); if ( p->vlan_id != -1 ) printf(" vlanid: %d", p->vlan_id);
	}
	else
	{
		unsigned char *mac = p->eh->h_source;
		unsigned char *dmac = p->eh->h_dest;

		printf("[%02i:%02i:%02i] ETH:%04x PROT:%s SIP:%s(%02X:%02X:%02X:%02X:%02X:%02X) SP:%d",
			lt->tm_hour, lt->tm_min, lt->tm_sec, ntohs(p->eh->h_proto), proto_str, inet_ntoa(*ip_src), mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff, p->sp);
		printf(" -> DIP:%s(%02X:%02X:%02X:%02X:%02X:%02X) DP:%d len:%d", 
			inet_ntoa(*ip_dst), dmac[0]&0xff, dmac[1]&0xff, dmac[2]&0xff, dmac[3]&0xff, dmac[4]&0xff, dmac[5]&0xff, p->dp, p->caplen);
		if ( p->vlan_id != -1 )
			printf(" vlanid: %d", p->vlan_id);
	}

	flag = p->tcph->th_flags;
	printf(" flag:%c%c%c%c%c%c ttl:%d\n", (flag&R_FIN)? 'F':'.', (flag&R_SYN)? 'S':'.', (flag&R_RST)? 'R':'.', (flag&R_PSH)? 'P':'.', (flag&R_ACK)? 'A':'.', (flag&R_URG)? 'U':'.', p->iph->ip_ttl);

	if ( !is_print_hexa  )
		return;

	for( i = 0 ; i < p->caplen; i++ )
	{
		if ( i%24 == 0 )
		{
			if ( i != 0 )
			{
				printf(" ");
				for ( j = i-24; j < i ; j++ )
				{
					ch = packet[j];
					printf("%c", ((ch > 127 || ch < ' ')? '.':ch) );
				}
			}
			if ( i != 0 )
				printf("\n");
			printf("[%03x] ", i);
		}
		else if( i%8 == 0 )
			printf(" ");

		printf("%02X ", packet[i]);
	}
	for ( j = i; j < (i + (24-i%24) ); j++ )
	{
		if( j%8 == 0 )
			printf(" ");
		printf("   ");
	}
	printf(" ");
	for ( j = i-(i%24); j < i ; j++ )
	{
		ch = packet[j];
		printf("%c", ((ch > 127 || ch < ' ')? '.':ch) );
	}
	printf("\n\n");
}

/* end of file */

