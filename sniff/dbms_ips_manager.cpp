/*
 * (C) Copyright 2010. PNP Secure, Inc.
 *
 * Any part of this source code can not be copied with
 * any method without prior written permission from
 * the author or authorized person.
 *
 */

/*!
 * \file dbms_ips_manager.c
 * \author SunTae Jin(zalhae@pnpsecure.com)
 * \brief 
 *  Information required for dbms_ips operation is read from mysql db, 
 *  loaded into memory, and detection and policy management threads are created.
 */


// 2023-05-16, Simplify with educational code

/*---- INCLUDES	  -------------------------------------------------*/

#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <pthread.h>

#include "dbms_ips_manager.h"
#include "util.h"
#include "init_agent.h"
#include "match.h"
#include "logging.h"
#include "session.h"

/*---- DEFINES		------------------------------------------------*/

#define INPUT_TYPE_NET 0

/*---- LOCAL TYPEDEF/STRUCT DECLARATION -------------------------------*/

/*---- STATIC VARIABLES -----------------------------------------------*/

static struct option2 program_options[] =
{
	{ "list"    , no_argument, 0, 'l' },
	{ "version" , no_argument, 0, 'v' },
	{ "test"    , no_argument, 0, 't' },
	{ "help"    , no_argument, 0, 'h' },
	{ "debug"   , no_argument, 0, 'g' },
	{ "hexa"   , no_argument, 0, 'H' },
	{ 0,0,0,0 }
};   /**< getopt_long 에서 처리할 옵션에 대한 정의 */


/*---- GLOBAL VARIABLES -----------------------------------------------*/
configure_t g_conf;      /**< Environment value collection structure for action */
IpsMatch rules;
IpsLog logs;
IpsSession sess;
/*---- STATIC FUNCTIONS FORWARD DECLARATION ---------------------------*/

static void display_manager_help(char *progname);
static void init_program(int nType);
void stop_processor(int sig);

/*---- FUNCTIONS ------------------------------------------------------*/

/*! \brief
 *   dbms_ips_manager's main
 *  \param  argc : argument count,
 *  \param  argv : agrument value
 *  \return int 0
 */
int main(int argc, char *argv[])
{
	char *argv1 = NULL;
	char cOption = 0;
	// pthread_t schedule_thread;
	char *optarg = NULL;        

	if ( argc < 3 )
		log_printf(IPS_MANAGER_NAME, "%s()-%d: START", __func__, __LINE__);


	///////////////////////////////////////////////////
	// step-1 : Initialization
	
	// variable initialization
	memset(&g_conf, 0, sizeof(g_conf));

	g_conf.is_running = 1;
	g_conf.ips_version = 2;
	g_conf.input_type = INPUT_TYPE_NET;

	// For training, option to output detected results to screen
	g_conf.is_print_list = 1;

	if ( 1 < argc )
		argv1 = argv[1];
	

	///////////////////////////////////////////////////
	// step-2 : option handling
	
	while ((cOption = getopt_long2(argc, argv, "lvgthH", program_options, NULL, &optarg)) != (char)-1)
	{
		switch(cOption)
		{
			case 'l':
				print_interface();
				exit(0);
				break;
			case 'v':
				display_version(argv[0]);
				exit(0);
				break;

			case 'g':
				g_conf.is_debug_mode = 1;
				break;

			case 't':
				g_conf.is_both_mode = 1;
				break;

			case 'h':
				display_manager_help(argv[0]);
				exit(0);
			
			case 'H':
				g_conf.is_print_hexa = 1;
				break;

			default:
				/* do nothing */
				break;
		}
	}

	if ( g_conf.is_debug_mode )
		fprintf(stderr, "%s() %d: option=%s\n", __func__, __LINE__, argv1);


	///////////////////////////////////////////////////
	// step-3 : Run dbms_ips_manager

	//signal(SIGTERM, stop_processor);
	signal(SIGINT, stop_processor);
	signal(SIGHUP, stop_processor);
	signal(SIGUSR1, stop_processor);
	//signal(SIGILL, SIG_IGN);
	//signal(SIGALRM, SIG_IGN);
	signal(SIGPROF, SIG_IGN);

	// step-3.1 : Program initialization according to options
	init_program(g_conf.input_type);

	if ( g_conf.is_debug_mode )
		fprintf(stderr, "%s() %d: write_own_pid(%s)\n", __func__, __LINE__, SERVICE_IPS_MANAGER_PID_FILE);


	// step-3.3 : Run main-thread & log-thread
	if ( init_server_agent(&g_conf) != ERR_SUCCESS )
	{
		log_printf(IPS_MANAGER_NAME, "%s() %d: Can't execute program\n", __func__, __LINE__);
		exit(0);
		return -1;
	}           

	///////////////////////////////////////////////////
	// step-4 : Program termination processing
	if ( g_conf.is_debug_mode )
		log_printf(IPS_MANAGER_NAME, "%s() %d: End of program\n", __func__, __LINE__);

	return 0;
}


/*!
 \brief
   display help
 \param progname : Name of this program
 \return void
 */
static void display_manager_help(char *progname)
{
	char *name = strchr(progname, '/');
	if ( name )
		name++;
	else
		name = progname;
	
	fprintf(stderr, "* License: %s\n", g_license_string);
	fprintf(stderr, "* Usage-1: %s [start|stop]\n", name);
	fprintf(stderr, "* Usage-2: %s [options]\n", name);
	fprintf(stderr, "* Options:\n"
		" --test, -t    : Test\n"
		" --list, -l    : Print Interface\n"
		" --version, -v : Print package version\n"
		" --debug, -g   : Print debug message\n"
		" --hexa, -H	: Print hexa mode\n"
		" --help, -h    : Print help\n");
}


/*!
 \brief
  program initialization
 \param int nType : Types of Audit Data (file, network, db)
 \return void
 */
static void init_program(int nType)
{
	struct sigaction act;
	FILE *fp = NULL;
	u_int i = 0;
	char szBuf[MAX_STR_LEN] = ""; 

	g_conf.ips_version = 5;
	memset(&act, 0, sizeof(act));


	///////////////////////////////////////////////////
	// step-0 : create dbms_ips_manager.conf
	if ( access(IPS_MANAGER_CONF, R_OK) != 0 )
	{
		// If the configuration file does not exist, create a default configuration file
		fp = fopen(IPS_MANAGER_CONF, "w");
		if ( fp )
		{
			fprintf(fp, "LANGUAGE=english\n");
			fprintf(fp, "SNIFF_NIC=enp2s0\n");
			fprintf(fp, "DB_IP=127.0.0.1\n");
			fprintf(fp, "DB_PORT=3306\n");
			fprintf(fp, "DB_USER=root\n");
			fprintf(fp, "DB_PW=dbsafer00\n");
			fprintf(fp, "DB_INFO=dbsafer3\n");
			fprintf(fp, "GW_IP=192.168.3.76\n");
			fprintf(fp, "LANGUAGE=korean\n\n");
			fprintf(fp, "# DBSCAN_CYCLE: default(600), minimum(60), maximum(86400), disable(0)\n");
			fprintf(fp, "DBSCAN_CYCLE=600\n");
			fclose(fp);
		}
	}


	///////////////////////////////////////////////////
	// step-1 : Get database connection information
	get_dump_conf(IPS_MANAGER_CONF, "DB_IP", g_conf.dbinfo.base.host, sizeof(g_conf.dbinfo.base.host));
	get_dump_conf(IPS_MANAGER_CONF, "DB_USER", g_conf.dbinfo.base.dbusr, sizeof(g_conf.dbinfo.base.dbusr));
	get_dump_conf(IPS_MANAGER_CONF, "DB_PW", g_conf.dbinfo.base.dbpass, sizeof(g_conf.dbinfo.base.dbpass));
	get_dump_conf(IPS_MANAGER_CONF, "DB_INFO", g_conf.dbinfo.db, sizeof(g_conf.dbinfo.db));
	get_dump_conf(IPS_MANAGER_CONF, "DB_PORT", g_conf.dbinfo.port, sizeof(g_conf.dbinfo.port));
	
	///////////////////////////////////////////////////
	// 추가 prac-1 : conf 파일에 있는 rule_file_name에 담기
	get_dump_conf(IPS_MANAGER_CONF, "RULE_LIST", g_conf.rule_file_name, sizeof(g_conf.rule_file_name));
	// 		prac-2 : IpsMatch 선언하고 클래스의 rule_t에 rule_list.txt에 있는 룰 맞춰 담기
	//	위에서 rule_t rules 구조체 전역변수로 선언
	//
	//	231121 전역변수로 클래스를 선언하고 여기서 룰을 따로 읽기
	if( !rules.is_read_rules( g_conf.rule_file_name ) ){
		printf("Don't read rules\n");
		return;
	}

	if( !rules.is_compile_rule() ){
		printf("Compile Fail!\n");
		return;
	}
	
	// 		prac-3 : compile 하기
	// 		prac-4 : contentsFilter 작성하기
	// 		prac-5 : packet을 가져와서 contentsFilter로 비교하기

	get_dump_conf(IPS_MANAGER_CONF, "TARGET_DB_IP", g_conf.targetIp, sizeof(g_conf.targetIp));
	get_dump_conf(IPS_MANAGER_CONF, "TARGET_DB_PORT", g_conf.targetPort, sizeof(g_conf.targetPort));

	if ( logs.is_read_logInfo() ){
		printf("read Log Fail\n");
		return;
	}

	if ( logs.connect_db() ) {
		printf("connect Fail\n");
		return;
	}

	if ( logs.create_log() ) {
		printf("Don't create log_db\n");
		return;
	}

	///////////////////////////////////////////////////
	// step-2 : get db-scan cycle
	if ( get_dump_conf(IPS_MANAGER_CONF, "DBSCAN_CYCLE", szBuf, sizeof(szBuf)-1) == ERR_SUCCESS && isdigit(*szBuf) )
	{
		g_conf.dbscan_cycle = (unsigned int)atoi(szBuf);
			if ( g_conf.dbscan_cycle < 1 )
			g_conf.dbscan_cycle = 0;
		else if ( g_conf.dbscan_cycle < 60 )
			g_conf.dbscan_cycle = 60;
		else if ( g_conf.dbscan_cycle > 86400 )
			g_conf.dbscan_cycle = 86400;
	}


	///////////////////////////////////////////////////
	// step-3 : get/set locale
	g_conf.language_type = 'k';


	///////////////////////////////////////////////////
	// step-4 : Get sniffing interface information
	get_dump_conf(IPS_MANAGER_CONF, "SNIFF_NIC", szBuf, sizeof(szBuf)-1);
	if ( isalpha(szBuf[0]) )
	{
		strncpy2(g_conf.interface_name[0], szBuf, sizeof(g_conf.interface_name[0])-1);
		g_conf.interface_count = 1;
	}

	if ( g_conf.is_debug_mode )
	{
		fprintf(stderr, "\nNIC Count(%d): ", g_conf.interface_count);
		for ( i = 0 ; i < (u_int)g_conf.interface_count ; i++ )
			fprintf(stderr, "%s ",  g_conf.interface_name[i]);
		fprintf(stderr, "\n---------------------\n");
	}


	///////////////////////////////////////////////////
	// step-5 : Get gateway IP address
	get_dump_conf(IPS_MANAGER_CONF, "GW_IP", szBuf, sizeof(szBuf)-1);
	if ( strlen(szBuf) < 6 )
		g_conf.service_ip = inet_addr("127.0.0.1");
	else
		g_conf.service_ip = inet_addr(szBuf);


	log_printf(IPS_MANAGER_NAME, "%s()-%d", __func__, __LINE__);

	// Synchronization variable initialization (pthread_mutex_lock/unlock)
	g_conf.sync_mutex = PTHREAD_MUTEX_INITIALIZER;
}

/*
 *!\brief
 *	End signal mapping function
 * \param sig : signal number
 * \return void : none
 *
 */

void stop_processor(int sig)
{
	signal(SIGPROF, SIG_IGN);
	g_conf.is_running = 0;

	log_printf(IPS_MANAGER_NAME, "%s()-%d: signal=%d", __func__, __LINE__, sig);

	sleep(1);
	exit(0);
}

/* End of program */
