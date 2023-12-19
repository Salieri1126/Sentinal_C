#include "logging.h"

extern configure_t g_conf;
extern IpsMatch rules;

static void bin_to_hex(const u_char *bin, size_t len, char *out);

/*
 *	!brief
 *		로그의 정보를 읽어오는 함수
 *	\param
 *	\return int
 *		0 
 */
int IpsLog::is_read_logInfo(){
	
	memcpy( l_info.logIp, g_conf.dbinfo.base.host, strlen(g_conf.dbinfo.base.host) );
	memcpy( l_info.logPort, g_conf.dbinfo.port, strlen(g_conf.dbinfo.port) );
	memcpy( l_info.user, g_conf.dbinfo.base.dbusr, strlen(g_conf.dbinfo.base.dbusr) );
	memcpy( l_info.password, g_conf.dbinfo.base.dbpass, strlen(g_conf.dbinfo.base.dbpass) );
	memcpy( l_info.dbName, g_conf.dbinfo.db, strlen(g_conf.dbinfo.db) );

	strim_both ( l_info.logIp );
	strim_both ( l_info.logPort );
	strim_both ( l_info.user );
	strim_both ( l_info.password );
	strim_both ( l_info.dbName );

	return 0;
}

int IpsLog::connect_db(){
	
	conn = mysql_init(NULL);

	/* Connect to database */
    if (!mysql_real_connect(conn, l_info.logIp, l_info.user, l_info.password, NULL, atoi(l_info.logPort), NULL, 0)) {
       	fprintf(stderr, "%s\n", mysql_error(conn));
		return -1;
    }

	return 0;
}

/*
 *	정책 DB에 연결하는 함수
 */

int IpsLog::conn_policy(){
	
	char query[1024];
	
	sprintf(query, "use S_ips_policy_db");

    if (mysql_query(conn, query)) {
		if( create_policy() ){
			return -1;
		}
    }

	create_policy();

	return 0;
}

/*
 *	정책 DB에서 정책을 읽어오는 함수
 */
int IpsLog::read_policy(){

	MYSQL_RES *result;

	if( mysql_query(conn, "SELECT * FROM ips_policy") ){
        fprintf(stderr, "%s\n", mysql_error(conn));
		create_policy();
        return -1;
	}

	result = mysql_store_result(conn);
	if( result == NULL ){
		fprintf(stderr, "mysql_store_result() failed\n");
        mysql_close(conn);
        return -1;
	}

	rules.is_read_rules(result);

	return 0;
}

/*
 *	정책 DB없을 경우 DB와 테이블을 생성하는 함수
 */
int IpsLog::create_policy(){

    /* send SQL query */
    if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS S_ips_policy_db")) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return -1;
    }

	char query[1024];

	sprintf(query, "use S_ips_policy_db");

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return -1;
    }

	memset( query, 0, sizeof(query));
    sprintf(query, "CREATE TABLE IF NOT EXISTS ips_policy"
				" (detected_no INT(6) NOT NULL AUTO_INCREMENT PRIMARY KEY,"
				"detected_name VARCHAR(50) NOT NULL,"
				"content1 VARCHAR(255),"
				"content2 VARCHAR(255),"
				"content3 VARCHAR(255),"
				"enable INT(1) NOT NULL default 0,"
				"src_ip VARCHAR(15) default 0,"
				"src_port int(5) default 0,"
				"action INT(1) NOT NULL default 0,"
				"level INT(1) NOT NULL default 0,"
				"base_time INT(11) default 0,"
				"base_limit INT(11) default 0,"
				"end_time DATE NOT NULL,"
				"detail VARCHAR(255),"
				"to_sip VARCHAR(15) default 0,"
				"to_sp INT(5) default 0,"
				"dst_ip VARCHAR(15) default 0,"
				"base_size INT(11) default 0) AUTO_INCREMENT = 100001");

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return -1;
    }
	
	return 0;
}

int IpsLog::create_log(){

    /* send SQL query */
    if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS S_ips_log_db")) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return -1;
    }

	char query[1024];
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

	sprintf(query, "use S_ips_log_db");

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return -1;
    }

	memset( query, 0, sizeof(query));
    sprintf(query, "CREATE TABLE IF NOT EXISTS log_%04d%02d%02d"
				" (log_index INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,"
				"detected_no INT(6) NOT NULL,"
				"detected_name VARCHAR(50) NOT NULL,"
				" time TIMESTAMP, action INT(1) NOT NULL,"
				" src_ip VARCHAR(15) NOT NULL,"
				" packet_bin VARBINARY(3000) NOT NULL,"
				" level INT(1) NOT NULL,"
				" src_port int(5) NOT NULL,"
				" dst_ip VARCHAR(15) NOT NULL)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    
	if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return -1;
    }
	
	return 0;
}

int IpsLog::logEnqueue(u_char *packet, packet_t *p, int ruleIndex){

	char query[0xFFFF]="";
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct in_addr *ip_src = (struct in_addr*)&p->sip;
	struct in_addr *ip_dst = (struct in_addr*)&p->dip;
	pthread_mutex_t m_mutex = PTHREAD_MUTEX_INITIALIZER;

	char hex[0xFFF];
	bin_to_hex(packet, p->caplen, hex);
	
	rule_t* detectRule = rules.getRule(ruleIndex);

	snprintf(query, sizeof(query), "INSERT INTO log_%04d%02d%02d"
			"(detected_no, detected_name, time, action, detail, src_ip, packet_bin, level, src_port, dst_ip)"
			"VALUES (%d, '%s', NOW(), %d, '%s', '%s', UNHEX('%s'), %d, %d, '%s')", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, detectRule->rid, detectRule->deName, detectRule->action, "test detected", inet_ntoa(*ip_src), hex, detectRule->level, p->sp, inet_ntoa(*ip_dst));
	
	pthread_mutex_lock(&m_mutex);
	enqueue(&m_queLog, query);
	pthread_mutex_unlock(&m_mutex);

	return 0;
}

/*
 * !brief
 *		payload내용을 이진코드로 변환하여 
 *
 *
 */
static void bin_to_hex(const u_char *bin, size_t len, char *out) {

    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02X", bin[i]);
    }
}

void IpsLog::logDequeue(){
	
	pthread_mutex_t m_mutex = PTHREAD_MUTEX_INITIALIZER;
	
	char query[0xFFFF] = "";
	char *pQuery;
	
	pthread_mutex_lock(&m_mutex);
	pQuery = dequeue(&m_queLog);
	pthread_mutex_unlock(&m_mutex);

	memcpy(query, pQuery, strlen(pQuery));

	if (mysql_query(conn, query)) {
	   	fprintf(stderr, "%s\n", mysql_error(conn));
    	return;
	}

	return;
}

int IpsLog::is_empty_logQueue(){

	if( is_empty(&m_queLog) ){
		return 1;
	}

	return 0;
}

void IpsLog::init(logQueue_t *Q)
{
	Q->rear = Q->front = 0;
}

int IpsLog::is_empty(logQueue_t *Q)
{
	return Q->front == Q->rear;
}

int IpsLog::is_full(logQueue_t *Q)
{
	return Q->front == (Q->rear + 1) % MAX_LOG_SIZE;
}

void IpsLog::enqueue(logQueue_t *Q, char *query)
{
	if (is_full(Q))
		return;
	else
	{
		Q->rear = (Q->rear + 1) % MAX_LOG_SIZE;

    	memcpy( Q->logQuery[Q->rear], query, strlen(query));
	}
}

char* IpsLog::dequeue(logQueue_t *Q)
{
  	if (is_empty(Q))
  	{
    	printf("Empty\n");
  		return 0;
  	}

  	else
  	{
		Q->front = (Q->front + 1) % MAX_LOG_SIZE;
	    return Q->logQuery[Q->front];
	}
}
