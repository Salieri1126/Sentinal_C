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
        fprintf(stderr, "%s\n", mysql_error(conn));
		if( create_policy() ){
			return -1;
		}
        return -1;
    }
	return 0;
}

/*
 *	정책 DB에서 정책을 읽어오는 함수
 */
int IpsLog::read_policy(){

	return 0;
}

/*
 *	정책 DB없을 경우 DB와 테이블을 생성하는 함수
 */
int IpsLog::create_policy(){
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
				"detected_no INT(6),"
				"detected_name VARCHAR(50),"
				" time TIMESTAMP, action INT(1),"
				" detail VARCHAR(255),"
				" src_ip VARCHAR(15),"
				" packet_bin VARBINARY(3000),"
				" level INT(1),"
				" src_port int(5),"
				" dst_ip VARCHAR(15))", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);

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

//TODO : logging thread에서 로그를 실행해야 할 함수 추가
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
