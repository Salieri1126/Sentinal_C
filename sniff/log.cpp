#include "log.h"

extern configure_t g_conf;

static void bin_to_hex(const u_char *bin, size_t len, char *out); 

int IpsLog::is_read_logInfo(){
	
	strncpy( l_info.logIp, g_conf.dbinfo.base.host, strlen(g_conf.dbinfo.base.host) );
	strncpy( l_info.logPort, g_conf.dbinfo.port, strlen(g_conf.dbinfo.port) );
	strncpy( l_info.user, g_conf.dbinfo.base.dbusr, strlen(g_conf.dbinfo.base.dbusr) );
	strncpy( l_info.password, g_conf.dbinfo.base.dbpass, strlen(g_conf.dbinfo.base.dbpass) );
	strncpy( l_info.dbName, g_conf.dbinfo.db, strlen(g_conf.dbinfo.db) );

	strim_both ( l_info.logIp );
	strim_both ( l_info.logPort );
	strim_both ( l_info.user );
	strim_both ( l_info.password );
	strim_both ( l_info.dbName );
	return 0;
}

int IpsLog::create_log(){

	conn = mysql_init(NULL);

	/* Connect to database */
    if (!mysql_real_connect(conn, l_info.logIp, l_info.user, l_info.password, "mysql", atoi(l_info.logPort), NULL, 0)) {
       	fprintf(stderr, "%s\n", mysql_error(conn));
		return 1;
    }

    /* send SQL query */
    if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS S_ips_log_db")) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return 1;
    }

	char query[1024];
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

	sprintf(query, "use S_ips_log_db");

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return 1;
    }

	memset( query, 0, sizeof(query));
    sprintf(query, "CREATE TABLE IF NOT EXISTS log_%04d%02d%02d (log_index INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY, detected_no INT(6), detected_name VARCHAR(50), time TIMESTAMP, action INT(1), detail VARCHAR(255), src_ip VARCHAR(15), packet_bin VARBINARY(1520), level INT(1)) PARTITION BY RANGE (log_index) (PARTITION p0 VALUES LESS THAN (1000), PARTITION p1 VALUES LESS THAN (2000), PARTITION p2 VALUES LESS THAN (3000), PARTITION p3 VALUES LESS THAN MAXVALUE)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return 1;
    }

	return 0;
}

int IpsLog::insert_log(u_char *packet, packet_t *p, rule_t *rule){

	char query[2048];
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	struct in_addr *ip_src = (struct in_addr*)&p->sip;

    char hex[p->caplen * 2 + 1];
    bin_to_hex(packet, p->caplen, hex);

	sprintf(query, "INSERT INTO log_%04d%02d%02d (detected_no, detected_name, time, action, detail, src_ip, packet_bin, level) VALUES (%d, '%s', NOW(), %d, '%s', '%s', '%s', %d)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, rule->rid, rule->deName, rule->action, "test detected", inet_ntoa(*ip_src), hex, rule->level);

	if (mysql_query(conn, query)) {
    	fprintf(stderr, "%s\n", mysql_error(conn));
    	return 1;
	}

	return 0;
}

static void bin_to_hex(const u_char *bin, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", bin[i]);
    }
}
