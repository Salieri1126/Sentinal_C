#ifndef __LOG_H__
#define __LOG_H__

#include <mysql.h>
#include <stdio.h>
#include <time.h>

#include "policy.h"
#include "match.h"

#define MAX_IPADD_LEN 15
#define MAX_PORT_LEN 5


typedef struct {

	char logIp[MAX_IPADD_LEN];
	char logPort[MAX_PORT_LEN];
	char user[MAX_STR_LEN];
	char password[MAX_STR_LEN];
	char dbName[MAX_STR_LEN];

}log_db_info;


class IpsLog {

	log_db_info l_info;
	MYSQL *conn;

	private:
	
	public:

		IpsLog(){
			memset(&l_info, 0, sizeof(log_db_info));
		}

		~IpsLog(){
			mysql_close(conn);
		}

		int is_read_logInfo();
		int connect_db();
		int printLog();
		int create_log();
		int insert_log(u_char *packet, packet_t *p, int ruleIndex);
		int close_log_db();
};



#endif
