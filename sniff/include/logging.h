#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <mysql.h>
#include <stdio.h>
#include <time.h>
#include <queue>

#include "policy.h"
#include "match.h"

#define MAX_IPADD_LEN 15
#define MAX_PORT_LEN 5
#define MAX_LOG_SIZE 10

typedef struct {

	char logIp[MAX_IPADD_LEN];
	char logPort[MAX_PORT_LEN];
	char user[MAX_STR_LEN];
	char password[MAX_STR_LEN];
	char dbName[MAX_STR_LEN];

}log_db_info;

typedef struct {

	char		logQuery[MAX_LOG_SIZE][0xFFFF];
	int			rear;
	int			front;

} logQueue_t;


class IpsLog {

	log_db_info 	l_info;
	MYSQL 			*conn;
	logQueue_t		m_logQueue;
	

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
		int logEnqueue(u_char *packet, packet_t *p, int ruleIndex);
		int close_log_db();
		int conn_policy();
		int read_policy();
		int create_policy();
		void logDequeue();
		int is_empty_logQueue();
};



#endif
