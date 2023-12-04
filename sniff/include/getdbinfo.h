/// Complie: gcc -Wall -o getdbinfo getdbinfo.c  -lmysqlclient -L/usr/lib/mysql -I/usr/include/mysql -D__FUNCTION_TEST__

#ifndef _GETDBINFO_H_
#define _GETDBINFO_H_

#include <stdio.h>
#include <string.h>

#define DEFAULT_MySQL_DB        "dbsafer"        /// DBSAFER 2.0 용 database
#define DEFAULT_MySQL_DB_DS3    "dbsafer3"       /// DBSAFER 3.0 용 database
#define DEFAULT_MySQL_DB_WAS    "wassafer4"      /// WASSAFER 용 database

#define DEFAULT_MySQL_PORT       3306            /// MySQL 서비스 포트
#define SVC_CONF                ".dbsafer.conf"  /// MySQL DB 정보가 있는 파일
#define ENCODE_MASK_KEY         0x9c             /// Encoding/Decoding mask key
#define TYPE_CONFIGURE_SET1     1                /// 개선 이전 버전의 타입
#define TYPE_CONFIGURE_SET2     2                /// 개선 후 버전의  타입

#define MAX_HOST_NAME_LEN       35

/// MySQL접속 정보.
typedef struct _CONFIGURE_SET_T 
{
	char host[MAX_HOST_NAME_LEN];         ///< 접속 서버 host명.
	char dbusr[80];        ///< DBMS ID.
	char dbpass[80];       ///< DBMS 패스워드.
} CONFIGURE_SET_T;

/// MySQL접속 정보2.
typedef struct _CONFIGURE_SET2_T 
{
	CONFIGURE_SET_T base;  ///< MySQL IP/ID/Password 정보 
	char port[11];         ///< 접속 포트
	char db[35];           /// DB명
	char unix_socket[80];  /// Unix socket명.
} CONFIGURE_SET2_T;


void Enc_Data(char *paBuff, int nLen);
int GetDbInfoFromConf(CONFIGURE_SET2_T *pstConfig);

#endif
