/// Complie: gcc -Wall -o getdbinfo getdbinfo.c  -lmysqlclient -L/usr/lib/mysql -I/usr/include/mysql -D__FUNCTION_TEST__

#ifndef _GETDBINFO_H_
#define _GETDBINFO_H_

#include <stdio.h>
#include <string.h>

#define DEFAULT_MySQL_DB        "dbsafer"        /// DBSAFER 2.0 �� database
#define DEFAULT_MySQL_DB_DS3    "dbsafer3"       /// DBSAFER 3.0 �� database
#define DEFAULT_MySQL_DB_WAS    "wassafer4"      /// WASSAFER �� database

#define DEFAULT_MySQL_PORT       3306            /// MySQL ���� ��Ʈ
#define SVC_CONF                ".dbsafer.conf"  /// MySQL DB ������ �ִ� ����
#define ENCODE_MASK_KEY         0x9c             /// Encoding/Decoding mask key
#define TYPE_CONFIGURE_SET1     1                /// ���� ���� ������ Ÿ��
#define TYPE_CONFIGURE_SET2     2                /// ���� �� ������  Ÿ��

#define MAX_HOST_NAME_LEN       35

/// MySQL���� ����.
typedef struct _CONFIGURE_SET_T 
{
	char host[MAX_HOST_NAME_LEN];         ///< ���� ���� host��.
	char dbusr[80];        ///< DBMS ID.
	char dbpass[80];       ///< DBMS �н�����.
} CONFIGURE_SET_T;

/// MySQL���� ����2.
typedef struct _CONFIGURE_SET2_T 
{
	CONFIGURE_SET_T base;  ///< MySQL IP/ID/Password ���� 
	char port[11];         ///< ���� ��Ʈ
	char db[35];           /// DB��
	char unix_socket[80];  /// Unix socket��.
} CONFIGURE_SET2_T;


void Enc_Data(char *paBuff, int nLen);
int GetDbInfoFromConf(CONFIGURE_SET2_T *pstConfig);

#endif
