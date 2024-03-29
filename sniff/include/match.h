#ifndef __MATCH_H_
#define __MATCH_H_

#include <sys/types.h>
#include <regex.h>

#include "packet.h"
#include "dbms_ips.h"
#include "policy.h"
#include "session.h"

#define MAX_REG_NUM 3
/*
 *	MAX_CONTENT_LEN		1024	content안에 들어가는 signature의 최대 길이
 *	MAX_RULE_STR_LEN	2048	1개의 룰의 최대 bytes수
 *	MAX_RULE_NUMBER		1025	최대 룰 개수
 */

typedef struct {
	int 			count;											// REG_NUM의 개수
	unsigned int	rid;											// 탐지 룰 번호
	char			deName[MAX_STR_LEN];							// 탐지 룰 이름
	unsigned int	srcIp;											// 탐지 IP
	unsigned int	to_srcIp;										// 범위 기반시 마지막 IP
	unsigned short	srcPort;										// 탐지 PORT
	unsigned short	to_srcPort;										// 범위 기반시 마지막 Port
	char			content[MAX_REG_NUM][MAX_RULE_STR_LEN];			// 탐지 룰 content[탐지 룰 개수][탐지 룰 형식]
	unsigned int	action;											// 행동유형
	unsigned int	level;											// 위험순위
	char			detail[MAX_STR_LEN];
	regex_t			regex[MAX_REG_NUM];								// 정규식
	unsigned int	dstIp;											// 탐지대상 IP

	unsigned int	base_size;										// 제한 사이즈 
	unsigned int 	base_limit;										// 제한 수
	unsigned int 	base_time;										// 기준 초
}rule_t;

typedef struct{

	u_int			sessionInfo;
	u_int			rid;
	time_t			matchTime;
}matchSession_t;

class IpsMatch {
	
	rule_t 				m_astRules[MAX_RULE_NUMBER];
	int					m_ruleCnt;
	matchSession_t		m_astMatchSession[MAX_SESSION_NUM];		

	private:

	public:

		IpsMatch(){
			memset(m_astRules, 0, sizeof(m_astRules));
			m_ruleCnt = 0;
			memset(m_astMatchSession, 0, sizeof(m_astMatchSession));
		}

		~IpsMatch(){
			for(int i = 0 ; i < MAX_RULE_NUMBER ; i++){
				for(int j = 0 ; j < MAX_REG_NUM ; j++){
					regfree(&m_astRules[i].regex[j]);
				}
			}
		}
		
		int is_read_rules(MYSQL_RES *result);
		int is_compile_rule();
		int ruleFilter(packet_t *p, u_char *pdata);
		void printf_rules();
		int setRules(int e_field_name, char *value, int nIndex);
		int convertValue(char *field, char *szValue, int nIndex);
		int compareSession(int nIndex, packet_t *p);
		rule_t* getRule(int nIndex); 
		void preBuildContent(char *pTmp, int nDataSize, char *pContent);
		int is_check_matchSession(packet_t *p, int nIndex);
		void inValue(int nIndex, int e_field_name, int value);
		void inIPValue(int nIndex, int e_field_name, u_int value);
		void inStrValue(int nIndex, int e_field_name, char *value);
		void inContentValue(int nIndex, int e_field_name, char *value);
		int sessionFilter(packet_t *p);
};

int preBuildData(packet_t *p, u_char *pPacket, int nDataSize, int nOffset);
void decoding(const char *utf8, char *reseult);

#endif
