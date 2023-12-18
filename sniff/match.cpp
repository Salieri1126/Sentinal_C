#ifndef __MATCH_H__
#define __MATCH_H__

#include "match.h"
#include "session.h"

char *rule_field_name[] {
	"dNum",
	"dName",
	"sIP",
	"sPort",
	"to_sPort",
	"to_sIP",
	"content",
	"base_time",
	"base_count",
	"dIP",
	"dPort",
	"base_size",
	"action",
	"level"
};

extern IpsSession sess;

void preBuildContent( char *pContent, int nDataSize );
/*
 *! \brief 
 *		룰 파일에서 룰을 읽어서 rule_t 구조체에 저장하는 함수
 *	\param
 *		룰을 담은 파일명
 *	\return
 *		1 : 룰 파일을 못 찾으면 실패
 *		0 : 룰 파일에서 모든 변수를 구조체에 담는 것이 성공
 *	\detail
 *		룰 ID가 없으면 룰을 적용시키지 않음
 */
int IpsMatch::is_read_rules(char *fileName){

	/*
	 *	rfp 		파일 포인터
	 *	ruleBuf		룰 파일의 한 줄을 임시로 담을 공간
	 *	index		field별로 자르기 위한 주소
	 *	ruleCount	룰의 index
	 */
	FILE *rfp = NULL;
	char ruleBuf[MAX_STR_LEN];
	char *index = NULL;
	int ruleCount = 0;
	int nRuleFieldSize = 0;

	nRuleFieldSize = sizeof(rule_field_name) / sizeof(rule_field_name[0]);
	//	파일 열기
	rfp = fopen(fileName, "r");
	if(!rfp){
		printf("Rule File not Found\n");
		return 1;
	}

	//	룰 읽기
	while( fgets( ruleBuf, sizeof(ruleBuf)-1, rfp) != NULL ){

		int i = 0;
		index = ruleBuf;

		//	룰이 적혀진 줄에서 앞부분 공백 제거
		while ( *index != '\0' && ( *index == '\t' || *index == ' ' ) ){
			index++;
		}

		//	룰이 적혀진 줄에 # 주석처리된 줄과 빈 줄 제외
		if( *index == '#' || strlen( index ) < 1 )
			continue;

		//	룰이 적혀진 줄에서 가져오기
		for( i = 0 ; i < nRuleFieldSize ; i++){
			if( setRules(index, rule_field_name[i], ruleCount) ){
				m_ruleCnt++;
				continue;
			}
		}
		//	다음 룰 담을 공간이동
		ruleCount++;
	}
	return 1;
}

/*
 *! \brief
 *		룰 파일에서 룰을 가져오기 위한 함수
 *	\param
 *		ruleLine : 하나의 룰을 저장하고 있는 줄
 *		field : 룰의 필드의 이름
 *	\return
 *		0 : 룰 파일 read 성공
 *		1 : 룰 파일 read 실패
 *	\detail
 *		룰의 ID번호가 존재하지 않으면 그 룰은 없는 룰
 */
int IpsMatch::setRules(char *ruleLine, char *field, int nIndex){

	if( !ruleLine || !field )
		return 1;

	char szValue[MAX_STR_LEN] = "";
	char *field_pos = NULL;
	char *field_value_pos = NULL;
	char *separator_pos = NULL;

	field_pos = strstr(ruleLine, field);

	if(field_pos == NULL)
		return 1;

	field_value_pos = strstr(field_pos, "=")+1;

	if( !strcmp(field, "content") ){
		separator_pos = NULL;
	}
	else{
		separator_pos = strstr(field_value_pos, " ");
	}


	memcpy(szValue, field_value_pos, separator_pos == NULL ? strlen(field_value_pos)+1 : strlen(field_value_pos)-strlen(separator_pos)+1);

	//	필드별로 맞춰서 넣기
	convertValue(field, szValue, nIndex);

	return 0;
}

int IpsMatch::convertValue(char *field, char *szValue, int nIndex){

	if( !field || !szValue )
		return 1;

	if(!strcmp(field, "dNum") || !strcmp(field, "sPort") || !strcmp(field, "base_count") || !strcmp(field, "base_time")
			|| !strcmp(field, "to_sPort") ){
		if( !strcmp(szValue, "any") )
			szValue = "0";
		inValue(nIndex, field, atoi(szValue));
	}

	if ( !strcmp(field, "sIP") || !strcmp(field, "dIP") || !strcmp(field, "to_sIP") ){
		if( !strcmp(szValue, "any") ){
			szValue = "0";
		}
		inIPValue(nIndex, field, inet_addr(szValue));
	}

	if( !strcmp(field, "dName") ){
		strim_both(szValue);
		memcpy( m_astRules[nIndex].deName, szValue, strlen(szValue));
	}

	if( !strcmp(field, "content") ){

		char *conSepPos = NULL;
		char tmpContent[MAX_STR_LEN] = "";

		while( (conSepPos = strstr( szValue, ",") ) != NULL){
			memset( tmpContent, 0, sizeof(tmpContent) );
			memcpy( tmpContent, szValue, strlen(szValue)-strlen(conSepPos));
			szValue = szValue + strlen(tmpContent)+1;
			cutdp_both(tmpContent);
			if( strstr(tmpContent, "\\") != NULL ){
				memcpy( m_astRules[nIndex].content[m_astRules[nIndex].count++], tmpContent, strlen(tmpContent) );
				continue;
			}
			preBuildContent( tmpContent, sizeof(tmpContent) , m_astRules[nIndex].content[m_astRules[nIndex].count++]);
		}

		cutdp_both(szValue);
		if( strstr(szValue, "\\") != NULL ){
			memcpy( m_astRules[nIndex].content[m_astRules[nIndex].count++], szValue, strlen(szValue)+1 );
			return 0;
		}
		preBuildContent( szValue, strlen(szValue), m_astRules[nIndex].content[m_astRules[nIndex].count++] );
	}

	return 0;
}

void IpsMatch::cutdp_both(char *text){

	int i = strlen(text);
	while( *(text+i) != '\"'){
		i--;
	}
	*(text+i) = '\0';

	if( *(text) == '\"' ){
		memcpy( text, text+1, strlen(text) );
	}

}
void IpsMatch::inIPValue(int nIndex, char *field, u_int value){

	if( !strcmp(field, "sIP") )
		m_astRules[nIndex].srcIp = value;

	if( !strcmp(field, "dIP") )
		m_astRules[nIndex].dstIp = value;
	
	if( !strcmp(field, "to_sIP") )
		m_astRules[nIndex].to_srcIp = value;
}

void IpsMatch::inValue(int nIndex, char *field, int value){

	if( !strcmp(field, "dNum") )
		m_astRules[nIndex].rid = value;

	if(	!strcmp(field, "sPort") )
		m_astRules[nIndex].srcPort = value;

	if( !strcmp(field, "base_count") )
		m_astRules[nIndex].base_limit = value;

	if ( !strcmp(field, "base_time") )
		m_astRules[nIndex].base_time = value;

	if ( !strcmp(field, "to_sPort") )
		m_astRules[nIndex].to_srcPort = value;
}

/*
 *! \brief 
 *		구조체에 담은 content로 정규표현으로 사용하기 위해 컴파일 하는 함수
 *	\param
 *	\return
 *		0 : 컴파일 실패
 *		1 : 컴파일 성공
 *	\detail
 *		content가 없는 곳은 skip하고 content가 있는 만큼만 regcomp한다.
/*/
int IpsMatch::is_compile_rule(){

	for (int i = 0; i < m_ruleCnt; i++) {
		//	content가 없는 곳은 skip
		if(m_astRules[i].count == 0)
			continue;

		for(int j = 0 ; j < m_astRules[i].count; j++){
			if ( regcomp(&(m_astRules[i].regex[j]), m_astRules[i].content[j], (REG_ICASE)) != 0 ) {
				return 0;
			}
		}
	}

	return 1;
}

void IpsMatch::preBuildContent( char *pTmp, int nDataSize, char *pContent){

	int i,j = 0;
	char conTemp[MAX_STR_LEN] = "";

	for(i = 0, j = 0 ; i < nDataSize ; i++,j++){
		if( (*(pTmp+i) >= 33 && *(pTmp+i) <= 47)
		 	|| (*(pTmp+i) >= 58 && *(pTmp+i) <= 64) 
		 	|| (*(pTmp+i) >= 123 && *(pTmp+i) <= 126 )){
			conTemp[j++] = '\\';
			conTemp[j] = *(pContent+i);
		}
		
		conTemp[j] = *(pTmp+i);
	}
	conTemp[j] = '\0';

	memcpy( pContent, conTemp, sizeof(conTemp)-1 );

	return;
}

int IpsMatch::compareSession(int nIndex, packet_t *p){

	
	//	port가 범위일경우
	if( m_astRules[nIndex].to_srcPort != 0 ){
		for( u_short i = m_astRules[nIndex].srcPort ; i <= m_astRules[nIndex].to_srcPort ; i++ ){
			if( i == p->sp ){
				return 1;
			}
		}
	}
	
	//	ip가 범위일경우
	if( m_astRules[nIndex].to_srcIp != 0 ){
		for( u_int i = m_astRules[nIndex].srcIp ; i <= m_astRules[nIndex].to_srcIp ; i++ ){
			if( i == p->sip ){
				return 1;
			}
		}
	}

	// port만 설정되어있는 경우
	if( m_astRules[nIndex].srcPort && (m_astRules[nIndex].srcPort == p->sp) ){
		return 1;
	}
	
	//	ip만 설정되어있는 경우
	if( m_astRules[nIndex].srcIp && (m_astRules[nIndex].srcIp == p->sip) ){
		return 1;
	}

	return 0;	
}

/*
 *! \brief 
 *		IpsMatch의 rule과 packet을 비교하여 rule에 일치하는 packet을 찾는 함수
 *	\param
 *		p		: packet_t 구조체 포인터
 *		pdata	: 가공된 payload
 *	\return
 *		-1 : rule에 맞는 packet 매칭 실패
 *		i : 매칭된 룰의 index 번호 반환
 *	\detail
 *		IP와 Port를 비교하여 rule에 맞는 IP와 Port가 매칭되었을때 content까지 안보고 매칭 성공
 *		IP와 Port가 다를때는 저장된 content와 비교하여 매칭되었을때 매칭된 ruleName을 출력
 */
int IpsMatch::ruleFilter(packet_t *p, u_char *pdata){

	int match = 0;
	
	if(p->flow == 0)
		return -1;

	for(int i = 0 ; i < m_ruleCnt ; i++){
	
		match = 0;
		//	세션 검사가 일치하는지 비교한다
		//	세션 검사가 다를 경우 패턴을 비교할 필요 없다
		if( m_astRules[i].srcPort != 0 || m_astRules[i].srcIp != 0) {
			if( compareSession(i,p) != 0){
				if( m_astRules[i].count == 0 ){
					return i;
				}
			}
		}

		for( int j = 0 ; j < m_astRules[i].count ; j++){
			if( regexec(&(m_astRules[i].regex[j]), (char *)pdata, 0, NULL, 0) == 0 ){
				match++;
			}
		}
		
		if( match != 0 && match == m_astRules[i].count ){

			//	rule중에 행동 탐지 옵션이 없는 것은 패턴만 탐지
			if( m_astRules[i].base_time == 0 || m_astRules[i].base_limit == 0 ){
				return i;
			}

			session_t *be_session;
			be_session = sess.getSession( sess.makeSession(p)%MAX_SESSION_NUM);
			time_t curTime = time(NULL);
			
			//	패턴 찾았으면 기준 시간 지났는지 확인
			if( difftime( curTime,(be_session->behavior_time)) >= m_astRules[i].base_time ){
				//	지났으면 Session의 cnt 초기화, time 초기화 후 cnt++
				be_session->behavior_time = time(NULL);
				be_session->behavior_cnt = 1;
				break;
			}
			//	안지났으면 Session의 cnt++
			be_session->behavior_cnt++;
			//	cnt가 기준 Cnt보다 크면 행동 패턴 공격 탐지
			//TODO:	공격 탐지 후에 차단할 것
			if( be_session->behavior_cnt == m_astRules[i].base_limit){
				return i;
			}
		}
	}
	return -1;
}

int IpsMatch::is_check_matchSession(packet_t *p, int nIndex){
	
	u_int sessionInfo = sess.makeSession(p);
	u_int sessionIndex = sessionInfo%MAX_SESSION_NUM;
	time_t curTime = time(NULL);
	
	if( difftime( curTime, m_astMatchSession[sessionIndex].matchTime ) <= 5 ){
		if( m_astRules[nIndex].rid == m_astMatchSession[sessionIndex].rid ){
			return 1;
		}

		if( sessionInfo == m_astMatchSession[sessionIndex].sessionInfo ){
			return 1;	
		}
	}
	
	m_astMatchSession[sessionIndex].rid = m_astRules[nIndex].rid;
	m_astMatchSession[sessionIndex].sessionInfo = sessionInfo;
	m_astMatchSession[sessionIndex].matchTime = time(NULL);

	return 0;
}

/*
 *! \brief 
 *		packet에 들어오는 payload를 변환하는 함수
 *	\param
 *		p			: 캡쳐 패킷
 *		pPacket		: 가공되기 전의 packet
 *		nDataSize	: payload의 size
 *	\return
 *		int -1	: 오류 실패
 *			0	: 가공 완료
 *	\detail
 *		packet에 들어오는 payload를 정규식과 비교하기 위해
 *		가공하여 문자와 숫자가 아닌 부분을 공란으로 처리하여
 *		payload를 반환
 */

int preBuildData(packet_t *p, u_char *pPacket, int nDataSize, int nOffset)
{
    int i;
	u_char *nocase;
	nocase = p->nocase;

	if( !p || !pPacket || nDataSize == 0 )
		return -1;

    for (i = 0 ; i < nDataSize; i++)
	{
		if( pPacket[i+nOffset] >= 127 || pPacket[i+nOffset] < ' ' ){
			*(nocase+i) = ' ';
			continue;
		}
		*(nocase+i) = pPacket[i+nOffset];
		// 알파벳 전부 소문자로
		if( *(nocase+i) >= 65 && *(nocase+i) <= 90 ){
			*(nocase+i) = *(nocase+i) + 32;
		}
    }
	*(nocase+nDataSize) = '\0';

    // 연속적인 공백을 하나의 공백으로 바꿉니다.
	for( i = 0 ; i < nDataSize ; i++ ){
		if( *(nocase+i) == ' ' && *(nocase+(i+1)) == ' '){
			for(int j = 0 ; j < nDataSize ; j++){
				*(nocase+(i+j)) = *(nocase+(i+1+j));
			}
			i--;
		}
	}

    return 0;
}

/*
 *! \brief 
 *		IpsMatch 클래스의 멤버변수 내용 출력
 *	\param
 *		nIndex : 룰의 인덱스
 *	\return
 *	\detail
 *		룰[인덱스]에 담긴 변수의 내용 출력
 *		 = 담긴 전체 룰 출력
 */
void IpsMatch::printf_rules(){
	
	for(int i = 0 ; i < MAX_RULE_NUMBER ; i++){
		if(m_astRules[i].count == 0)
			continue;
		printf("rule[%d] rid : %d\n"
				"rule[%d] deName : %s\n"
				"rule[%d] srcIp : %x\n"
				"rule[%d] srcPort : %d\n"
				"rule[%d] count : %d\n"
				"rule[%d] base_limit : %d\n"
				"rule[%d] base_time : %d\n", i, m_astRules[i].rid, i, m_astRules[i].deName, i, m_astRules[i].srcIp, i, m_astRules[i].srcPort, i, m_astRules[i].count, i, m_astRules[i].base_limit, i, m_astRules[i].base_time);
		for(int j = 0 ; j < MAX_REG_NUM ; j++){
			printf("rule[%d] content [%d] : %s\n", i, j, m_astRules[i].content[j]);
		}
	}
	return;
}

/*
 *!	\brief
 *		룰 하나 가져오는 함수
 *	\param
 *		int nIndex : 룰의 인덱스
 *	\return
 *		rule_t 구조체
 */
rule_t* IpsMatch::getRule(int nIndex){
	return &m_astRules[nIndex];
}

#endif
