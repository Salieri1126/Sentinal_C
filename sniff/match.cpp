#ifndef __MATCH_H__
#define __MATCH_H__

#include "match.h"
#include "session.h"

char *rule_field_name[] = {
	"rid",
 	"deName",
 	"srcIp",
 	"srcPort",
 	"content",
	"base_time",
	"base_limit"
};

extern IpsSession testSes;

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
			if( setRules(index, rule_field_name[i], ruleCount) )
				continue;
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
	
	separator_pos = strstr(field_value_pos, ":");
	
	strncpy(szValue, field_value_pos, separator_pos == NULL ? strlen(field_value_pos) : strlen(field_value_pos)-strlen(separator_pos));

	strim_both(szValue);
	//	필드별로 맞춰서 넣기
	convertValue(field, szValue, nIndex);

	return 0;
}

int IpsMatch::convertValue(char *field, char *szValue, int nIndex){
	
	if( !field || !szValue )
		return 1;

	if(!strcmp(field, "rid") || !strcmp(field, "srcPort") || !strcmp(field, "base_limit") || !strcmp(field, "base_time")){
		if( !strcmp(szValue, "any") )
			szValue = "0";
		inValue(nIndex, field, atoi(szValue));
	}

	if ( !strcmp(field, "srcIp") ){
		if( !strcmp(szValue, "any") ){
			szValue = "0";
		}
		m_astRules[nIndex].srcIp = inet_addr(szValue);
	}

	if( !strcmp(field, "deName") )
		strncpy( m_astRules[nIndex].deName, szValue, strlen(szValue));

	if( !strcmp(field, "content") ){
		
		char *conSepPos = NULL;

		while( (conSepPos = strstr( szValue, ",") ) != NULL){
			char tmpContent[MAX_STR_LEN] = "";
			strncpy( tmpContent, szValue, strlen(szValue)-strlen(conSepPos));
			szValue = szValue+strlen(tmpContent)+1;
			strim_both(tmpContent);
			strncpy( m_astRules[nIndex].content[m_astRules[nIndex].count], tmpContent, strlen(tmpContent) );
			m_astRules[nIndex].count++;
		}
		strncpy( m_astRules[nIndex].content[m_astRules[nIndex].count], szValue, strlen(szValue));
		strim_both( m_astRules[nIndex].content[m_astRules[nIndex].count] );
		m_astRules[nIndex].count++;
	}

	return 0;
}

void IpsMatch::inValue(int nIndex, char *field, int value){
	
	if( !strcmp(field, "rid") )
		m_astRules[nIndex].rid = value;
	

	if(	!strcmp(field, "srcPort") )
		m_astRules[nIndex].srcPort = value;

	if( !strcmp(field, "base_limit") )
		m_astRules[nIndex].base_limit = value;
	
	if ( !strcmp(field, "base_time") )
		m_astRules[nIndex].base_time = value;
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
 */
int IpsMatch::is_compile_rule(){

	for (int i = 0; i < MAX_RULE_NUMBER; i++) {
		//	content가 없는 곳은 skip
		if(m_astRules[i].count == 0)
			continue;

		for(int j = 0 ; j < m_astRules[i].count; j++){
			if ( regcomp(&(m_astRules[i].regex[j]), m_astRules[i].content[j], (REG_EXTENDED | REG_ICASE)) != 0 ) {
            	return 0;
        	}
		}
    }
	return 1;
}

/*
 *! \brief 
 *		IpsMatch의 rule과 packet을 비교하여 rule에 일치하는 packet을 찾는 함수
 *	\param
 *		p		: packet_t 구조체 포인터
 *		pdata	: 가공된 payload
 *	\return
 *		0 : rule에 맞는 packet 매칭 실패
 *		1 : rule에 맞는 packet 매칭 성공
 *	\detail
 *		IP와 Port를 비교하여 rule에 맞는 IP와 Port가 매칭되었을때 content까지 안보고 매칭 성공
 *		IP와 Port가 다를때는 저장된 content와 비교하여 매칭되었을때 매칭된 ruleName을 출력
 */
int IpsMatch::ruleFilter(packet_t *p, u_char *pdata){

	int match = 0;
	std::map<session_t, u_int>::iterator itr;

	for( int i = 0 ; i < MAX_RULE_NUMBER ; i++){
		if( m_astRules[i].srcIp == p->sip){
			printf("detection IP & Port : ");
			return 1;
		}

		if( m_astRules[i].count == 0 )
			continue;

		for( int j = 0 ; j < m_astRules[i].count ; j++){
			if( regexec(&(m_astRules[i].regex[j]), (char *)pdata, 0, NULL, 0) == 0 ){
				match = 1;
			}
		}

		if( match ){

			itr = testSes.existSession(p);
				//	Select찾았으면 기준 시간 지났는지 확인
			if ( (time(NULL)-itr->first.s_time) > m_astRules[i].base_time) {
				//	지났으면 Session의 cnt 초기화, time 초기화 후 cnt++
				//	안지났으면 Session의 cnt++
				//	기준 Cnt 보다 큰지 확인
				itr->second = 0;
				testSes.timeInit(itr);
			}
			itr->second++;
			if( itr->second > m_astRules[i].base_limit) {
				//	cnt가 기준 Cnt보다 크면 행동 패턴 공격 탐지
				//	cnt가 기준 Cnt보다 작으면 종료
				printf("(deName : %s) ", m_astRules[i].deName);
				printf("(count : %d) ", itr->second);
				return 1;
			}
		}
	}
	return 0;
}

/*
 *! \brief 
 *		packet에 들어오는 payload를 변환하는 함수
 *	\param
 *		pPacket		: 가공되기 전의 packet
 *		nDataSize	: payload의 size
 *	\return
 *		tmp : 가공된 payload
 *	\detail
 *		packet에 들어오는 payload를 정규식과 비교하기 위해
 *		가공하여 문자와 숫자가 아닌 부분을 공란으로 처리하여
 *		payload를 반환
 */
u_char *preBuildData(u_char *pPacket, int nDataSize){

	u_char *tmp = (u_char *)malloc(nDataSize);
	memset(tmp, 0, nDataSize);
	memcpy(tmp, pPacket+54, nDataSize); 
	
	for(int i = 0 ; i < nDataSize ; i++){
		tmp[i] = ( tmp[i] > 127 || tmp[i] < ' ' ) ? ' ' : tmp[i];
	}
	
	return tmp;
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

rule_t* IpsMatch::getRules(){
	return m_astRules;
}

#endif
