#ifndef __MATCH_H__
#define __MATCH_H__

#include "match.h"
#include "session.h"

char *rule_field_name[] {
	"detected_no",
	"detected_name",
	"content1",
	"content2",
	"content3",
	"enable",
	"src_ip",
	"src_port",
	"action",
	"level",
	"base_time",
	"base_limit",
	"end_time",
	"detail",
	"to_sip",
	"to_sp",
	"dst_ip",
	"base_size"
};

typedef enum {

	detected_no = 0,
	detected_name,
	content1,
	content2,
	content3,
	enable,
	src_ip,
	src_port,
	action,
	level,
	base_time,
	base_limit,
	end_time,
	detail,
	to_sip,
	to_sp,
	dst_ip,
	base_size

} e_field_name;

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
int IpsMatch::is_read_rules(MYSQL_RES* result){

	/*
	 *	rfp 		파일 포인터
	 *	ruleBuf		룰 파일의 한 줄을 임시로 담을 공간
	 *	index		field별로 자르기 위한 주소
	 *	ruleCount	룰의 index
	 */
	MYSQL_ROW row;
	m_ruleCnt = 0;
	int nRuleFieldSize = 0;
	memset( m_astRules, 0, sizeof(m_astRules) );
	nRuleFieldSize = sizeof(rule_field_name) / sizeof(rule_field_name[0]);

	//	룰 읽기
	while( (row = mysql_fetch_row(result)) != NULL ){

		int i = 0;
		
		// enable이 0이면 룰 읽지 않음
		if( atoi(row[5]) == 0 ){
			continue;
		}
		
		// 룰 Line의 값을 필드별로 찾아서 변환하여 입력
		for( i = 0 ; i < nRuleFieldSize ; i++){
			setRules(i, row[i], m_ruleCnt ); 
		}

		//	다음 룰 담을 공간이동
		m_ruleCnt++;
	}
	return 1;
}

int IpsMatch::sessionFilter(packet_t *p){

	for( int i = 0 ; i < m_ruleCnt ; i++ ){
		if( m_astRules[i].count == 0 ){
			if( compareSession(i, p) > 0 ){
				return i;
			}
		}
	}

	return -1;
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
int IpsMatch::setRules(int e_field_name, char *value, int nIndex){

	if( !value || e_field_name < 0 || nIndex < 0 )
		return -1;

	switch ( e_field_name ){

		//	일반 숫자
		case detected_no:
		case src_port:
		case action:
		case level:
		case base_time:
		case base_limit:
		case to_sp:
		case base_size:
			inValue(nIndex, e_field_name, atoi(value));
			return 0;

		//	IP유형
		case src_ip:
		case to_sip:
		case dst_ip:
			inIPValue(nIndex, e_field_name, inet_addr(value));
			return 0;

		//	일반 text
		case detected_name:
			inStrValue(nIndex, e_field_name, value);
			return 0;
		
		//	인코딩된 text
		case content1:
		case content2:
		case content3:
			inContentValue(nIndex, e_field_name, value);
	}

	return 0;
}

void decoding(const char *input, char *output) {
	
	size_t len = strlen(input);
    size_t j = 0;

    for (size_t i = 0; i < len; ++i) {
        if (input[i] == '+') {
            output[j++] = ' ';
        } else if (input[i] == '%' && i + 2 < len) {
            int hex_value;
            sscanf(input + i + 1, "%2x", &hex_value);
            output[j++] = (char)hex_value;
            i += 2;
        } else {
            output[j++] = input[i];
        }
    }

    output[j] = '\0';
}

void IpsMatch::inContentValue(int nIndex, int e_field_name, char *value){

	char pTmp[MAX_STR_LEN] = "";

	switch( e_field_name ){
		
		case content1:
			decoding(value, pTmp);
			if( pTmp[0] == '^' ){
				memcpy( m_astRules[nIndex].content[0], pTmp, sizeof(pTmp)-1 );
			}
			else{
				preBuildContent( pTmp, strlen(pTmp), m_astRules[nIndex].content[0] ); 
			}
			
			m_astRules[nIndex].count = 1;
			return;
		
		case content2:
			decoding(value, pTmp);
			if( pTmp[0] == '^' ){
				memcpy( m_astRules[nIndex].content[0], pTmp, sizeof(pTmp)-1 );
			}
			else{
				preBuildContent( pTmp, strlen(pTmp), m_astRules[nIndex].content[1] ); 
			}
			
			m_astRules[nIndex].count++;
			return;

		case content3:
			decoding(value, pTmp);
			if( pTmp[0] == '^' ){
				memcpy( m_astRules[nIndex].content[0], pTmp, sizeof(pTmp)-1 );
			}
			else{
				preBuildContent( pTmp, strlen(pTmp), m_astRules[nIndex].content[2] ); 
			}
			
			m_astRules[nIndex].count++;
			return;

	}
}

void IpsMatch::inStrValue(int nIndex, int e_field_name, char *value){

	switch( e_field_name ){
		
		case detected_name:
			memcpy( m_astRules[nIndex].deName, value, strlen(value) ); 
			return;
	}
}

/*
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
*/

void IpsMatch::inIPValue(int nIndex, int e_field_name, u_int value){

	switch ( e_field_name ){
		
		case src_ip:
			m_astRules[nIndex].srcIp = value;
			return;

		case dst_ip:
			m_astRules[nIndex].dstIp = value;
			return;
	
		case to_sip:
			m_astRules[nIndex].to_srcIp = value;

	}
}

void IpsMatch::inValue(int nIndex, int e_field_name, int value){

	switch( e_field_name ) {
		
		case detected_no:
			m_astRules[nIndex].rid = value;
			return;

		case src_port:
			m_astRules[nIndex].srcPort = value;
			return;

		case base_limit:
			m_astRules[nIndex].base_limit = value;
			return;

		case base_time:
			m_astRules[nIndex].base_time = value;
			return;

		case to_sp:
			m_astRules[nIndex].to_srcPort = value;
			return;

		case action:
			m_astRules[nIndex].action = value;
			return;
	
		case level:
			m_astRules[nIndex].level = value;
			return;

		case base_size:
			m_astRules[nIndex].base_size = value;
	}
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
		if( *(pTmp+i) < 32 || (*(pTmp+i) >= 33	&& *(pTmp+i) <= 47) || (*(pTmp+i) >= 58 && *(pTmp+i) <= 64) ||
 			*(pTmp+i) == 91 || (*(pTmp+i) >= 93 && *(pTmp+i) <= 96) || *(pTmp+i) >= 123){
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

	int base = 0;
	int match = 0;

	if( m_astRules[nIndex].srcPort ){
		base++;
	}

	if( m_astRules[nIndex].to_srcPort){
		base+=10;
	}

	if( m_astRules[nIndex].srcIp ){
		base+=100;
	}

	if( m_astRules[nIndex].to_srcIp){
		base+=1000;
	}
		

	// port가 설정되어있는 경우
	if( m_astRules[nIndex].srcPort ){
		//	port가 범위일 경우
		if( m_astRules[nIndex].to_srcPort != 0 ){
			if( p->sp > m_astRules[nIndex].srcPort && p->sp <= m_astRules[nIndex].to_srcPort){
				match+=11;
			}
		}

		if( m_astRules[nIndex].srcPort == p->sp ){
			match++;
		}
	}
	
	//	ip가 설정되어있는 경우
	if( m_astRules[nIndex].srcIp ){
		//	ip가 범위일경우
		if( m_astRules[nIndex].to_srcIp != 0 ){
			if( p->sip > m_astRules[nIndex].srcIp && p->sip <= m_astRules[nIndex].to_srcIp){
				match+=1100;
			}
		}

		if( m_astRules[nIndex].srcIp == p->sip ){
			match+=100;
		}
	}

	if( base == match){
		return match;
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
	
	if( difftime( curTime, m_astMatchSession[sessionIndex].matchTime ) <= 60 ){
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

	if( !p || !pPacket || nDataSize == 0 )
		return -1;

    for (i = 0 ; i < nDataSize; i++)
	{
		if( pPacket[i+nOffset] >= 127 || pPacket[i+nOffset] < ' ' ){
			p->nocase[i] = ' ';
			continue;
		}
		p->nocase[i] = pPacket[i+nOffset];
		// 알파벳 전부 소문자로
		if( p->nocase[i] >= 65 && p->nocase[i] <= 90 ){
			p->nocase[i] = p->nocase[i] + 32;
		}
    }
	p->nocase[nDataSize] = '\0';

    // 연속적인 공백을 하나의 공백으로 바꿉니다.
	for( i = 0 ; i < nDataSize ; i++ ){
		if( p->nocase[i] == ' ' && p->nocase[i+1] == ' '){
			for(int j = 0 ; j < nDataSize ; j++){
				p->nocase[i+j] = p->nocase[i+1+j];
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
	
	for(int i = 0 ; i < m_ruleCnt ; i++){
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
