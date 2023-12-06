#include "session.h"
#include "match.h"

/*
 *!\brief
 *		세션 확인 함수
 * \param
 *		p : 캡쳐 패킷
 * \return
 *		0 : 세션 확인 성공
 *		1 : 세션 확인 실패
 * \detail
 * 		- 관리 중인 세션일 경우
 * 			- FIN or RST 패킷일 경우 세션 삭제
 * 			- FIN or RST 패킷이 아닐경우 세션 cnt++
 * 		- 관리 중인 세션이 아닐 경우 세션 추가
 */
int IpsSession::checkSession(packet_t *p){

	if( !p || p->reverse_flow == -1 )
		return 1;

	sItr = m_astSession.begin();

	if( (sItr = m_astSession.find(	makeSession(p) )) != m_astSession.end() ){
		if( ((p->tcph->th_flags & R_FIN) || (p->tcph->th_flags & R_RST)) ) {
			m_astSession.erase(sItr);
			return 0;
		}
		sItr->second.session_cnt++;
		sItr->second.s_time = time(NULL);
		return 0;
	}

	if( p->reverse_flow == 0 && (p->tcph->th_flags & R_SYN) ){
		if( addSession(p) ){
			printf("Session Add Fail!\n");
			return 1;
		}
	}

	return 0;
}

/*
 *!\brief
 *		세션 추가 함수
 * \param
 *		p : 캡쳐 패킷
 * \return
 *		0 : 세션 추가 성공
 *		1 : 세션 추가 실패
 */
int IpsSession::addSession(packet_t *p){

	if( !p )
		return 1;

	session_t tmpSes = makeSession(p);	
	
	session_value tmpVal;

	memset(&tmpVal, 0, sizeof(session_value));

	tmpVal.s_time = time(NULL);
	tmpVal.session_cnt++;
	
	m_astSession.insert(std::make_pair(tmpSes, tmpVal));

	return 0;
}

/*
 *!\brief
 *		세션 확인하는 함수
 * \param
 *		p : 들어오는 패킷의 정보
 * \return
 *		0 : 함수 종료 
 */
int IpsSession::printSession(){

	while(1){

		if( m_astSession.empty() )
			continue;

		sleep(60);

		struct in_addr *ip_src;
		struct in_addr *ip_dst;
	
		for( sItr = m_astSession.begin() ; sItr != m_astSession.end() ; sItr++ ){
			time_t tmpTime = time(NULL);
			struct tm ses_t;
			struct tm cur_t;

			ses_t = *localtime(&sItr->second.s_time);
			cur_t = *localtime(&tmpTime);
			ip_src = (struct in_addr*)(&(sItr->first.sip));
			ip_dst = (struct in_addr*)(&(sItr->first.dip)); 
			
			if( difftime(tmpTime,(sItr->second.s_time)) <= 120 ){
				printf("/------------ Session --------------/\n");
				printf("Source IP : %s\n", inet_ntoa(*ip_src));
				printf("Source Port : %d\n", sItr->first.sp);
				printf("Destiny IP : %s\n", inet_ntoa(*ip_dst));
				printf("Destiny Port : %d\n", sItr->first.dp);
				printf("Session Count : %d\n", sItr->second.session_cnt);
				printf("Make Session time : %04d.%02d.%02d %02d:%02d:%02d\n", ses_t.tm_year+1900, ses_t.tm_mon+1, ses_t.tm_mday, ses_t.tm_hour, ses_t.tm_min, ses_t.tm_sec);
				printf("Current time : %04d.%02d.%02d %02d:%02d:%02d\n", cur_t.tm_year+1900, cur_t.tm_mon+1, cur_t.tm_mday, cur_t.tm_hour, cur_t.tm_min, cur_t.tm_sec);
				printf("/-----------------------------------/\n\n");
			}
		}
	}
		
	return 0;
}

/*! brief
 * 		존재하는 세션의 위치 출력
 * 	\param
 * 		packet_t* p : 캡쳐 패킷
 * 	\return iterator 세션의 iterator 출력
 */
std::map<session_t, session_value>::iterator IpsSession::existSession(packet_t* p){
	
	std::map<session_t, session_value>::iterator sItr;

	sItr = m_astSession.find(makeSession(p));

	return sItr;
}

/*! brief
 * 		캡쳐 패킷으로 세션형태로 변환
 *	\param
 *		packet_t* p : 캡쳐 패킷
 *	\return session_t
 *		캡쳐 패킷으로 생성한 Session
 */
session_t IpsSession::makeSession(packet_t *p){

	session_t tmpSes;	
	tmpSes.sip = p->sip;
	tmpSes.sp = p->sp;
	tmpSes.dip = p->dip;
	tmpSes.dp = p->dp;

	return tmpSes;
}

void* IpsSession::printSessionWrapper(void* context) {
	return reinterpret_cast<void*>(static_cast<IpsSession*>(context)->printSession());
}
