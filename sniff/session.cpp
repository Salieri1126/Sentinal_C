#include "session.h"
#include "match.h"

#define perMimute 60

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

	std::map<session_t, u_int>::iterator sItr;
	
	if( p->reverse_flow == 1 && ((p->tcph->th_flags & R_FIN) || (p->tcph->th_flags & R_RST)) ) {
		delSession(p);
		return 0;
	}
	
	if( (sItr = m_astSession.find(	makeSession(p) )) != m_astSession.end() ){
		sItr->second++;
		return 0;
	}

	if( sItr == m_astSession.end() && p->reverse_flow == 0 && (p->tcph->th_flags & R_SYN) ){
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
	
	tmpSes.s_time = time(NULL);
	
	m_astSession.insert(std::make_pair(tmpSes, 1));

	return 0;
}

/*
 *!\brief
 *		세션 확인하는 함수
 * \param
 *		p : 들어오는 패킷의 정보
 * \return
 *		0 : 
 */
int IpsSession::printSession(){

	while(1){

		if( m_astSession.empty() )
			continue;

		sleep(10);

		struct in_addr *ip_src;
		struct in_addr *ip_dst;
	
		std::map<session_t, u_int>::iterator sItr;
			
		for( sItr = m_astSession.begin() ; sItr != m_astSession.end() ; sItr++ ){
			time_t tmpTime = time(NULL);
			ip_src = (struct in_addr*)(&(sItr->first.sip));
			ip_dst = (struct in_addr*)(&(sItr->first.dip)); 
				
			if( (tmpTime-(sItr->first.s_time)) < 120 ){
				printf("/------------ Session --------------/\n");
				printf("Source IP : %s\n", inet_ntoa(*ip_src));
				printf("Source Port : %d\n", sItr->first.sp);
				printf("Destiny IP : %s\n", inet_ntoa(*ip_dst));
				printf("Destiny Port : %d\n", sItr->first.dp);
				printf("Session Count : %d\n", sItr->second);
				printf("/-----------------------------------/\n\n");
			}
		}
	}
		
	return 0;
}

/*
 *!\brief
 *		세션의 시간 초기화
 * \param
 *		std::map<session_t, u_int>::iterator itr 시간 초기화할 세션의 iterator
 * \return
 *		0 : 시간 초기화 성공
 *		1 : 시간 초기화 실패
 */
int IpsSession::timeInit(std::map<session_t, u_int>::iterator itr){

	if ( itr == m_astSession.end() )
		return 1;

	session_t tmpSes = itr->first;

	tmpSes.s_time = time(NULL);

	m_astSession.erase(itr++);

	m_astSession.insert(std::make_pair(tmpSes, 1));

	return 0;
}

/*
 *! \brief
 *		세션 삭제
 *	\param
 *		packet_t* p : 캡쳐 패킷
 *	\return int 
 *		0 : 삭제 성공
 *		1 : 삭제 실패
 */

int IpsSession::delSession(packet_t *p){
	
	if( !p )
		return 1;

	std::map<session_t, u_int>::iterator sItr;

	for( sItr = m_astSession.begin() ; sItr != m_astSession.end() ; sItr++){
		if( sItr->first.sip == p->dip && sItr->first.sp == p->dp){
			m_astSession.erase(sItr++);
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
std::map<session_t, u_int>::iterator IpsSession::existSession(packet_t* p){
	
	std::map<session_t, u_int>::iterator sItr;

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
