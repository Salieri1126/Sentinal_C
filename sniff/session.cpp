#include "session.h"
#include "match.h"

#define MAX_SESSION_TIME 86400

void* finDelSession(void* index);

/*
 *!\brief
 *		세션 확인 함수
 * \param
 *		p : 캡쳐 패킷
 * \return
 *		0 : 세션 확인 성공
 *		-1 : 세션 확인 실패
 *		1 : 공격 탐지 성공
 * \detail
 * 		- 관리 중인 세션일 경우
 * 			- FIN or RST 패킷일 경우 세션 삭제
 * 			- FIN or RST 패킷이 아닐경우 세션 cnt++
 * 		- 관리 중인 세션이 아닐 경우 세션 추가
 */
int IpsSession::checkSession(packet_t *p){

	time_t curTime = time(NULL);

	if( !p || p->flow == 0 )
		return -1;
	
	u_int nIndex = makeSession(p) % MAX_SESSION_NUM;

	// 관리중인 세션이면 s_time이 0일수 없으므로 0이면 세션 추가
	// 관리중인 세션인지 확인
	if( m_astSession[nIndex].s_time == 0 ) {
		if( (p->flow == 1)){
			// 관리 중인 세션이 아니면 세션 추가
			if( addSession(p, nIndex) ){
				printf("Session Add Fail!\n");
				return -1;
			}
		}
		return 0;
	}

	// FIXME:1시간지났으면 삭제는 thread로 관리?
	// 관리중인 세션 중 기준시간(1시간)이 지났으면 세션 삭제
	// 시간이 지났는데 SYN 패킷이라면 세션 초기화
	// 시간이 지났는데 SYN 패킷이 아니라면 세션 초기화
	if( difftime( curTime, m_astSession[nIndex].e_time ) > MAX_SESSION_TIME ){
		delSession(nIndex);
		addSession(p, nIndex);
	}

	// 관리중인 세션 중 RST 패킷이 들어오면 세션 삭제
	if( p->tcph->th_flags & R_RST ) {
		delSession(nIndex);
		return 0;
	}

	// 관리중인 세션 중 FIN 패킷이 들어오면 FIN LIST에 세션 저장
	if( p->tcph->th_flags & R_FIN ) {
		m_astFinSession[nIndex].fin_time = time(NULL);
		m_astFinSession[nIndex].fin_count = 1;
		return 0;
	}

	// 관리 중인 세션 중 FIN LIST에 존재하면 FIN이 들어왔던 시간이 지났는지 확인
	// 시간이 지났는데 SYN 패킷이라면 FIN LIST 삭제하고 addSession
	// 시간이 지났는데 SYN 패킷이 아니라면 FIN LIST 삭제하고 delSession
	if( m_astFinSession[nIndex].fin_count != 0 ){
		if( difftime(curTime, m_astFinSession[nIndex].fin_time) > 120 ){
			
			memset( &m_astFinSession[nIndex], 0, sizeof(finSession_t) );
			
			if( p->tcph->th_flags & R_SYN ){
				addSession(p, nIndex);
				return 0;
			}
			
			delSession(nIndex);
			return 0;
		}
	}

	// 관리 중인 세션이면서 RST과 FIN이 아닐경우 세션에 카운트 추가, 세션 마지막 시간 최신화
	m_astSession[nIndex].session_cnt++;
	m_astSession[nIndex].e_time = time(NULL);

	// TODO:DDOS공격, SCAN공격, FLOODING공격에 대한 탐지
	if( checkAttack(p) ){

		return 1;
	}

	return 0;
}

int IpsSession::delSession(int nIndex){

	memset(&m_astSession[nIndex], 0, sizeof(session_t));

	return 0;
}

/*
 *!\brief
 *	DDOS공격, SCAN공격, FLOODING공격에 대한 확인 함수
 * \param
 *	packet_t* p 캡쳐 패킷
 * \return
 *	int 0 : 공격 미탐지
 *		1 : DDOS 공격 탐지
 *		2 : SCAN 공격 탐지
 *		3 : FLOODING 공격 탐지
 */
int IpsSession::checkAttack(packet_t *p){
	
	return 0;
}

/*
 *!\brief
 *		세션 추가 함수
 * \param
 *		p : 캡쳐 패킷
 * \return
 *		0 : 세션 추가 성공
 *		-1 : 세션 추가 실패
 */
int IpsSession::addSession(packet_t *p, int nIndex){

	if( !p || nIndex < 0)
		return -1;

	// 세션 추가 전에 Fin List에 존재하는 세션인지 확인
	if( m_astFinSession[nIndex].fin_count != 0 ){
		return 0;
	}

	m_astSession[nIndex].p_session.sip = p->sip;
	m_astSession[nIndex].p_session.dip = p->dip;
	m_astSession[nIndex].p_session.sp = p->sp;
	m_astSession[nIndex].p_session.dp = p->dp;

	m_astSession[nIndex].data_size = p->dsize;
	m_astSession[nIndex].s_time = time(NULL);
	m_astSession[nIndex].e_time = time(NULL);
	m_astSession[nIndex].session_cnt = 1;
	
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
		if(	existSession() == -1 ){
			sleep(1);
			continue;
		}

		sleep(60);

		struct in_addr *ip_src;
		struct in_addr *ip_dst;
		struct tm ses_t;
		struct tm cur_t;
		
		time_t tmpTime = time(NULL);

		for(int i = 0 ; i < MAX_SESSION_NUM ; i++){

			if( m_astSession[i].session_cnt == 0 ){
				continue;
			}

			ses_t = *localtime(&m_astSession[i].s_time);
			cur_t = *localtime(&tmpTime);
			ip_src = (struct in_addr*)(&m_astSession[i].p_session.sip);
			ip_dst = (struct in_addr*)(&m_astSession[i].p_session.dip); 
			
			if( difftime(tmpTime,(m_astSession[i].s_time)) <= 120 ){
				printf("/------------ Session --------------/\n");
				printf("Source IP : %s\n", inet_ntoa(*ip_src));
				printf("Source Port : %d\n", m_astSession[i].p_session.sp);
				printf("Destiny IP : %s\n", inet_ntoa(*ip_dst));
				printf("Destiny Port : %d\n", m_astSession[i].p_session.dp);
				printf("Session Count : %d\n", m_astSession[i].session_cnt);
				printf("Make Session time : %04d.%02d.%02d %02d:%02d:%02d\n", ses_t.tm_year+1900, ses_t.tm_mon+1, ses_t.tm_mday, ses_t.tm_hour, ses_t.tm_min, ses_t.tm_sec);
				printf("Current time : %04d.%02d.%02d %02d:%02d:%02d\n", cur_t.tm_year+1900, cur_t.tm_mon+1, cur_t.tm_mday, cur_t.tm_hour, cur_t.tm_min, cur_t.tm_sec);
				printf("/-----------------------------------/\n\n");
			}
		}
	}
	return 0;
}

session_t* IpsSession::getSession(int nIndex){
	
	return &m_astSession[nIndex];
}
/*! brief
 * 		캡쳐 패킷으로 세션형태로 변환
 *	\param
 *		packet_t* p : 캡쳐 패킷
 *	\return session_t
 *		캡쳐 패킷으로 생성한 Session
 */
u_int IpsSession::makeSession(packet_t *p){

	return ((p->sip ^ p->sp)>>1) ^ p->dip ^ p->dp;
}

void* IpsSession::printSessionWrapper(void* context) {
	return reinterpret_cast<void*>(static_cast<IpsSession*>(context)->printSession());
}

int IpsSession::existSession(){

	for(int i = 0 ; i < MAX_SESSION_NUM ; i++){
		if( m_astSession[i].session_cnt != 0 )
			return i;
	}
	return -1;
}
