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
//TODO:	여러 IP에서 동시에 오는 DDOS공격에 대한 탐지
//		한 IP에서 시간내에 일정개수 이상의 SYN패킷이 감지 되었을때 탐지
//		SYN패킷이 아닌 연결중에 탐지 시스템이 켜졌을때 새로운 세션 생성
//		시간이 지났을때 지난 세션은 삭제
int IpsSession::checkSession(packet_t *p){

	if( !p || p->reverse_flow == -1 )
		return -1;
	
	u_int sessionIndex = makeSession(p);

	if( m_astSession[sessionIndex%MAX_SESSION_NUM].s_time == 0 ) {
		if( p->reverse_flow == 0 && (p->tcph->th_flags & R_SYN) ){
			if( addSession(p) ){
				printf("Session Add Fail!\n");
				return -1;
			}
		}
		// TODO : 관리중인 세션이 아닌데 SYN패킷이 아닌경우 새로운 세션 생성
		return 0;
	}

	if( ((p->tcph->th_flags & R_FIN) || (p->tcph->th_flags & R_RST)) ) {
		memset(&m_astSession[sessionIndex%MAX_SESSION_NUM], 0, sizeof(session_t));
		return 0;
	}
	m_astSession[sessionIndex%MAX_SESSION_NUM].session_cnt++;
	m_astSession[sessionIndex%MAX_SESSION_NUM].e_time = time(NULL);

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
int IpsSession::addSession(packet_t *p){

	if( !p )
		return -1;

	u_int i = makeSession(p);
	int j = i%MAX_SESSION_NUM;

	while(m_astSession[j].s_time != 0){
		j++;
	}
	
	m_astSession[j].session_hash = i;

	m_astSession[j].p_session.sip = p->sip;
	m_astSession[j].p_session.dip = p->dip;
	m_astSession[j].p_session.sp = p->sp;
	m_astSession[j].p_session.dp = p->dp;

	m_astSession[j].s_time = time(NULL);
	m_astSession[j].e_time = time(NULL);
	m_astSession[j].session_cnt = 1;

	//error 코드 확인
	
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

			if( m_astSession[i].session_hash == 0 ){
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

int IpsSession::existSession(){
	
	for ( int i = 0 ; i < MAX_SESSION_NUM ; i++ ){
		if( m_astSession[i].session_hash != 0)
			return i;
	}
	return -1;
}
/*! brief
 * 		캡쳐 패킷으로 세션형태로 변환
 *	\param
 *		packet_t* p : 캡쳐 패킷
 *	\return session_t
 *		캡쳐 패킷으로 생성한 Session
 */
u_int IpsSession::makeSession(packet_t *p){

	u_int tmpSes;	

	tmpSes = ((p->sip ^ p->sp)>>1) ^ p->dip ^ p->dp;

	return tmpSes;
}

void* IpsSession::printSessionWrapper(void* context) {
	return reinterpret_cast<void*>(static_cast<IpsSession*>(context)->printSession());
}
