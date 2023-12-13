#ifndef __SESSION_H__
#define __SESSION_H__

#include <ctime>

#include "policy.h"

#define MAX_SESSION_NUM 0xffff

typedef struct{
	
	u_int	sip;
	u_int	dip;
	u_short	sp;
	u_short	dp;

}session_info;

//TODO:데이터 사이즈에 관한 탐지
typedef struct{

	session_info	p_session;

	time_t			s_time;
	time_t 			e_time;
	u_int			session_cnt;
	u_int			behavior_cnt;
	time_t			behavior_time;
	u_int			data_size;

}session_t;
/*
 *	mem : 세션의 수, 세션 구조체의 자료구조
 *	생성자, 소멸자
 *	함수 :	세션 확인		:	세션의 방향 설정
 *			세션 추가		:	
 *			세션 업데이트
 *			세션 삭제
 *			세션 출력
 *	
 */
class IpsSession {

	session_t			m_astSession[MAX_SESSION_NUM];

	private :


	public :
		IpsSession(){
			memset( m_astSession, 0, sizeof(session_t) );
		}

		~IpsSession(){
		}

		int checkSession(packet_t *p);
		int addSession(packet_t *p, int nIndex);
		int printSession();
		session_t* getSession(int nIndex);
		u_int makeSession(packet_t *p);
		int checkAttack(packet_t *p);
		int delSession(int nIndex);
		static void* printSessionWrapper(void* context);
		int existSession();
};

#endif
