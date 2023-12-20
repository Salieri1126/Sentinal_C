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

typedef struct{

	session_info	p_session;				//	세션의 기본정보

	time_t			s_time;					//	해당 세션의 처음 접속 시간
	time_t 			e_time;					//	해당 세션의 마지막 접속 시간
	u_int			session_cnt;			//	해당 세션의 패킷 수
	u_int			data_size;				//	해당 세션의 데이터 사이즈
	
	u_int			rx_count;				//	들어오는 패킷의 수(순방향)
	u_int			tx_count;				//	나가는 패킷의 수(역방향)

	u_int			rx_size;				//	들어오는 패킷의 사이즈(순방향)
	u_int			tx_size;				//	나가는 패킷의 사이즈(역방향)

	u_int			behavior_cnt;			//	해당 세션의 행동의 수
	time_t			behavior_time;			//	해당 세션의 행동시간


}session_t;

typedef struct{

	time_t			fin_time;				//	FIN 패킷 들어올시 FIN패킷의 접속 시간
	u_int			fin_session;			//	FIN 패킷의 세션 정보

}finSession_t;


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

	session_t			m_astSession[MAX_SESSION_NUM];		//	세션 구조체
	u_int				m_nSessionCnt;						//	총 세션의 수
	
	finSession_t		m_astFinSession[MAX_SESSION_NUM];	//	FIN 세션 구조체
	u_int				m_nFinCnt;							//	FIN 세션의 수
	
	private :


	public :
		IpsSession(){
			memset( m_astSession, 0, sizeof(m_astSession) );
			memset( m_astFinSession, 0, sizeof(m_astFinSession) );
			m_nSessionCnt = 0;
			m_nFinCnt = 0;
		}

		~IpsSession(){
		}

		int checkSession(packet_t *p);
		int addSession(packet_t *p, int nIndex);
		int delSession(int nIndex);
		int existSession();
		u_int makeSession(packet_t *p);
		session_t* getSession(int nIndex);
		int printSession();
		void update_session(packet_t *p, int nIndex);
		
		int  check_finSession();
		void insert_finSession(packet_t *p, u_int nFinIndex);

		int checkAttack(packet_t *p);

		static void* printSessionWrapper(void* context);
};

#endif
