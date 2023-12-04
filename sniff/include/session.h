#ifndef __SESSION_H__
#define __SESSION_H__

#include <map>
#include <ctime>
#include <utility>

#include "policy.h"

#define MAX_SES_NUM 10000

/*
 * 세션 구조체
 * Source Ip
 * Source Port
 * Destiny Ip
 * Destiny Port
 * f_time
 * e_time
 * count
 */
struct session_t{
	u_int 	sip;
	u_int 	sp;
	u_int	dip;
	u_int 	dp;

	time_t	s_time;

	bool operator<(const session_t& other) const{
		if( sip < other.sip )
			return sip < other.sip;
		
		if( sp < other.sp )
			return sp < other.sp;
		
		if( dip < other.dip )
			return dip < other.dip;
		
		if( dp < other.dp )
			return dp < other.dp;
		return sip < other.sip;
	}
};

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

	std::map<session_t, u_int>			m_astSession;

	private :


	public :
		IpsSession(){
		}

		~IpsSession(){
		}

		int checkSession(packet_t *p);
		int addSession(packet_t *p);
		int delSession(packet_t *p);
		int printSession();
		int timeInit(std::map<session_t, u_int>::iterator itr);
		std::map<session_t, u_int>::iterator existSession(packet_t* p);
		session_t makeSession(packet_t *p);
};

#endif
