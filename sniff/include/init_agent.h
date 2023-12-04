/**
  @file init_agent.h

  @section  CREATEINFO information
	- writer: JST(SunTae Jin, zalhae@pnpsecure.com)
	- date  : 2010-03-12

  @section MODIFYINFO modify info
	- JST/2010-03-12 : 최초 작성
  @brief 프로그램 초기화 관련 함수 정의
*/

#include "dbms_ips.h"

int  init_server_agent (configure_t *conf);
int  create_thread(configure_t *conf, pthread_t *thread_point);
