/**
  @file init_agent.h

  @section  CREATEINFO information
	- writer: PHS(HeeSeung Park, pak0302@gmail.com)
	- date  : 2010-03-12

  @section MODIFYINFO modify info
	- JST/2023-11-07 : ���� �ۼ�
  @brief ���α׷� �ʱ�ȭ ���� �Լ� ����
*/

#include "dbms_ips.h"

int  init_server_agent (configure_t *conf);
int  create_thread(configure_t *conf, pthread_t *thread_point);
