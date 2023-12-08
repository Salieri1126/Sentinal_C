#ifndef __THREAD_MANAGE_H__
#define __THREAD_MANAGE_H__

#include <pthread.h>

#define MAX_THREAD_NUM 2

class IpsThread{

	pthread_t m_astThread[MAX_THREAD_NUM];

	private:

	public:
	
		int logging;
		int printSession;
};

#endif
