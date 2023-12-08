#include <stdio.h>
#include <arpa/inet.h>		// inet_addr
#include <stdlib.h>			// atoi

int main(){

	char chSip[15] = "192.168.1.14";
	char chDip[15] = "192.168.1.24";
	char chSp[6] = "2345";
	char chDp[6] = "3306";

	u_int sip = inet_addr(chSip);
	u_int dip = inet_addr(chDip);
	u_short sp = atoi(chSp);
	u_short dp = atoi(chDp);

	u_int result = sip ^ dip ^ dp ^ sp;
	u_int result1 = dip ^ (sip>>1) ^ dp ^ (sp>>1);
	u_int result2 = dip ^ (sip>>2) ^ dp ^ (sp>>1);
	
	u_int result_sip = (result1 ^ dip ^ dp ^ (sp>>1))<<1;
	
	printf("sip : %x\n", sip);
	printf("dip : %x\n", dip);
	printf("result : %x\n", result);
	printf("result>>1 : %x\n", result1);
	printf("result>>2 : %x\n", result2);
	printf("result : %x\n", result_sip);

	return 0;
}
