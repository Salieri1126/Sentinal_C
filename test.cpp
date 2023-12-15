#include <iostream>
#include <queue>

int main(){
	
	char logList[10][100];

	std::queue<char*> testque;

	testque.push("ABC");
	testque.push("DEF");
	testque.push("GHI");

	printf("%s\n", testque.front());

	testque.pop();
	
	printf("%s\n", testque.front());

	return 0;
}
