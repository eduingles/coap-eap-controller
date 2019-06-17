#include <iostream>     // std::cout, std::end
#include "session.h"


	using namespace std;
int main (int argc, char *argv[]){

	Session session;
	session();
	char *mymsk ="123456";
	
	sessionsetMSK(mymsk,6);

	cout << mymsk << endl;

}	
