#include <iostream>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/bio.h>

using namespace std;


int main()
{
	string filename = "simon.txt";
	ifstream file;
	file.open(filename.c_str);
	if(file.isbad()) 
	{
		cerr << "The file does not exist" << endl;
		return 0;
	}
	
	

	return 0;
}
