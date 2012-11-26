#include <iostream>
#include <string>
using namespace std;

#include <time.h>
#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"


//returns (SHA1 hash key, key length) pair
pair <char *,int> shash (string infile, string outfile)
{
	//This section uses BIOs to write a copy of infile.txt to outfile.txt
	//  and to send the hash of infile.txt to the command window.
	//  It is a barebones implementation with little to no error checking.

	//The SHA1 hash BIO is chained to the input BIO, though it could just
	//  as easily be chained to the output BIO instead.

	const char * infilename = infile.c_str();
	const char * outfilename = outfile.c_str();

	char * buffer[1024];

	BIO *binfile, *boutfile, *hash;
	binfile = BIO_new_file(infilename, "r");
	boutfile = BIO_new_file(outfilename, "w") ;
	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());

	//Chain on the input
	BIO_push(hash, binfile); //pushes hash onto input file for encryption

	//Chain on the output
	//BIO_push(hash, boutfile);

	int actualRead, actualWritten;

	while((actualRead = BIO_read(hash, buffer, 1024)) >= 1)
	{
		//Could send this to multiple chains from here
		//we write what's in buffer to the boutfile
		actualWritten = BIO_write(boutfile, buffer, actualRead);
	}

	//Get digest
	char * mdbuf = new char(EVP_MAX_MD_SIZE);
	memset(mdbuf,0,sizeof(mdbuf));
	int mdlen = BIO_gets(hash, mdbuf, EVP_MAX_MD_SIZE);
	
	//Free BIO files
	BIO_free_all(boutfile);
	BIO_free_all(hash);
	
	pair <char *, int> phash(mdbuf,mdlen);
	
	return phash;
}

int main()
{
	/*string filename = "simon.txt";
	ifstream file;
	file.open(filename.c_str);
	if(file.isbad()) 
	{
		cerr << "The file does not exist" << endl;
		return 0;
	}*/
	
	string infile = "simon.txt";
	string outfile = "outfile.txt";
	
	//Compute SHA1 hash
	pair <char *,int> hash = shash(infile,outfile);
	cout << "SHA1 Hash: "
		 << buff2hex((const unsigned char *)hash.first,hash.second) 
		 << endl;
	
	//Read in RSA private key
	BIO * privkeyfile = BIO_new_file("rsaprivatekey.pem", "r");
	

	return 0;
}
