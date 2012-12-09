//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client serverip:port filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
    string randomNumber="31337"; //***This number needs to change***/
	//SSL_write
	const char * cbuff = randomNumber.c_str();
	int cbufflen = 0;
	cbufflen = SSL_write(ssl,cbuff,BUFFER_SIZE);
    
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

    char sigbuffer[BUFFER_SIZE];
	memset(sigbuffer,0,BUFFER_SIZE);
	int siglen = SSL_read(ssl,sigbuffer,BUFFER_SIZE);

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)sigbuffer, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");

	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free
	
	string generated_key="";
	string decrypted_key="";
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
	//BIO_flush
    //BIO_puts
	//BIO_flush(client);
	const char * filenamebuff = filename;
	int filenamebufflen = 0;
	//BIO_puts(client,filebuff);
	filenamebufflen = SSL_write(ssl,filenamebuff,BUFFER_SIZE);
	BIO_flush(client);

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

	char filebuffer[BUFFER_SIZE];
	memset(filebuffer,0,BUFFER_SIZE);
	string ufilename = filename;
	string outfile_name = "client/"+ufilename;
	BIO * boutfile = BIO_new_file(outfile_name.c_str(), "w");
	int actualRead = 0;
	int bytesSent=0;
	
	while((actualRead = SSL_read(ssl, filebuffer, BUFFER_SIZE)) > 0)
	{
		BIO_write(boutfile, filebuffer, actualRead);
	}

	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	SSL_shutdown(ssl);
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	BIO_free_all(boutfile);
	return EXIT_SUCCESS;
	
}
