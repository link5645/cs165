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
#include <openssl/rand.h>   // Pseudo-random number generator

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
    
    /*unsigned char random_str[BUFFER_SIZE];
    memset(random_str,0,sizeof(random_str));
    
    if(RAND_bytes(random_str,BUFFER_SIZE) == 0) 
    	printf("Random value was not generated");*/
    
    string challenge = "31337";//(const char *)random_str;
	const char * cbuff = challenge.c_str();
	int cbufflen = 5;
	
	//Read in RSA public key
	BIO * chrsapubfile = BIO_new_file("rsapublickey.pem","r");
	RSA * chpubkey = PEM_read_bio_RSA_PUBKEY(chrsapubfile,NULL,NULL,NULL);
	
	//Sign challenge with public key
	unsigned char signed_ch[BUFFER_SIZE];
	memset(signed_ch,0,BUFFER_SIZE);
	
	//Prepare to send encrypted challenge
	int chsiglen = RSA_public_encrypt(cbufflen,(const unsigned char *)cbuff,signed_ch,chpubkey,RSA_PKCS1_PADDING);
	
	BIO * chsigbio = BIO_new(BIO_s_mem());
	BIO_puts(chsigbio,(const char *)signed_ch);
	
	int chactualRead = 0;
	int chbytesSent = 0;
	
	//Send encrypted challenge
	while((chactualRead = BIO_read(chsigbio, signed_ch, BUFFER_SIZE)) > 0)
	{
		chbytesSent = SSL_write(ssl, signed_ch, chactualRead);
	}
	
	//cbufflen = SSL_write(ssl,cbuff,BUFFER_SIZE);
	//chbytes = SSL_write(ssl,signed_ch,chsiglen);
    
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", buff2hex((const unsigned char *)signed_ch, chsiglen).c_str()/*challenge.c_str()*/);

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

    unsigned char signed_hash[BUFFER_SIZE];
	memset(signed_hash,0,BUFFER_SIZE);
	int siglen = SSL_read(ssl,signed_hash,BUFFER_SIZE);

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signed_hash, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");
	
	//Hash un-encrypted challenge
	char chashbuff[BUFFER_SIZE];

	BIO *ch, *hash;
	ch = BIO_new(BIO_s_mem());
	BIO_puts(ch,challenge.c_str());
	hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, EVP_sha1());

	//Chain on the input
	BIO_push(hash, ch); //pushes hash onto challenge

	int aRead;

	while((aRead = BIO_read(hash, chashbuff, BUFFER_SIZE)) >= 1)
	{}

	//Get digest
	char hashbuff[EVP_MAX_MD_SIZE];
	int hashlen = BIO_gets(hash, hashbuff, EVP_MAX_MD_SIZE);

	string generated_key = buff2hex((const unsigned char *)hashbuff,hashlen);
	
	//Read in RSA public key
	BIO * rsapubfile = BIO_new_file("rsapublickey.pem","r");
	RSA * pubkey = PEM_read_bio_RSA_PUBKEY(rsapubfile,NULL,NULL,NULL);
	
	//Recover hash
	unsigned char recovered_hash[BUFFER_SIZE];
	int hashsize = RSA_public_decrypt(siglen,signed_hash,recovered_hash,pubkey,RSA_PKCS1_PADDING); 
	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free
	
	string decrypted_key = buff2hex((const unsigned char *)recovered_hash,hashsize);
    
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
