////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_client.c
//  Description   : This is the client side of the Needham Schroeder
//                  protocol, and associated main processing loop.
//
//   Author        : Tongyu Yue
//   Last Modified : Today
//

// Includes
#include <arpa/inet.h>
#include <unistd.h>
#include <cmpsc311_log.h>
#include <cmpsc311_util.h>
#include <gcrypt.h>
// #include <cmpsc311_network.h>
#include <tuy133_network.h>

// Project Include Files
#include <cmpsc443_ns_proto.h>
#include <cmpsc443_ns_util.h>

// Defines
#define NS_ARGUMENTS "h"
#define USAGE \
	"USAGE: cmpsc443_ns_client [-h]\n" \
	"\n" \
	"where:\n" \
	"    -h - help mode (display this message)\n" \
	"\n" \

#define GCRY_CIPHER GCRY_CIPHER_AES128
#define GCRY_CIPHER_MODE GCRY_CIPHER_MODE_CBC
// Functional Prototypes
int ns_client( void );

//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the Needam Schroeder protocol client
//
// Inputs       : argc - the number of command line parameters
//                argv - the parameters
// Outputs      : 0 if successful, -1 if failure

int main( int argc, char *argv[] )
{
	// Local variables
	int ch;

	// Process the command line parameters
	while ((ch = getopt(argc, argv, NS_ARGUMENTS)) != -1) {

		switch (ch) {
		case 'h': // Help, print usage
			fprintf( stderr, USAGE );
			return( -1 );

		default:  // Default (unknown)
			fprintf( stderr, "Unknown command line option (%c), aborting.\n", ch );
			return( -1 );
		}
	}

	// Create the log, run the client
    initializeLogWithFilehandle(STDERR_FILENO);
    enableLogLevels(LOG_INFO_LEVEL);
	ns_client();

	// Return successfully
	return( 0 );
}

typedef struct message {
    u_int16_t length;
    u_int16_t type;
	u_int8_t data[NS_MAX_XMIT_SIZE];
} message_t;

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ns_client
// Description  : The client function for the Needam Schroeder protocol server
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int ns_client( void ) {

	// Method local type definition
	char ss[NS_MAX_XMIT_SIZE];
	memset(ss,0,sizeof(ss));

	int sock = tuy133_connect_server("127.0.0.1", NS_SERVER_PROTOCOL_PORT);

	int message_length = 0;
	int header_length = 4;
	int data_length = 0;
	int ticket_length = 0;
	message_t message;
	u_int8_t * p;
	u_int8_t cipher_buf[NS_MAX_XMIT_SIZE];

	gcry_cipher_hd_t cipher_hd;
	ns_key_t key_A;
	ns_iv_t iv_A;
	int key_length = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
	int block_size = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
	int block_required;
	
	if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER,  GCRY_CIPHER_MODE, 0)) return -1;
	makeKeyFromPassword(NS_ALICE_PASSWORD, key_A);

	memset(&message, 0, sizeof(message_t));
	memset(&cipher_buf, 0, sizeof(cipher_buf));

	///////////////////////////
	// Step 1 Ticket request
	///////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 1:");

	// format request ticket
	tkt_req_t tkt_req;
	memset(&tkt_req, 0, sizeof(tkt_req_t));

	ns_nonce_t nonce;
	createNonce(&nonce);
	tkt_req.N1 = nonce;
	memcpy(tkt_req.A, NS_ALICE_IDENTITY, sizeof(NS_ALICE_IDENTITY));
	memcpy(tkt_req.B, NS_BOB_IDENTITY, sizeof(NS_BOB_IDENTITY));

	// format message
	data_length = sizeof(tkt_req_t);
	message_length = header_length + data_length;
	memset(&message, 0, message_length);
	message.length = htons(data_length);
	message.type = htons(NS_TKT_REQ);
	memcpy(message.data, &tkt_req, data_length);
	
	logBufferMessage(LOG_INFO_LEVEL, "Ticket request", (void *)&message, message_length);
	
	int r = tuy133_send(sock, message_length, (void *)&message);
	
	logMessage(LOG_INFO_LEVEL, "r: %d", r);

	if (r) return -1;

	///////////////////////////
	// Step 2 Ticket response
	///////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 2:");

	memset(&message, 0, sizeof(message_t));

	if (tuy133_read(sock, header_length, (void *)&message)) return -1;
	if (ntohs(message.type) != NS_TKT_RES) {
		logMessage(LOG_ERROR_LEVEL, "Type Error!");
		return -1;
	}
	data_length = ntohs(message.length);
	logMessage(LOG_INFO_LEVEL, "data length: %d", data_length);
	p = message.data;
	if (tuy133_read(sock, data_length, p)) return -1;

	logBufferMessage(LOG_INFO_LEVEL, "Ticket response", (void *)&message, header_length + data_length);

	// ----------------decrypt------------------------------
	memcpy(iv_A, p, sizeof(iv_A));
	p += key_length;
	if (gcry_cipher_setkey(cipher_hd, key_A, key_length)) return -1;
	if (gcry_cipher_setiv(cipher_hd, iv_A, key_length)) return -1;

	logBufferMessage(LOG_INFO_LEVEL, "key_A", key_A, key_length);
	logBufferMessage(LOG_INFO_LEVEL, "iv_A", iv_A, key_length);
	
	u_int16_t encrypted_data_length = ntohs(*(u_int16_t*)p);
	p += sizeof(encrypted_data_length);

	block_required = encrypted_data_length / block_size;
	if (encrypted_data_length % block_size) block_required++;

	if (gcry_cipher_decrypt(cipher_hd, p, block_required * block_size, NULL, 0)) return -1;

	logBufferMessage(LOG_INFO_LEVEL, "decrypted", p, encrypted_data_length);

	tkt_res_t tkt_res;
	memset(&tkt_res, 0, sizeof(tkt_res_t));

	memcpy(&tkt_res, p, encrypted_data_length);

	if (tkt_res.N1 != nonce) {
		logMessage(LOG_ERROR_LEVEL, "N1 not match!");
		return -1;
	}
	
	if (strcmp(tkt_res.B, tkt_req.B)) {
		logMessage(LOG_ERROR_LEVEL, "B not match!");
		return -1;
	}
	
	logBufferMessage(LOG_INFO_LEVEL, "key_AB", tkt_res.Kab, key_length);
	ticket_length = encrypted_data_length - sizeof(ns_nonce_t) - sizeof(ns_id_t) - key_length;
	logMessage(LOG_INFO_LEVEL, "ticket length: %d", ticket_length);
	
	///////////////////////////
	// Step 3 Service request
	///////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 3:");

	// format massage
	data_length = 2*sizeof(ns_id_t) + ticket_length + key_length + 2 + block_size;
	message_length = header_length + data_length;
	memset(&message, 0, message_length);
	message.length = htons(data_length);
	message.type = htons(NS_SVC_REQ);

	p = message.data;
	memcpy(p, NS_ALICE_IDENTITY, sizeof(NS_ALICE_IDENTITY));
	p += sizeof(ns_id_t);
	memcpy(p, NS_BOB_IDENTITY, sizeof(NS_BOB_IDENTITY));
	p += sizeof(ns_id_t);
	memcpy(p, &tkt_res.ticket, ticket_length);
	p += ticket_length;
	memcpy(p, iv_A, key_length);
	p += key_length;
	*(u_int16_t*)p = htons(sizeof(ns_nonce_t));
	p += sizeof(u_int16_t);

	// generate N2
	createNonce(&nonce);
	logBufferMessage(LOG_INFO_LEVEL,"N2", (void *)&nonce, sizeof(ns_nonce_t));

	memset(&cipher_buf, 0, block_size);
	memcpy(cipher_buf, &nonce, sizeof(ns_nonce_t));

	if (gcry_cipher_setkey(cipher_hd, tkt_res.Kab, key_length)) return -1;
	if (gcry_cipher_setiv(cipher_hd, iv_A, key_length)) return -1;
	if (gcry_cipher_encrypt(cipher_hd, cipher_buf, block_size, NULL, 0)) return -1;

	memcpy(p, cipher_buf, block_size);
	
	logBufferMessage(LOG_INFO_LEVEL,"Service request", (void *)&message, message_length);
	if (tuy133_send(sock, message_length, (void *)&message)) return -1;


	////////////////////////////
	// Step 4 Service response
	///////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 4");

	memset(&message, 0, sizeof(message_t));
	if (tuy133_read(sock, header_length, (void *)&message)) return -1;

	if (ntohs(message.type) != NS_SVC_RES) {
		logMessage(LOG_ERROR_LEVEL, "Type Error!");
		return -1;
	}
	data_length = ntohs(message.length);
	logMessage(LOG_INFO_LEVEL, "data length: %d", data_length);

	if (tuy133_read(sock, data_length, message.data)) return -1;
	logBufferMessage(LOG_INFO_LEVEL,"Service response", (void *)&message, header_length + data_length);
	p = message.data;

	memcpy(iv_A, p, key_length);
	p += key_length;
	logBufferMessage(LOG_INFO_LEVEL, "iv_A",iv_A,key_length);
	if (gcry_cipher_setiv(cipher_hd, iv_A, key_length)) return -1;

	encrypted_data_length = ntohs(*(u_int16_t *)p);
	p += sizeof(u_int16_t);
	if (gcry_cipher_decrypt(cipher_hd, p, encrypted_data_length, NULL, 0)) return -1;
	logBufferMessage(LOG_INFO_LEVEL,"decrypted", p, encrypted_data_length);

	svc_res_t svc_res;
	memcpy(&svc_res, p, encrypted_data_length);
	logBufferMessage(LOG_INFO_LEVEL,"N2-1",(void *)&svc_res.N2,sizeof(ns_nonce_t));
	
	if (ntohll64(svc_res.N2) != ntohll64(nonce) - 1) {
		logMessage(LOG_ERROR_LEVEL, "N2 not match!");
		return -1;
	}

	////////////////////////////////////
	// Step 5  Service acknowledgement
	////////////////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 5");

	data_length = key_length + 2 + block_size;
	message_length = header_length + data_length;
	memset(&message, 0, message_length);
	message.length = htons(data_length);
	message.type = htons(NS_SVC_ACK);
	p = message.data;
	memcpy(p, iv_A, key_length);
	p += key_length;
	*(u_int16_t*)p = htons(sizeof(ns_nonce_t));
	p += sizeof(u_int16_t);

	// prepare for n3-1
	nonce = htonll64(ntohll64(svc_res.N3) - 1);
	memset(cipher_buf, 0, block_size);
	memcpy(cipher_buf, &nonce, sizeof(ns_nonce_t));
	if (gcry_cipher_setiv(cipher_hd, iv_A, key_length)) return -1;
	if (gcry_cipher_encrypt(cipher_hd, cipher_buf, block_size, NULL, 0)) return -1;
	memcpy(p, cipher_buf, block_size);
	if (tuy133_send(sock, message_length, (void *)&message)) return -1;
	logBufferMessage(LOG_INFO_LEVEL, "Service acknowledgement", (void*)&message, message_length);

	/////////////////////////
	// Step 6  Data request
	/////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 6");

	if (tuy133_read(sock, header_length, (void*)&message)) return -1;
	if (ntohs(message.type) != NS_DAT_REQ) {
		logMessage(LOG_ERROR_LEVEL, "Type Error!");
		return -1;
	}
	data_length = ntohs(message.length);
	if (tuy133_read(sock, data_length, message.data)) return -1;

	logMessage(LOG_INFO_LEVEL, "data length: %d", data_length);

	p = message.data;
	memcpy(iv_A, p, key_length);
	p += key_length;
	logBufferMessage(LOG_INFO_LEVEL, "iv_A", iv_A, key_length);

	encrypted_data_length = ntohs(*(u_int16_t *)p);
	p +=2;
	logMessage(LOG_INFO_LEVEL, "cipher length: %d", encrypted_data_length);
	logBufferMessage(LOG_INFO_LEVEL, "cipher text", p, encrypted_data_length);
	block_required = encrypted_data_length / block_size;
	if (encrypted_data_length % block_size) block_required++;
	memset(cipher_buf, 0, sizeof(cipher_buf));
	memcpy(cipher_buf, p, encrypted_data_length);
	if (gcry_cipher_setiv(cipher_hd, iv_A, key_length)) return -1;
	if (gcry_cipher_decrypt(cipher_hd, cipher_buf, block_required * block_size, NULL, 0)) return -1;

	logBufferMessage(LOG_INFO_LEVEL,"DATA",cipher_buf, encrypted_data_length);

	/////////////////////////
	// Step 7 Data response
	/////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 7");

	u_int8_t xor = 0xb6;
	p = cipher_buf;
	while (p - cipher_buf < encrypted_data_length) {
		*p ^= xor;
		p++;
	}
	if (gcry_cipher_setiv(cipher_hd, iv_A, key_length)) return -1;
	if (gcry_cipher_encrypt(cipher_hd, cipher_buf, block_required * block_size, NULL, 0)) return -1;

	data_length = key_length + 2 + encrypted_data_length;
	message_length = header_length + data_length;
	memset(&message, 0, message_length);
	message.length = htons(data_length);
	message.type = htons(NS_DAT_RES);
	
	p = message.data;
	memcpy(p, iv_A, key_length);
	p += key_length;

	*(u_int16_t*)p = htons(encrypted_data_length);
	p += sizeof(u_int16_t);

	memcpy(p, cipher_buf, encrypted_data_length);

	if (tuy133_send(sock, message_length, (void*)&message)) return -1;
	logBufferMessage(LOG_INFO_LEVEL, "Data response", (void*)&message, message_length);

	//////////////////////////
	// Step 8 Service finish
	//////////////////////////
	logMessage(LOG_INFO_LEVEL, "STEP 8");
	if (tuy133_read(sock, header_length, (void*)&message)) return -1;

	data_length = ntohs(message.length);
	if (ntohs(message.type) != NS_SVC_FIN) {
		logMessage(LOG_ERROR_LEVEL, "Type Error!");
		return -1;
	}

	logMessage(LOG_INFO_LEVEL, "YEAHHHHHH! Succes!");
	
	if (tuy133_send(sock, header_length, (void*)&message)) return -1;

	gcry_cipher_close(cipher_hd);
	tuy133_close(sock);
	// Return successfully
	return(0);
}