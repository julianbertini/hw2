/*
 * Copyright (c) 2018, Hammurabi Mendes.
 * License: BSD 2-clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "networking.h"
#include "tls.h"

#define BUFFER_SIZE 1024

#define MAX(A, B) ((A) > (B) ? (A) : (B))

#define MODE_E 0
#define MODE_D 1

int handle_client_encrypt(int client_socket);
int handle_client_decrypt(int client_socket);

int flush_buffer(int socket, char *buffer, int ntowrite);
int flush_buffer_ssl(SSL *ssl, char *buffer, int ntowrite);

int forward_connection(int protected_socket, SSL *protected_ssl, int unprotected_socket);

void print_address_information(char *template, struct sockaddr *address, int address_size);

static int mode;
static char *local_port;
static char *destination_host;
static char *destination_port;

static SSL_CTX *tls_context;

int main(int argc, char **argv) {
	int result;

	// Argument parsing

		if(argc < 4) {
			fprintf(stderr, "Usage: server [E|D] <local_port> <proxy_host> <proxy_port>\n");

			return -1;
		}

		if(strcmp(argv[1], "E") == 0) {
			mode = MODE_E;
		}
		else if(strcmp(argv[1], "D") == 0) {
			mode = MODE_D;
		}
		else {
			fprintf(stderr, "Usage: server [E|D] <local_port> <proxy_host> <proxy_port>\n");

			return -1;
		}



//	char *lport = "9000";
//	char *dest_host = "localhost";
//	char *dest_port = "8000";

//	local_port = lport;//argv[2];
//	destination_host = dest_host;//argv[3];
//	destination_port = dest_port;//argv[4];
//	mode = MODE_D;

	local_port = argv[2];
	destination_host = argv[3];
	destination_port = argv[4];

	// Using getaddrinfo to obtain the first address to bind to

	struct addrinfo result_hints;
	struct addrinfo *result_list;

	memset(&result_hints, 0, sizeof(struct addrinfo));

	result_hints.ai_family = AF_UNSPEC;
	result_hints.ai_socktype = SOCK_STREAM;
	result_hints.ai_flags = AI_PASSIVE;

	result = getaddrinfo(NULL, local_port, &result_hints, &result_list);

	if(result != 0) {
		perror("Cannot obtain address");

		return -1;
	}

	// Listening socket creation

	int listen_socket;

	for(struct addrinfo *result_curr = result_list; result_curr != NULL; result_curr = result_curr->ai_next) {
		// Listening socket creation

		listen_socket = socket(result_curr->ai_family, result_curr->ai_socktype, result_curr->ai_protocol);

		if(listen_socket == -1) {
			continue;
		}

		// Binding to a local address/port


		result = bind(listen_socket, result_curr->ai_addr, result_curr->ai_addrlen);

		if(result == -1) {
			close(listen_socket);
			listen_socket = -1;

			continue;
		}

		print_address_information("Listening in address [%s] port [%s]\n", result_curr->ai_addr, result_curr->ai_addrlen);

		break;
	}

	if(listen_socket == -1) {
		fprintf(stderr, "Not possible to bind to any address/port\n");

		return -1;
	}

	// Listen for connections

	result = listen(listen_socket, 5);

	if(result == -1) {
		perror("Impossible to listen to connections");

		return -1;
	}

	// Prepare the TLS library

	init_openssl_library();
	tls_context = get_tls_context();

	// Read from client and echo its messages
	int client_socket;
	struct sockaddr_storage client_socket_address;
	socklen_t client_socket_size;

	client_socket_size = sizeof(struct sockaddr_storage);

	while(1) {
		client_socket = accept(listen_socket, (struct sockaddr *) &client_socket_address, &client_socket_size);

		if(client_socket == -1) {
			perror("Cannot accept client");


			return -1;
		}

		// Read from client and echo its messages
		print_address_information("Connection from client from [%s] port [%s]\n", (struct sockaddr *) &client_socket_address, client_socket_size);

		int pid = fork();

		if(pid != 0) {
			// Server executes this
			close(client_socket);
		}
		else {
			// Client executes this
			if(mode == MODE_E) {
				handle_client_encrypt(client_socket);
			}
			else {
				handle_client_decrypt(client_socket);
			}

			close(client_socket);

			// This call is important
			exit(0);
		}
	}

	return 0;
}

int handle_client_encrypt(int client_socket) {
	int result;
	// Create (d) socket to talk to proxy

	char *cert_file="pki_files/ca_certificate.pem";

	result = SSL_CTX_load_verify_locations(tls_context,cert_file,NULL);

	if (result == 0) {
		perror("Not able to find certificate file verification locations");
		return 0;
	}

	int decrypt_socket;
	decrypt_socket = create_client(destination_host, destination_port);

	if (decrypt_socket == -1){
		perror("Error creating decrypt (D) socket");
		return 0;
	}

	// 2. https handshake protocol
	SSL *remote_ssl = tls_session_active(decrypt_socket, tls_context);

	if((SSL_get_peer_certificate(remote_ssl)) == NULL){
		perror("No certificate present");
		return 0;
	}

	if((SSL_get_verify_result(remote_ssl)) < 0){
		perror("peer not verified");
		return 0;

	}

	result = forward_connection(decrypt_socket, remote_ssl, client_socket);

	if (result == 0){
		perror("Error forwarding the connection");
		return 0;
	}

	// finish ssl stream and session cleanly
	SSL_shutdown(remote_ssl);
	SSL_free(remote_ssl);

	// close client and server sockets
	printf("closing client socket");
	close(client_socket);
	close(decrypt_socket);

	return 1;
}

int handle_client_decrypt(int client_socket) {

	int result;
	int proxy_socket;

	printf("Starting decrypt...");

	// Create (d) socket to talk to proxy
	proxy_socket = create_client(destination_host, destination_port);

	if (proxy_socket == -1){
		perror("Error creating proxy socket");
		return 0;
	}

	// 2. https handshake protocol, waiting for E packets
	SSL *remote_ssl = tls_session_passive(client_socket, tls_context);

	// forward packets to the proxy server
	result = forward_connection(client_socket, remote_ssl, proxy_socket);

	if (result == 0){
		perror("Error forwarding the connection");
		return 0;
	}

	// finish ssl stream and session cleanly
	SSL_shutdown(remote_ssl);
	SSL_free(remote_ssl);

	// close client and server sockets
	close(client_socket);
	close(proxy_socket);

	return 1;
}

int forward_connection(int protected_socket, SSL *protected_ssl, int unprotected_socket) {

	int result;
	char buffer[BUFFER_SIZE];

	fd_set descriptor_set;

	while(1) {
		FD_ZERO(&descriptor_set);

		FD_SET(protected_socket, &descriptor_set);
		FD_SET(unprotected_socket, &descriptor_set);

		result = select(MAX(protected_socket,unprotected_socket) + 1, &descriptor_set, NULL, NULL, 0);

		if(result == -1) {
			perror("select");
			continue;
		}

		// protected_socket is ready for reading
		if(FD_ISSET(protected_socket, &descriptor_set)) {
			int nread = SSL_read(protected_ssl, buffer, BUFFER_SIZE);
			if(nread < 0){
				perror("read");

				return 0;
			}
			result = flush_buffer(unprotected_socket, buffer,nread);

			if(result == -1){
				perror("flush_buffer");
				return 0;
			}

		}

		// There's something ready coming from the server
		if(FD_ISSET(unprotected_socket, &descriptor_set)) {
			int nread = read(unprotected_socket, buffer, BUFFER_SIZE);
			if(nread < 0){
				perror("read");

				return 0;
			}

			result = flush_buffer_ssl(protected_ssl, buffer,nread);

			if(result == -1){
				perror("flush_buffer");
				return 0;
			}
		}
	}

	return 1;

}

void print_address_information(char *template, struct sockaddr *address, int address_size) {
	int result;

	char host[1024];
	char port[16];

	result = getnameinfo(address, address_size, host, 1024, port, 16, NI_NUMERICHOST | NI_NUMERICSERV);

	if(result != 0) {
		perror("Error obtaining information from client");
	}

	printf(template, host, port);
}

int flush_buffer(int socket, char *buffer, int ntowrite) {
	int result;

	int nwritten = 0;

	while(ntowrite > 0) {
		result = write(socket, buffer + nwritten, ntowrite);

		if(result == -1) {
			perror("write");

			return -1;
		}

		nwritten += result;
		ntowrite -= result;
	}

	return nwritten;
}

int flush_buffer_ssl(SSL *ssl, char *buffer, int ntowrite) {
	int result;

	int nwritten = 0;

	while(ntowrite > 0) {
		result = SSL_write(ssl, buffer + nwritten, ntowrite);

		if(result == -1) {
			perror("write");

			return -1;
		}

		nwritten += result;
		ntowrite -= result;
	}

	return nwritten;
}
