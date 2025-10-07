/* $begin tinymain */
/*
 * tiny.c - A simple, iterative HTTP/1.0 Web server that uses the
 *     GET method to serve static and dynamic content.
 *
 * Updated 11/2019 droh
 *   - Fixed sprintf() aliasing issue in serve_static(), and clienterror().
 */
#define _GNU_SOURCE // Enable the use of RTLD_NEXT

#include <sys/types.h>
#include <sys/socket.h>

#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_initializer.h"
#include "kvstore.h"
#include "rio.h"

#define MAXLINE 8192 /* Max text line length */
#define LISTENQ 1024 /* Second argument to listen() */

typedef struct sockaddr SA;

// Web Server Methods
void doit(int fd);
void read_request(struct rio *rp, uint8_t **value, unsigned short *len);
int  parse_uri(char *uri, char *key);
void write_response(int fd, char *code, char *meaning, unsigned short len,
    uint8_t *body);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg,
    char *longmsg);

// CSAPP Methods
int open_listenfd(char *port);

int
main(int argc, char **argv)
{
	/* Check command line args */
	if (argc != 3 && argc != 5) {
		fprintf(stderr, "usage: %s <port> <filename> [-c <size>]\n",
		    argv[0]);
		exit(1);
	}

	if (argc == 5) {
		if (strcmp(argv[3], "-c") != 0) {
			fprintf(stderr,
			    "usage: %s <port> <filename> [-c <size>]\n",
			    argv[0]);
			exit(1);
		}

		if (access(argv[2], F_OK) == 0) {
			fprintf(stderr,
			    "Cannot specify existing file \"%s\" when using -c\n",
			    argv[2]);
			exit(1);
		}

		if (atol(argv[4]) <= 0) {
			fprintf(stderr,
			    "Must specify positive size when using -c\n");
			exit(1);
		}

		if (initialize_file(argv[2], atol(argv[4])) != 0) {
			fprintf(stderr, "File initialization failed\n");
			exit(1);
		}
	}

	if (atoi(argv[1]) < 18000 || atoi(argv[1]) > 19000) {
		fprintf(stderr, "port must be between 18000 and 19000\n");
		exit(1);
	}

	int success = init(argv[2]);

	if (success != 0) {
		errno = success;
		perror("Initialization error");
		exit(1);
	}

	int			listenfd, connfd;
	socklen_t		clientlen;
	struct sockaddr_storage clientaddr;

	listenfd = open_listenfd(argv[1]);
	if (listenfd == -1) {
		perror("open_listenfd");
		exit(1);
	}

	if (setvbuf(stdout, NULL, _IONBF, 0) != 0) {
		perror("setvbuf");
		exit(1);
	}

	fprintf(stdout, "Server Ready\n");

	while (true) {
		clientlen = sizeof(clientaddr);
		connfd = accept(listenfd, (SA *)&clientaddr,
		    &clientlen); // line:netp:tiny:accept
		doit(connfd);	 // line:netp:tiny:doit
		close(connfd);	 // line:netp:tiny:close
	}
}
/* $end tinymain */

/*
 * doit - handle one HTTP request/response transaction
 */
/* $begin doit */
void
doit(int fd)
{
	char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE],
	    key[MAXLINE];
	uint8_t	  *value;
	uint16_t   len;
	struct rio rio;

	/* Read request line and headers */
	rio_readinitb(&rio, fd);
	if (!rio_readlineb(&rio, buf, MAXLINE)) // line:netp:doit:readrequest
		return;
	sscanf(buf, "%s %s %s", method, uri,
	    version); // line:netp:doit:parserequest

	read_request(&rio, &value, &len); // line:netp:doit:readrequesthdrs

	if (parse_uri(uri, key) == 0) {
		if (strlen(key) != KEYSIZE) {
			printf("key: %s, len: %ld\n", key, strlen(key));
			clienterror(fd, "Bad Request", "400", "Malformed Key",
			    "Keys must be 64 bytes");
			return;
		}

		if (strcasecmp(method, "GET") == 0) {
			uint32_t  len;
			uint8_t	 *value;
			enum resp response = get_entry(key, &len, &value);
			if (response == SUCCESS) {
				write_response(fd, "200", "OK", len, value);
			} else if (response == NOT_FOUND) {
				clienterror(fd, "Not Found", "404",
				    "Key not found",
				    "Could not find desired key");
			} else if (response == SERVER_ERROR) {
				clienterror(fd, "Server Error", "500",
				    "Internal Server Error",
				    "We ran into an issue");
			}
		} else if (strcasecmp(method, "PUT") == 0) {
			enum resp response = set_entry(key, len, value);
			if (response == SUCCESS) {
				write_response(fd, "200", "OK", 0, NULL);
			} else if (response == SERVER_ERROR) {
				clienterror(fd, "Server Error", "500",
				    "Internal Server Error",
				    "We ran into an issue");
			} else if (response == NOT_ENOUGH_SPACE) {
				clienterror(fd, "Insufficient Storage", "507",
				    "Insufficient Storage",
				    "Not enough space to store value");
			}
		} else if (strcasecmp(method, "DELETE") == 0) {
			enum resp response = delete_entry(key);
			if (response == SUCCESS) {
				write_response(fd, "200", "OK", 0, NULL);
			} else if (response == SERVER_ERROR) {
				clienterror(fd, "Server Error", "500",
				    "Internal Server Error",
				    "We ran into an issue");
			} else if (response == NOT_FOUND) {
				clienterror(fd, "Not Found", "404",
				    "Key not found",
				    "Could not find desired key");
			}
		} else {
			clienterror(fd, "Invalid Method", "405",
			    "Method Not Allowed",
			    "Supported Methods: GET, PUT, POST");
		}
	} else {
		clienterror(fd, "Bad Request", "400", "Malformed URI",
		    "URI should be of the form /api?key=\\<key\\>");
	}
}
/* $end doit */

/*
 * read_request - read HTTP request
 */
/* $begin read_request */
void
read_request(struct rio *rp, uint8_t **value, unsigned short *len)
{
	char buf[MAXLINE];
	*len = 0;

	rio_readlineb(rp, buf, MAXLINE);
	while (strcmp(buf, "\r\n")) { // line:netp:readhdrs:checkterm
		rio_readlineb(rp, buf, MAXLINE);
		if (strstr(buf, "Content-Length")) {
			char *p = strchr(buf, ':');
			*len = atoi(p + 2);
		}
	}

	if (*len) {
		*value = malloc(*len);
		rio_readnb(rp, *value, *len);
	}

	return;
}
/* $end read_request */

/*
 * parse_uri - parse URI into filename and CGI args
 *             return 0 if valid endpoint, -1 if not
 */
/* $begin parse_uri */
int
parse_uri(char *uri, char *key)
{
	char *p;
	if ((p = strstr(uri, "api?"))) {
		if (p + 4 == strstr(uri, "key=")) {
			strcpy(key, p + 8);
			return (0);
		} else
			return (-1);
	} else
		return (-1);
}
/* $end parse_uri */

void
write_response(int fd, char *code, char *meaning, unsigned short len,
    uint8_t *body)
{
	char buf[MAXLINE];

	sprintf(buf, "HTTP/1.0 %s %s\r\n", code, meaning);
	rio_writen(fd, buf, strlen(buf));
	sprintf(buf, "Server: Tiny Web Server\r\n");
	rio_writen(fd, buf, strlen(buf));

	if (len != 0) {
		sprintf(buf, "Content-type: text/plain\r\n");
		rio_writen(fd, buf, strlen(buf));
	}

	sprintf(buf, "\r\n");
	rio_writen(fd, buf, strlen(buf));

	if (body != NULL) {
		rio_writen(fd, body, len);
	}
}

/*
 * clienterror - returns an error message to the client
 */
/* $begin clienterror */
void
clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg)
{
	char buf[MAXLINE];

	/* Print the HTTP response headers */
	sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
	rio_writen(fd, buf, strlen(buf));
	sprintf(buf, "Content-type: text/html\r\n\r\n");
	rio_writen(fd, buf, strlen(buf));

	/* Print the HTTP response body */
	sprintf(buf, "<html><title>Tiny Error</title>");
	rio_writen(fd, buf, strlen(buf));
	sprintf(buf,
	    "<body bgcolor="
	    "ffffff"
	    ">\r\n");
	rio_writen(fd, buf, strlen(buf));
	sprintf(buf, "%s: %s\r\n", errnum, shortmsg);
	rio_writen(fd, buf, strlen(buf));
	sprintf(buf, "<p>%s: %s</p>\r\n", longmsg, cause);
	rio_writen(fd, buf, strlen(buf));
	sprintf(buf, "<hr><em>The Tiny Web server</em></body></html>\r\n");
	rio_writen(fd, buf, strlen(buf));
}
/* $end clienterror */

/*
 * open_listenfd - Open and return a listening socket on port. This
 *     function is reentrant and protocol-independent.
 *
 *     On error, returns:
 *       -2 for getaddrinfo error
 *       -1 with errno set for other errors.
 */
/* $begin open_listenfd */
int
open_listenfd(char *port)
{
	struct addrinfo hints, *listp, *p;
	int		listenfd, rc, optval = 1;

	/* Get a list of potential server addresses */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;	     /* Accept connections */
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; /* ... on any IP address */
	hints.ai_flags |= AI_NUMERICSERV;	     /* ... using port number */
	if ((rc = getaddrinfo(NULL, port, &hints, &listp)) != 0) {
		fprintf(stderr, "getaddrinfo failed (port %s): %s\n", port,
		    gai_strerror(rc));
		return -2;
	}

	/* Walk the list for one that we can bind to */
	for (p = listp; p; p = p->ai_next) {
		/* Create a socket descriptor */
		if ((listenfd = socket(p->ai_family, p->ai_socktype,
			 p->ai_protocol)) < 0)
			continue; /* Socket failed, try the next */

		/* Eliminates "Address already in use" error from bind */
		setsockopt(listenfd, SOL_SOCKET,
		    SO_REUSEADDR, // line:netp:csapp:setsockopt
		    (const void *)&optval, sizeof(int));

		/* Bind the descriptor to the address */
		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
			break;		   /* Success */
		if (close(listenfd) < 0) { /* Bind failed, try the next */
			fprintf(stderr, "open_listenfd close failed: %s\n",
			    strerror(errno));
			return -1;
		}
	}

	/* Clean up */
	freeaddrinfo(listp);
	if (!p) /* No address worked */
		return -1;

	/* Make it a listening socket ready to accept connection requests */
	if (listen(listenfd, LISTENQ) < 0) {
		close(listenfd);
		return -1;
	}
	return listenfd;
}
/* $end open_listenfd */
