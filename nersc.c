/*
 * Author: Scott Campbell, Tom Davis
 * Set of functions called by the command instrumentation and logging
 *
 *  notes as follows:
 *     hostname and source port of the syslog listener are hardcoded into
 *      the code to prevent issues with configuration - both intentional and otherwise.
 * 
 * ------------------------------------------------------------------------------
 * Instrumented Open SSHD, Copyright (c) *2013*, The
 * Regents of the University of California, through Lawrence Berkeley National
 * Laboratory (subject to receipt of any required approvals from the U.S.
 * Dept. of Energy).  All rights reserved.
 * 
 * If you have questions about your rights to use or distribute this software,
 * please contact Berkeley Lab's Technology Transfer Department at  TTD@lbl.gov
 * .
 * 
 * NOTICE.  This software is owned by the U.S. Department of Energy.  As such,
 * the U.S. Government has been granted for itself and others acting on its
 * behalf a paid-up, nonexclusive, irrevocable, worldwide license in the
 * Software to reproduce, prepare derivative works, and perform publicly and
 * display publicly.  Beginning five (5) years after the date permission to
 * assert copyright is obtained from the U.S.
 * Department of Energy, and subject to any subsequent five (5) year renewals,
 * the U.S. Government is granted for itself and others acting on its behalf a
 * paid-up, nonexclusive, irrevocable, worldwide license in the Software to
 * reproduce, prepare derivative works, distribute copies to the public,
 * perform publicly and display publicly, and to permit others to do so.
 * 
 * *** License agreement ***
 * 
 * " Instrumented Open SSHD, Copyright (c) 2013, The Regents of the
 * University of California, through Lawrence Berkeley National Laboratory
 * (subject to receipt of any required approvals from the U.S. Dept. of
 * Energy).  This software was developed under funding from the DOE Office of
 * Advanced Scientific Computing Research* *and is associated with the
 * Berkeley Lab OASCR project. All rights reserved."
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * (2) Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * (3) Neither the name of the University of California, Lawrence Berkeley
 * National Laboratory, U.S. Dept. of Energy nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * *You are under no obligation whatsoever to provide any bug fixes, patches,
 * or upgrades to the features, functionality or performance of the source
 * code ("Enhancements") to anyone; however, if you choose to make your
 * Enhancements available either publicly, or directly to Lawrence Berkeley
 * National Laboratory, without imposing a separate written license agreement
 * for such Enhancements, then you hereby grant the following license: a
 *  non-exclusive, royalty-free perpetual license to install, use, modify,
 * prepare derivative works, incorporate into other computer software,
 * distribute, and sublicense such enhancements or derivative works thereof,
 * in binary and source code form.*
 * 
 * ------------------------------------------------------------------------------
 * Additional URL encoding code taken from stringcoders-v3.10.3 source.  Thanks!
 * ------------------------------------------------------------------------------
 * http://code.google.com/p/stringencoders/
 *
 * Copyright &copy; 2006,2007  Nick Galbreath -- nickg [at] modp [dot] com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 *   Neither the name of the modp.com nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This is the standard "new" BSD license:
 * http://www.opensource.org/licenses/bsd-license.php
 */


#include "includes.h"
#ifdef NERSC_MOD

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "openbsd-compat/sys-queue.h"
#include "ssh.h"
#include "channels.h"
#include "log.h"
#include "misc.h"
#include "xmalloc.h"
#include "version.h"
#include "servconf.h"
#include "readconf.h"
#include "nersc.h"

/* this is for the stringencoders data */
#include "modp_burl.h"
#include "modp_burl_data.h"

/* import */
int audit_disabled;
extern char *__progname;

int client_session_id;
int sis_socket = -1;		  /* socket test varible */
int sis_connect = -1;		  /* connect test variable */
int stun_conn_error = 0;	  /* track the number of connection errors to the stunnel */
int stun_write_error = 0;	  /* track the number of write errors to the stunnel */

char n_ntop[NI_MAXHOST] = "X";
char n_port[NI_MAXHOST] = "X";

extern char *__progname;

static char server_id[128] = "X"; /* 
				   * This is a unique value composed of: 
				   *  <pid><list address><list port>
				   *  used for the lifetime of the process. 
				   *  128 == max reasonable size expected 
				   */
#define NERSCMSGBUF 4096
#define STUN_ERROR_MOD 10	  /* 
				   * Filter the number of errors down by this factor 
				   *  so that on a busy sustem the local syslog is not 
				   *  flooded with anoying and redundant messages 
				   */

char interface_list[256] = "X";   /* 
				   * Contains space delimited list of system interfaces.
				   *   at times we may need more than the host name to 
				   *   determine the system in question.  Fill up and ship
				   *   back to the bro instance to sort out 
				   */

void l_syslog(const char *fmt,...)
{
	/* 
	 * Function filtering accidental printing of log messages to 
	 *   stderr/stdout when logging messages.
	 *
	 * NOTE: for standalong binaries like ssh, some of this code will get
	 *   called since there are common shared objects like channels.o which
	 *   trigger annoying errors to stderr otherwise.   
	 */

	if ( ! log_is_on_stderr() ) {
		va_list args;

		va_start(args, fmt);
		do_log(SYSLOG_LEVEL_INFO, fmt, args);
		va_end(args);
	}
}


int get_client_session_id()
	{
	return client_session_id;
	}

void set_server_id(int parent_pid, char* ntop, int port)
	{
	/* 
	 * This is called to assert the server id from server_listen() 
	 *   in sshd.c .
	 */
	if ( server_id[0] == 'X' ) {
		char hn[64];
		long hid;

		if ( gethostname((char*)hn, 64) == -1 )
			strncpy(hn, "unknown-hostname", sizeof(hn));

		hid = gethostid();
		snprintf(server_id, 64,"%ld:%s:%i", hid, hn, port);
		}
	}	

static char* get_server_id()
	{
	/* 
	 * If this is the first reference to this variable, it may be blank and 
	 *   we can try filing it in via the values set up during the sshd run.
	 */
	char *cp = NULL;
	char *p = NULL;
	long hid;

	if( server_id[0] == 'X' ) {

		hid = gethostid();
		/* 
		 * When invoking subsystems, we may have a situation where the 
		 *   server id will be incomplete.  run an additional test here 
		 *   to make sure that n_top and n_port have been filled.  if not,
		 *   make a sanity guess based on: 
		 *     SSH_CONNECTION=127.0.0.1 33602 127.0.0.1 22
		 */
		if ( n_port[0] == 'X' ) {

			if ((cp = getenv("SSH_CONNECTION")) != NULL) {

				p = strtok(cp," ");			/* src IP */
				p = strtok(NULL, " ");			/* src port */

				if ( (p = strtok(NULL, " ")) != NULL)	/* dst IP */
					strncpy(n_ntop,p,NI_MAXHOST-1);

				if ( (p = strtok(NULL, " ")) != NULL)	/* dst port */
					strncpy(n_port,p,NI_MAXHOST-1);

				bzero(cp, strlen(cp));
			}
			else {
				/* 
				 * Have not been able to extract SSH_CONNECTION from
				 *   the running environment.  WTF?
				 */
				strncpy(n_port, "unknown-port", strlen(n_port));
				strncpy(n_ntop, "unknown-ip", strlen(n_ntop));
			}
		}

		char hn[64];
		gethostname((char*)hn, 64);

		snprintf(server_id, 64,"%ld:%s:%s", hid, hn, n_port);

		return (server_id);
		}
	else
		return (server_id);
	}

int set_interface_list()
{
	int iSocket;
	struct if_nameindex *pIndex, *pIndex2;

	if ( strlen(interface_list) > 1 )
		return 0;
   
	if ((iSocket = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {

		perror("socket");
		bzero(interface_list, sizeof(interface_list));
		interface_list[0] = 'S';
		return -1;
	}

	bzero(interface_list, sizeof(interface_list));

	/* 
	 * if_nameindex() returns an array of if_nameindex structures.  
	 *
	 * if_nametoindex is also defined in <net/if.h>, and is as follows:
	 *
	 *	struct if_nameindex {
	 *		unsigned int   if_index;   1, 2, ... 
	 *		char          *if_name;    null terminated name: "le0", ...
	 * 	}; 
	 */
	pIndex = pIndex2 = if_nameindex();

	/* for an error state, pIndex will be NULL */
	while ((pIndex != NULL) && (pIndex->if_name != NULL)) {

		struct ifreq req;

		strncpy(req.ifr_name, pIndex->if_name, IFNAMSIZ);

		if (ioctl(iSocket, SIOCGIFADDR, &req) < 0) {

			if (errno == EADDRNOTAVAIL) {
				pIndex++;
				continue;
			}

			perror("ioctl");
			bzero(interface_list, sizeof(interface_list));
			interface_list[0] = 'I';
         		close(iSocket);
         
			return -1;
		}

		/* add a delimiter */
		if ( pIndex > pIndex2 )
			strncat(interface_list, "_", 2);

		size_t nl = strlen(inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr));

		if (  nl + strlen(interface_list) + 2 < sizeof(interface_list) ) {

			strncat( interface_list, 
				inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr), 
				sizeof(interface_list) - nl -1);
		}
      
	pIndex++;
	
	}

	if ( pIndex2 != NULL )
		if_freenameindex(pIndex2);

	close(iSocket);

	return 0;
}

static int sis_opentcp(char *hostname, int portnum)
{
	struct sockaddr_in sa = { 0 };
	struct hostent *hp = NULL;
	int s, valopt;
	fd_set myset;
	struct timeval tv;
	socklen_t lon;

	s = -1;
	sis_connect = -1;

	hp = gethostbyname(hostname);
	
	if (hp == NULL) {
		hp = gethostbyaddr(hostname, strlen(hostname), AF_INET);
		if (hp == NULL) {
			l_syslog("error resolving stunnel server address, exiting open");
			return(-1);
		}
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(portnum);
	(void) memcpy(&sa.sin_addr, hp->h_addr, hp->h_length);

	if ((s=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {

		l_syslog("error opening connection to stunnel listener, exiting open");
		return (-1);
	}
	
	/* now make the socket non-blocking */
	if ( fcntl(s,F_SETFL,FNDELAY) == -1) {
		l_syslog("Failure setting socket to no-blocking");
	}

	sis_connect = connect(s, (struct sockaddr *) & sa, sizeof(sa));

	if ( sis_connect < 0 ) {

		/* 
		 * We might be waiting for the connection to complete -
		 *   quick check for that condition.
		 */
		if (errno == EINPROGRESS) {
			/* sit for 2 seconds */
			tv.tv_sec = 2;
			tv.tv_usec = 0;
			FD_ZERO(&myset);
			FD_SET(s, &myset);

			if (select(s+1, NULL, &myset, NULL, &tv) > 0) {
				lon = sizeof(int);
				getsockopt(s, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon);

				if (valopt) {
					if ( ( stun_conn_error % STUN_ERROR_MOD ) == 0 ) {
						l_syslog("connection to stunnel rejected/timeout, exiting open, error = %d, %s" , 
							valopt, strerror(valopt));

						stun_conn_error++;
						close(s);
						sis_connect = -1;
						return(-1);
					}
				}
				else {
					/* sitting around has worked, mark connect as successful */
					sis_connect = 1;
				}
			}
		}
		else {
			/* some simple sanity filtering for connect errors */
			if ( ( stun_conn_error % STUN_ERROR_MOD ) == 0 ) {
				l_syslog("connection to stunnel rejected, exiting open");

				stun_conn_error++;	
				close(s);
				return(-1);
			}
		}
	}

	return(s);
}

static int sis_write(char *buffer)
{
	int err = 0;
	size_t sent = 0;

	if ( sis_connect != -1 && sis_socket != -1)
		sent = send(sis_socket, buffer, strlen(buffer), 0);

	/* this may be a little heavy handed ... */
	if (sent != strlen(buffer) || sis_socket == -1 || sis_connect == -1) {

#ifndef STUNNEL_PORT
	#define	STUNNEL_PORT 799
#endif

#ifndef STUNNEL_HOST
	#define STUNNEL_HOST "localhost"
#endif
		/* 
		 * Close the fd since writes are failing, but only
		 *   if there is an error on it already since that would
		 *   close a socket that was never opened ...
		 */
		if ( stun_write_error > 0 ) {

			close(sis_socket);
			sis_socket = -1;
			sis_connect = -1;

			/* 
			 * Some simple sanity filtering for connect errors 
			 *   this will flag every 10th error starting after #1
			 */
			if ( ( stun_write_error % STUN_ERROR_MOD ) == 1 ) {
				l_syslog("write to stunnel failed, reopening connection");
			}

		}

		stun_write_error++;
		sis_socket = sis_opentcp(STUNNEL_HOST, STUNNEL_PORT);

		if ( sis_socket == -1 || sis_connect == -1 ) {
			err = -1;
		}
		else {
			sent = send(sis_socket, buffer, strlen(buffer), 0);

			err=1; 
		}

	}
	
	return(err);
}


/*
 * Main auditing function called by other code
 * s_audit( <event_name>, <fmt>, <args> );
 */
void s_audit(const char *_event, const char *fmt, ...)
{
	if ( audit_disabled == 1 )
		return;

	va_list args;
	char msgbuf[NERSCMSGBUF] = "";
	char fmtbuf[NERSCMSGBUF] = "";

	struct timeval tv;
	gettimeofday(&tv, NULL);
	
	char* t1buf = encode_string( get_server_id(), strlen(get_server_id()) );
	/* get version string */

	/* 
	 * If --with-nerscmod has not been set in confgure there is no access to
	 *   SSH_AUDITING so we set a token value for the define.
	 */
#ifndef NERSC_MOD
	#define SSH_AUDITING	"XXX"
#endif
	char* t2buf = encode_string( SSH_AUDITING, strlen(SSH_AUDITING) );
	/* get interface list */
	set_interface_list();
	char* t3buf = encode_string( interface_list, strlen(interface_list) );

	/* fmt defines how data provided by args should be formatted */	
	va_start(args, fmt);
	/* copy the data into msgbuf */
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	va_end(args);

	/* copy event and system data in front of the argument data */
	snprintf(fmtbuf, sizeof(fmtbuf), "%s time=%ld.%ld uristring=%s uristring=%s %s\n", _event, tv.tv_sec, (long int)tv.tv_usec, t2buf, t1buf, msgbuf);

	/*write(STDERR_FILENO, fmtbuf, strlen(fmtbuf));  */
	/*syslog(LOG_NOTICE, fmtbuf); */

	/* 
	 * If the socket open fails, sis_write() will return a -1.  for the time
	 *   being we will just let this ride since we will be reporting
	 *   write failures anyway.
	 */
	sis_write(fmtbuf);

	free(t1buf);
	free(t2buf);
	free(t3buf);
}


char* encode_string(const char* src, const int len)
{
	/* take a string and return a pointer to the URI encoded version */
	int new_len = modp_burl_encode_len(len);

	char *url_enc_string;

	url_enc_string = xmalloc(new_len);

	if ( url_enc_string == NULL ) 
		return (char*)src;
	else
		/* 
		 * We do not test the return here since it 
		 *   is done via the call itself.
		 */	
		modp_burl_encode(url_enc_string, src, len);
	
	return url_enc_string;
}

#endif /* NERSC_MOD */
