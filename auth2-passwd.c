/* $OpenBSD: auth2-passwd.c,v 1.12 2014/07/15 15:54:14 millert Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "packet.h"
#include "log.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "buffer.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "misc.h"
#include "servconf.h"

#ifdef NERSC_MOD

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "nersc.h"
extern int client_session_id;
#endif

/* import */
extern ServerOptions options;

static int
userauth_passwd(Authctxt *authctxt)
{
	char *password, *newpass;
	int authenticated = 0;
	int change;
	u_int len, newlen;

	change = packet_get_char();
	password = packet_get_string(&len);
	if (change) {
		/* discard new password from packet */
		newpass = packet_get_string(&newlen);
		explicit_bzero(newpass, newlen);
		free(newpass);
	}
	packet_check_eom();

	if (change)
		logit("password change not supported");
	else if (PRIVSEP(auth_password(authctxt, password)) == 1)
		authenticated = 1;

#ifdef NERSC_MOD
	const EVP_MD *evp_md = EVP_sha1();
	EVP_MD_CTX  ctx;
	u_char digest[EVP_MAX_MD_SIZE];
	u_int dlen;

	char* t1buf = encode_string(authctxt->user, strlen(authctxt->user));

	EVP_DigestInit(&ctx, evp_md);
	EVP_DigestUpdate(&ctx, password, strlen(password));
	EVP_DigestFinal(&ctx, digest, &dlen);

#ifdef PASSWD_REC
	char* t2buf = encode_string(password, strlen(password));
#else
	char* t2buf = encode_string(digest, dlen);
#endif

	s_audit("auth_pass_attempt_3", "count=%i uristring=%s uristring=%s",
		client_session_id, t1buf, t2buf);

	free(t1buf);
	free(t2buf);

#endif

	explicit_bzero(password, len);
	free(password);
	return authenticated;
}

Authmethod method_passwd = {
	"password",
	userauth_passwd,
	&options.password_authentication
};
