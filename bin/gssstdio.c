/* $Id: gssstdio.c,v 1.6 2010/04/14 11:26:50 dowdes Exp $ */

/*-
 * Copyright 2009  Morgan Stanley and Co. Incorporated
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*-
 * Copyright (c) 2003 Roland C. Dowdeswell.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/* this include must be before krb5/resolve.conf for things to work */
#include <arpa/nameser.h>

extern char _log_buff[2048];

#include "gssstdio.h"
#include "knc.h"

char *
gstd_get_display_name(gss_name_t client)
{
	OM_uint32	maj;
	OM_uint32	min;
	gss_buffer_desc	buf;
	char		*ret;

	maj = gss_display_name(&min, client, &buf, NULL);
	GSTD_GSS_ERROR(maj, min, NULL, "gss_display_name");

	if ((ret = (char *)malloc(buf.length + 1)) == NULL) {
		LOG(LOG_ERR, ("unable to malloc"));
		gss_release_buffer(&min, &buf);
		return NULL;
	}

	memcpy(ret, buf.value, buf.length);
	ret[buf.length] = '\0';

	gss_release_buffer(&min, &buf);

	return ret;
}

char *
gstd_get_export_name(gss_name_t client)
{
	OM_uint32	maj;
	OM_uint32	min;
	gss_buffer_desc	buf;
	unsigned char   *bufp;
	unsigned char   nibble;
	char		*ret;
	size_t	  i, k;

	maj = gss_export_name(&min, client, &buf);
	GSTD_GSS_ERROR(maj, min, NULL, "gss_export_name");

	if ((ret = (char *)malloc(buf.length * 2 + 1)) == NULL) {
		LOG(LOG_ERR, ("unable to malloc"));
		gss_release_buffer(&min, &buf);
		return NULL;
	}

	for (bufp = buf.value, i = 0, k = 0; i < buf.length; i++) {
		nibble = bufp[i] >> 4;
		ret[k++] = "0123456789ABCDEF"[nibble];
		nibble = bufp[i] & 0x0f;
		ret[k++] = "0123456789ABCDEF"[nibble];
	}

	ret[k] = '\0';
	gss_release_buffer(&min, &buf);

	return ret;
}

#define KNC_KRB5_MECH_OID "\052\206\110\206\367\022\001\002\002"

char *
gstd_get_mech(gss_OID mech_oid)
{
#ifdef HAVE_GSS_OID_TO_STR
	OM_uint32	maj;
	OM_uint32	min;
#endif
	gss_buffer_desc	buf;
	char		*ret;

	if (mech_oid->length == sizeof(KNC_KRB5_MECH_OID) - 1 &&
	    memcmp(mech_oid->elements, KNC_KRB5_MECH_OID,
		   sizeof(KNC_KRB5_MECH_OID) - 1) == 0) {
		if ((ret = strdup("krb5")) == NULL) {
			LOG(LOG_ERR, ("unable to malloc"));
			return NULL;
		}
		return ret;
	}

#ifdef HAVE_GSS_OID_TO_STR
	maj = gss_oid_to_str(&min, mech_oid, &buf);
	if (maj != GSS_S_COMPLETE) {
		LOG(LOG_ERR, ("unable to display mechanism OID"));
		return NULL;
	}
	ret = strndup(buf.value, buf.length);
#else
	ret = strdup("");
#endif
	if (!ret)
		LOG(LOG_ERR, ("unable to malloc"));
	return ret;
}


/*
 * The following function writes up to len bytes, returning -1 if it fails
 * to do so for any reason, and len otherwise.  Note, partial writes may
 * have occurred if this function returns -1
 */
ssize_t
writen(int fd, const void *buf, ssize_t len) {
	ssize_t nleft;
	ssize_t nwritten;
	const char *buffer = buf;

	nleft = len;
	while (nleft > 0) {
		nwritten = write(fd, buffer, len);

		if (nwritten < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				LOG_ERRNO(LOG_ERR, ("write failed"));
				return -1;
			}
		} else {
			nleft -= nwritten;
			buffer += nwritten;
		}
	}

	LOG(LOG_DEBUG, ("wrote %d bytes", len));
	return len;
}


static int
gstd_errstring(char **str, int min_stat)
{
	gss_buffer_desc	 status;
	OM_uint32	 new_stat;
	OM_uint32	 msg_ctx = 0;
	OM_uint32	 ret;
	int		 len = 0;
	char		*tmp;
	char		*statstr;

	/* XXXrcd this is not correct yet */
	/* XXXwps ...and now it is. */

	if (!str)
		return -1;

	*str = NULL;
	tmp = NULL;

	do {
		ret = gss_display_status(&new_stat, min_stat,
		    GSS_C_MECH_CODE, GSS_C_NO_OID, &msg_ctx,
		    &status);

		/* GSSAPI strings are not NUL terminated */
		if ((statstr = (char *)malloc(status.length + 1)) == NULL) {
			LOG(LOG_ERR, ("unable to malloc status string "
				      "of length %ld", status.length));
			gss_release_buffer(&new_stat, &status);
			free(statstr);
			free(tmp);
			return 0;
		}

		memcpy(statstr, status.value, status.length);
		statstr[status.length] = '\0';

		if (GSS_ERROR(ret)) {
			free(statstr);
			free(tmp);
			break;
		}

		if (*str) {
			if ((*str = malloc(strlen(*str) + status.length +
					   3)) == NULL) {
				LOG(LOG_ERR, ("unable to malloc error "
						"string"));
				gss_release_buffer(&new_stat, &status);
				free(statstr);
				free(tmp);
				return 0;
			}

			len = sprintf(*str, "%s, %s", tmp, statstr);
		} else {
			*str = malloc(status.length + 1);
			if (!*str) {
				LOG(LOG_ERR, ("unable to malloc error "
						"string"));
				gss_release_buffer(&new_stat, &status);
				free(statstr);
				free(tmp);
				return 0;
			}
			len = sprintf(*str, "%s", (char *)statstr);
		}

		gss_release_buffer(&new_stat, &status);
		free(statstr);
		free(tmp);

		tmp = *str;
	} while (msg_ctx != 0);

	return len;
}

void
gstd_error(int pri, int min_stat, const char *s)
{
	char *t1;

	if (gstd_errstring(&t1, min_stat) < 1)
		LOG(pri, ("%s: couldn't form GSSAPI error string", s));
	else {
		LOG(pri, ("%s: %s", s, t1));
		free(t1);
	}
}
