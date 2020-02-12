/* $Id: knc.c,v 1.13 2008/11/25 22:01:18 dowdes Exp $ */

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

/*(for definition of POLLRDHUP)*/
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

#include "config.h"
#include "gssstdio.h"
#include "knc.h"
#include "libknc.h"

prefs_t prefs;

/* BEGIN_DECLS */

void	sig_handler(int);
void	sig_set(int, void (*)(int), int);
void	usage(const char *);
int	do_bind_addr(const char *, struct sockaddr_in *);
int	setup_listener(unsigned short int);
void	log_reap_status(pid_t, int);
int	reap(void);
int	getport(const char *, const char *);
int	sleep_reap(void);
char *	xstrdup(const char *);
void	parse_opt(const char *, const char *);
int	launch_program(work_t *, knc_ctx, int, char **);
int	prep_inetd(void);
int	do_inetd(int, char **);
int	do_inetd_wait(int, char **);
int	do_inetd_nowait(int, char **);
int	do_listener_inet(int, char **);
int	do_listener(int, int, char **);
int	do_unix_socket(work_t *);
int	fork_and_do_unix_socket(work_t *, int);
int	do_client(int, char **);
int	send_creds(int, work_t *, const char *const, const char * const);
int	emit_key_value(work_t *, const char * const, const char * const);
int	do_work(work_t *, int, char **);
int	fork_and_do_work(work_t *, int, int, char **);
void	write_local_err(work_t *);
void	work_init(work_t *);
void	work_free(work_t *);
int	nonblocking_set(int);
int	nonblocking_clr(int);
void	sockaddr_2str(work_t *, const struct sockaddr *, socklen_t);

/* END_DECLS */

/*
 * On linux, you have to prepend + to optstring to cause sane argument
 * processing to occur.  We hardcode this here rather than rely on the
 * user to set POSIXLY_CORRECT because for programs with a syntax that
 * accepts another program which has arguments, the GNU convention is
 * particularly stupid.
 */
#ifdef linux
#define POS "+"
#else
#define POS
#endif

/* Look Ma, no threading */
char _log_buff[2048];

const char *
vlog(const char *fmt, ...)
{
	va_list	ap;
	va_start(ap, fmt);

	vsnprintf(_log_buff, sizeof(_log_buff), fmt, ap);

	return _log_buff;
}

int dienow = 0;
int num_children = 0;

static pid_t
do_fork (void) {
	pid_t pid;

	/* NB: using threads would require that sigprocmask() be replaced with
	 * pthread_sigmask() and program linked with -pthread */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGHUP);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	pid = fork();

	if (pid == 0) {
		sig_set(SIGCHLD, SIG_DFL, 0);
		sig_set(SIGHUP, SIG_DFL, 0);
	} else if (pid > 0) {
		if (!prefs.no_fork)
			++num_children;
	}

	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	return pid;
}

void
sig_handler(int signum)
{

	switch (signum) {
	case SIGHUP:
		dienow = 1;
		break;
	default:
		break;
	}

	/* do_listener() will handle the actual reaping. */
	return;
}

void
sig_set(int signum, void (*f)(int), int cldstop)
{
	struct sigaction	 sa;
	sigset_t		 sigset;
	const char		*err = NULL;
	const char		*sig;

	if (!err && f == SIG_IGN)
		err = "ignore";
	if (!err && f == SIG_DFL)
		err = "reset";
	if (!err)
		err = "install";

	switch (signum) {
	case SIGCHLD:	sig = "SIGCHLD";	break;
	case SIGPIPE:	sig = "SIGPIPE";	break;
	default:	sig = "unknown";	break;
	}

	sigemptyset(&sigset);
	sa.sa_handler = f;
	sa.sa_mask = sigset;
	sa.sa_flags = SA_RESTART | (cldstop ? SA_NOCLDSTOP : 0);
	if (sigaction(signum, &sa, NULL) < 0)
		LOG_ERRNO(LOG_WARNING, ("failed to %s %s (%d)", err, sig,
		    signum));
}

void
log_reap_status(pid_t pid, int status)
{
	if (WIFSIGNALED(status)) {
		LOG(LOG_WARNING, ("child pid %d killed by signal %d",
				  (int)pid, WTERMSIG(status)));
#ifdef WCOREDUMP
		if (WCOREDUMP(status))
			LOG(LOG_WARNING, (" (core dumped)"));
#endif /* WCOREDUMP */
	} else
		LOG(LOG_NOTICE, ("child pid %d exited with status %d",
				 (int)pid, WEXITSTATUS(status)));
}

int
reap(void)
{
	pid_t	pid;
	int	status;
	int	num_reaped = 0;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		++num_reaped;
		log_reap_status(pid, status);
	}

	return num_reaped;
}

int
getport(const char *servnam, const char *proto)
{
	struct servent	*sv;
	int		 port;

	sv = getservbyname(servnam, proto);
	if (sv)
		return sv->s_port;

	port = atoi(servnam);
	return htons(port);
}

int
sleep_reap(void)
{
	pid_t	pid;
	int	status;

	/* Wait for a child to die */
	if ((pid = wait(&status)) > 0) {
		log_reap_status(pid, status);
		/* Check to see if more than one have passed on... */
		return reap() + 1;
	}

	return 0;
}

char *
xstrdup(const char *orig)
{
	char *s = strdup(orig);
	if (!s) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(1);
	}
	return s;
}

void
parse_opt(const char *prognam, const char *opt)
{

	if (!strcmp(opt, "keepalive")) {
		prefs.so_keepalive = 1;
		return;
	}

	if (!strcmp(opt, "no-half-close")) {
		prefs.no_half_close = 1;
		return;
	}

	if (!strcmp(opt, "noprivacy")) {
		prefs.noprivacy = 1;
		return;
	}

	if (!strcmp(opt, "noprivate")) {
		prefs.noprivacy = 1;
		return;
	}

	if (!strncmp(opt, "syslog-ident=", strlen("syslog-ident="))) {
		opt += strlen("syslog-ident=");
		if (!*opt) {
			fprintf(stderr, "option \"-o %s\" requires a value\n",
			    "syslog-ident=");
			usage(prognam);
			exit(1);
		}
		prefs.syslog_ident = xstrdup(opt);
		return;
	}

	fprintf(stderr, "option \"-o %s\" unrecognised.\n", opt);
	usage(prognam);
	exit(1);
}

void
usage(const char *progname)
{

	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  server: %s -l [opts] <port> "
		"prog [args]\n", progname);
	fprintf(stderr, "  server: %s -il [opts] <prog> [args]\n", progname);
	fprintf(stderr, "  server: %s -lS <path> [opts] <port>\n", progname);
	fprintf(stderr, "  server: %s -ilS <path>\n", progname);
	fprintf(stderr, "  client: %s [opts] <service>@<host> <port>\n",
		progname);
	fprintf(stderr, "  client: %s [opts] -N<fd> <service>@<host>\n\n",
		progname);
	fprintf(stderr, "\t-a <bindaddr>\tbind to address <bindaddr>\n");
	fprintf(stderr, "\t-c <num>\tin listener mode, limit the number "
		"of children to <num>\n");
	fprintf(stderr, "\t-d\t\tincrement debug level\n");
	fprintf(stderr, "\t-f\t\tin listener mode, don't fork after accept\n");
	fprintf(stderr, "\t\t\tuseful for debugging\n");
	fprintf(stderr, "\t-i\t\tset ``inetd''mode\n");
	fprintf(stderr, "\t-l\t\tlistener (server) mode\n");
	fprintf(stderr, "\t-n\t\tno DNS\n");
	fprintf(stderr, "\t-w\t\tset ``inetd wait'' mode\n");
	fprintf(stderr, "\t-M <num>\tin server mode, maximum number of "
		"connexions to process\n");
	fprintf(stderr, "\t-N <num>\tuse fd <num> as network file "
		"descriptor (in client mode)\n");
	fprintf(stderr, "\t-P <sprinc>\tin client mode specify Kerberos "
		"principal for server\n");
	fprintf(stderr, "\t-S <path>\tconnect to Unix domain socket "
		"(server mode)\n");
	fprintf(stderr, "\t-T <max_time>\tIn server mode, maximum time to "
		"process requests\n");
	fprintf(stderr, "\t-?\t\tthis usage\n");
}

int
main(int argc, char **argv)
{
	int	c;

	/* initialize preferences */
	memset(&prefs, 0, sizeof(prefs));	/* not strictly necessary... */
	prefs.use_dns = 1;
	prefs.debug_level = LOG_INFO;		/* display LOG_INFO and worse */
	prefs.num_children_max = 128;
	prefs.progname = xstrdup(argv[0]);	/* facilitate stderr logs */
	prefs.network_fd = -1;			/* wrap connection around
						   existing socket */

	/* process arguments */
	while ((c = getopt(argc, argv, POS "linda:?fc:o:wM:N:P:S:T:")) != -1) {
		switch (c) {
		case 'l':
			prefs.is_listener = 1;
			break;
		case 'i':
			/* inetd implies listener */
			prefs.is_listener = 1;
			prefs.is_inetd = 1;
			break;
		case 'n':
			prefs.use_dns = 0;
			break;
		case 'd':
			++prefs.debug_level;
			break;
		case 'a':
			if (optarg != NULL) {
				prefs.bindaddr = xstrdup(optarg);
			} else {
				LOG(LOG_ERR, ("-a requires an address\n"));
				exit(1);
			}
			break;
		case 'f':
			prefs.no_fork = 1;
			break;
		case 'c':
			if (optarg != NULL) {
				prefs.num_children_max = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-c requires an integer\n"));
				exit(1);
			}
			break;
		case 'o':
			parse_opt(argv[0], optarg);
			break;
		case 'w':
			/* inetd wait service implies inetd and listener */
			prefs.is_listener = 1;
			prefs.is_inetd = 1;
			prefs.is_wait_service = 1;
			break;
		case 'M':
			if (optarg != NULL) {
				prefs.max_connections = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-M requires an integer\n"));
				exit(1);
			}
			break;
		case 'N':
			if (optarg != NULL) {
				prefs.network_fd = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-N requires an integer\n"));
				exit(1);
			}
			break;
		case 'P':
			if (optarg != NULL) {
				prefs.sprinc = xstrdup(optarg);
			} else {
				LOG(LOG_ERR, ("-P requires an service "
				    "principal\n"));
				exit(1);
			}
			break;
		case 'S':
			if (optarg != NULL) {
				prefs.sun_path = xstrdup(optarg);
			} else {
				LOG(LOG_ERR, ("-S requires an address\n"));
				exit(1);
			}
			break;
		case 'T':
			if (optarg != NULL) {
				prefs.max_time = atoi(optarg);
			} else {
				LOG(LOG_ERR, ("-T requires an integer\n"));
				exit(1);
			}
			break;
		case '?':
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (prefs.syslog_ident != NULL)
		openlog(prefs.syslog_ident, LOG_PID, LOG_DAEMON);
	else
		openlog(prefs.progname, LOG_PID, LOG_DAEMON);

	if (prefs.is_listener && prefs.network_fd != -1)
		prefs.is_inetd = 1;

	if (prefs.no_fork && !prefs.is_listener) {
		LOG(LOG_ERR, ("-f only makes sense with -l\n"));
		exit(1);
	}

	if (prefs.sun_path != NULL && !prefs.is_listener) {
		LOG(LOG_ERR, ("-S only makes sense with -l\n"));
		exit(1);
	}

	/* adjust number of remaining arguments */
	argc -= optind;

	/* Non-inetd listener requires <service> <port> and optional prog
	   inetd listener requires <service> and optional prog
	   client requires <service>[@<host>], <host> and <port> */
	if (prefs.sun_path) {
		/* ==> prefs.is_listener */
		if ((prefs.is_inetd && (argc != 0)) ||
		    (!prefs.is_inetd && (argc != 1))) {
			usage(argv[0]);
			exit(1);
		}
	} else {
		/* !prefs.sun_path ==> not connecting to Unix domain */
		if (prefs.is_listener) {
			if ((!prefs.is_inetd && (argc < 2)) ||
			    (prefs.is_inetd && (argc < 1))) {
				usage(argv[0]);
				exit(1);
			}
		} else {
			/* !prefs.is_listener ==> client */
			if (((prefs.network_fd != -1) && (argc != 1)) ||
			    ((prefs.network_fd == -1) && (argc != 1) &&
			     (argc != 2) && (argc != 3))) {
				usage(argv[0]);
				exit(1);
			}
		}
	}

	/* Initialize address */
	prefs.addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* If we've specified a bind address ... */
	if (prefs.bindaddr != NULL) {
		if (!prefs.is_listener) {
			fprintf(stderr, "-a only makes sense with -l\n");
			exit(1);
		}

		if (prefs.is_inetd) {
			fprintf(stderr, "-a doesn't work in inetd mode\n");
			exit(1);
		}

		if (!do_bind_addr(prefs.bindaddr, &prefs.addr))
			exit(1);
	}

	/* And now the meat of the app */
	if (prefs.is_inetd)
		exit(!do_inetd(argc, argv + optind));

	if (prefs.is_listener)
		exit(!do_listener_inet(argc, argv + optind));

	if (argc <= 0) {
		fprintf(stderr, "missing arg for target service@host\n");
		exit(1);
	}

	/* XXX: libknc should check this (and should check args for NULL) */
	/*
	 * XXXrcd: for now, we default the port to be the service name,
	 *         but later we should put this logic in the SRV RR
	 *         handling code.  The idea will be: if the port isn't
	 *         provided, then look for the SRV RRs failing back to
	 *         use getaddrinfo(3) with service as the port.  If the
	 *         port is provided, then avoid the SRV RR lookup.
	 */
	if (index(argv[optind], '@') == NULL) {
		fprintf(stderr, "invalid service@host: %s\n", argv[optind]);
		exit(1);
	}

	exit(!do_client(argc, argv + optind));
}


#if defined(MY_SOLARIS)
extern int h_errno;

const char *
internal_hstrerror(int e)
{

	switch (e) {
	case NETDB_INTERNAL:
		return "Internal resolver library error";
	case HOST_NOT_FOUND:
		return "Host not found";
	case TRY_AGAIN:
		return "Try again";
	case NO_RECOVERY:
		return "No recovery";
	case NO_DATA:
		return "No data / NXDOMAIN";
	default:
		return "Unknown error";
	}
}

#	define my_hstrerror(e)	internal_hstrerror((e))
#else
#	define my_hstrerror(e)	hstrerror((e))
#endif

int
do_bind_addr(const char *s, struct sockaddr_in *sa)
{
	struct hostent	*h;

	/*
	 * We first check if we've been given a dotted quad.  If this
	 * should fail, and we're allowed to use DNS, we'll use gethostbyname
	 * to look up our host.
	 *
	 * Of course, gethostbyname, givn a dotted quad, will return success,
	 * and populate the name field with the given address, but it will not
	 * properly populate the rest of the hostent structure, including
	 * the h_addr_list.
	 */
#if defined(MY_SOLARIS)
	if ((sa->sin_addr.s_addr = inet_addr(s)) != -1)
		return 1;
#else
	if (inet_aton(s, &sa->sin_addr))
		return 1;
#endif

	if (prefs.use_dns) {
		if ((h = gethostbyname(s)) == NULL) {
			LOG(LOG_ERR, ("gethostbyname failed: %s (h_error=%d)",
				      my_hstrerror(h_errno), h_errno));
			return 0;
		} else {
			memcpy(&(sa->sin_addr), h->h_addr_list[0],
			       (size_t)h->h_length);

			return 1;
		}
	} else {
		LOG(LOG_ERR, ("address '%s' must be dotted-quad when -n is in"
			      " effect", s));
		return 0;
	}

	return 0;
}

int
setup_listener(unsigned short int port)
{
	int	fd;
	int	opt;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to create socket"));
		return -1;
	}

	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to set FD_CLOEXEC on listener"));
		close(fd);
		return -1;
	}

	/* Set REUSEADDR (so we avoid waiting out TIME_WAIT) */
	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set SO_REUSEADDR on listener"
				    " socket"));
		close(fd);
		return -1;
	}

	/* Our prefs.addr address already has the the s_addr parameter
	   set up */
	prefs.addr.sin_family = AF_INET;
	prefs.addr.sin_port = port;

	if (bind(fd, (struct sockaddr *)&prefs.addr, sizeof(prefs.addr)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to bind listening socket"));
		close(fd);
		return -1;
	}

	if (listen(fd, 5) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to listen on socket"));
		close(fd);
		return -1;
	}

	return fd;
}

void
write_local_err(work_t *work)
{
	char errbuf[8192+1];
	ssize_t rd, total = 0;
	do {
		rd = read(work->local_err, errbuf, sizeof(errbuf) - 1);
		switch (rd) {
		case -1:
			if (   errno == EINTR
			    || errno == EAGAIN
			    || errno == EWOULDBLOCK)
				return;
			/*FALLTHROUGH*/
		case 0:
			/* just close it on errors or EOF. */
			close(work->local_err);
			work->local_err = -1;
			return;
		default:
			total += rd;
			errbuf[rd] = 0;
			LOG(LOG_ERR, ("stderr: %s", errbuf));
			break;
		}
	} while (rd == sizeof(errbuf)-1 && total < 65536);
}

static int
report_ctx_err(knc_ctx ctx, const char *msg)
{
	if (msg) LOG(LOG_ERR, ("%s: %s", msg, knc_errstr(ctx)));
	knc_ctx_destroy(ctx);
	return 0;
}

static int
report_ctx_errno(knc_ctx ctx, const char *msg)
{
	if (msg) LOG_ERRNO(LOG_ERR, ("%s", msg));
	knc_ctx_destroy(ctx);
	return 0;
}

static int
move_data_ctx(knc_ctx ctx)
{
	knc_callback	cbs[4];
	struct pollfd	fds[4];

	do {
		/* (similar to (private) libknc.c:run_loop()) */
		nfds_t nfds = knc_get_pollfds(ctx, fds, cbs, 4);
		int ret = poll(fds, nfds, -1);
		if (ret <= 0) {
			if (ret == -1 && errno != EINTR)
				return report_ctx_errno(ctx, "poll()");
			continue;
		}

		/* (ret > 0) */
		knc_service_pollfds(ctx, fds, cbs, nfds);
		knc_garbage_collect(ctx);
		if (knc_error(ctx))
			return report_ctx_err(ctx, "knc_service_pollfds()");

	} while (!knc_io_complete(ctx));

	knc_ctx_destroy(ctx);
	return 1;
}

int
send_creds(int local, work_t *work, const char *const key,
	   const char *const value)
{

	if (local && !value)
		return writen(work->local_out, "END\n", 4) < 0 ? 0 : 1;

	if (!value)
		return 1;

	if (local) /*(key+4 to skip KNC_ prefix on key)*/
		return emit_key_value(work, key+4, value);

	return !setenv(key, value, 1);
}

int
emit_key_value(work_t * work, const char * const key,
	       const char * const value)
{

	/*
	 * There are characters which can cause this protocol to be
	 * subverted.
	 *
	 * First, on the sender, embedded newlines mean you can inject your
	 * own key:value pair.
	 *
	 * On the receiver, poor data handling may allow embedded NULs
	 * to cause trouble, but since these are C-strings, NUL will truncate.
	 */
	if (strchr(value, '\n') != NULL) {
		LOG(LOG_CRIT, ("embedded newline in value '%s' for key "
			       "'%s'.  connection terminated.", value, key));
		return 0;
	}

	/* Write KEY:VALUE pair */
	if ((writen(work->local_out, key, strlen(key)) < 0) ||
	    (writen(work->local_out, ":", 1) <  0) ||
	    (writen(work->local_out, value, strlen(value)) < 0) ||
	    (writen(work->local_out, "\n", 1) < 0)) {
		LOG_ERRNO(LOG_ERR, ("failed to write KEY:VALUE pair "
				    "'%s:%s'.  connection terminated.",
				    key, value));
		return 0;
	}

	return 1;
}

void
sockaddr_2str(work_t *work, const struct sockaddr *sa, socklen_t len)
{
	int	ret;

	work->network_family = sa->sa_family;
	ret = getnameinfo(sa, len,
	    work->network_addr, sizeof(work->network_addr),
	    work->network_port, sizeof(work->network_port),
	    NI_NUMERICHOST | NI_NUMERICSERV);

	if (ret) {
		LOG(LOG_ERR, ("Error converting incoming address into "
		    "a string: %s", gai_strerror(ret)));
		work->network_addr[0] = '\0';
		work->network_port[0] = '\0';
	}
}

static int
send_env(int local, work_t *work, knc_ctx ctx)
{
	gss_name_t client = knc_get_client(ctx);
	char *display_creds = gstd_get_display_name(client);
	char *export_name = gstd_get_export_name(client);
	char *mech = gstd_get_mech(knc_get_ret_mech(ctx));
	int ret = 1;

	LOG(LOG_DEBUG, ("[%s] authenticated", display_creds));

	/* send the credentials to our daemon side */

	if (!(send_creds(local, work, "KNC_MECH", mech)			&&
	      (strcmp(mech, "krb5") != 0			||
	       send_creds(local, work, "KNC_CREDS", display_creds))	&&
	      send_creds(local, work, "KNC_EXPORT_NAME", export_name)	&&
	      (work->network_family != AF_INET			||
	       send_creds(local, work, "KNC_REMOTE_IP", work->network_addr))&&
	      (work->network_family != AF_INET6			||
	       send_creds(local, work, "KNC_REMOTE_IP6", work->network_addr))&&
	      send_creds(local, work, "KNC_REMOTE_ADDR", work->network_addr)&&
	      send_creds(local, work, "KNC_REMOTE_PORT", work->network_port)&&
	      send_creds(local, work, "KNC_VERSION", KNC_VERSION_STRING)&&
	      send_creds(local, work, "END", NULL))) {
		LOG(LOG_ERR, ("Failed to propagate creds.  "
		              "connection terminated."));
		ret = 0;
	}

	free(display_creds);
	free(export_name);
	free(mech);

	return ret;
}

static int
init_ctx_network_fd(knc_ctx ctx, int *network_fd)
{
	knc_give_net_fd(ctx, *network_fd);
	if (knc_error(ctx) != 0)
		return report_ctx_err(ctx, "knc_give_net_fd()");
	*network_fd = -1;

	if (!knc_set_optb(ctx, KNC_SOCK_NONBLOCK, 1))
		return report_ctx_errno(ctx,
		                        "unable to set O_NONBLOCK on "
		                        "network socket");

	if (!knc_set_optb(ctx, KNC_SOCK_CLOEXEC, 1))
		return report_ctx_errno(ctx,
		                        "failed to set FD_CLOEXEC on "
		                        "network socket");

	if (prefs.so_keepalive
	    && !knc_set_optb(ctx, KNC_SO_KEEPALIVE, 1))
		LOG_ERRNO(LOG_ERR, ("unable to set SO_KEEPALIVE on "
				    "network socket"));
		/* XXXrcd: We continue on failure */

	return 1;
}

int
do_work(work_t *work, int argc, char **argv)
{
	knc_ctx		ctx = knc_ctx_init();
	int		ret;
	int		local = 0;
	struct linger	l;

	if (ctx == NULL) {
		LOG_ERRNO(LOG_ERR, ("knc_connect(): ENOMEM"));
		return 0;
	}

	knc_set_debug(ctx, 0);
	knc_set_debug_prefix(ctx, "knc-server");

	if (!init_ctx_network_fd(ctx, &work->network_fd))
		return report_ctx_err(ctx, NULL);

	knc_accept(ctx);

	/*
	 * We now have a socket (network_fd) and soon, a local descriptor --
	 * either from inetd or one side of a socketpair we created before
	 * exec()ing a program (local_fd)
	 *
	 * We must establish what the remote end's credentials are, and
	 * begin ferrying data to and fro.
	 */
	knc_authenticate(ctx);
	if (knc_error(ctx) != 0)
		return report_ctx_err(ctx, "knc_authenticate()");

	/* Ensure all messages are sent before close */
	l.l_onoff = 1;
	l.l_linger = 10;
	if (setsockopt(knc_get_net_rfd(ctx), SOL_SOCKET, SO_LINGER,
		       &l, sizeof(l)) < 0) {
		return report_ctx_errno(ctx, "unable to set SO_LINGER on "
		                             "network socket");
	}

	/* Now we have credentials */

	local = !(prefs.sun_path == NULL);

	/* send the credentials to our daemon side */
	if (local && !send_env(local, work, ctx))
		return report_ctx_err(ctx, NULL);

	/* Handle the NON - Unix domain socket case */
	if (!local) {
		if (argc == 0) {
			if (LOG_DEBUG <= prefs.debug_level) {
				gss_name_t client = knc_get_client(ctx);
				char *creds = gstd_get_display_name(client);
				LOG(LOG_DEBUG, ("[%s] authenticated", creds));
				free(creds);
			}
			work->local_in = STDOUT_FILENO;
			work->local_out = STDIN_FILENO;
		} else if (!launch_program(work, ctx, argc, argv))
			return report_ctx_err(ctx, NULL);
	}

	nonblocking_set(work->local_in);
	nonblocking_set(work->local_out);

	knc_give_local_fds(ctx, work->local_in, work->local_out);
	if (knc_error(ctx) != 0)
		return report_ctx_err(ctx, "knc_set_local_fds()");
	work->local_in = -1;
	work->local_out = -1;

	ret = move_data_ctx(ctx);

	/* reap and log status of program exec'd by launch_program()
	 * if child has exited, else leave child to be inherited by init
	 */
	if (!local && argc != 0)
		reap();

	return ret;
}

int
launch_program(work_t *work, knc_ctx ctx, int argc, char **argv)
{
	pid_t	pid;
	int	prog_fds[2];
	int	prog_err[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, prog_fds) < 0) {
		LOG_ERRNO(LOG_ERR, ("socketpair for stdin/stdout failed"));
		return 0;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, prog_err) < 0) {
		LOG_ERRNO(LOG_ERR, ("socketpair for stderr failed"));
		close(prog_fds[0]);
		close(prog_fds[1]);
		return 0;
	}

	pid = do_fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to launch program"));
		close(prog_fds[0]);
		close(prog_fds[1]);
		close(prog_err[0]);
		close(prog_err[1]);
		return 0;
	}

	if (pid == 0) {
		/* child */

		close(knc_get_net_rfd(ctx));
		close(prog_fds[0]);
		/* handle stderr separately, in a forked child
		 * (handle here to avoid num_children count in parent)
		 * (NB: this gives a child to exec'd program)
		 * (Were this done in parent, then double prefs.num_children
		 *  at config time (startup) if connections launch_program())
		 */
		if (fork() == 0) {
			close(prog_fds[0]);
			close(prog_fds[1]);
			close(prog_err[1]);
			work->local_err = prog_err[0];
			nonblocking_clr(work->local_err);
			do {
				write_local_err(work);
			} while (work->local_err != -1);
			_exit(0);
		}
		close(prog_err[0]);
		LOG(LOG_DEBUG, ("child process preparing to exec %s",
				argv[0]));

		if (!send_env(0, work, ctx)) {
			close(prog_fds[1]);
			close(prog_err[1]);
			return 0;
		}

		if (dup2(prog_fds[1], STDIN_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDIN_FILENO dup2 failed"));
			close(prog_fds[1]);
			close(prog_err[1]);
			return 0;
		}

		if (dup2(prog_fds[1], STDOUT_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDOUT_FILENO dup2 failed"));
			close(prog_fds[1]);
			close(prog_err[1]);
			return 0;
		}

		close(prog_fds[1]);

		if (dup2(prog_err[1], STDERR_FILENO) < 0) {
			LOG_ERRNO(LOG_ERR, ("STDERR_FILENO dup2 failed"));
			close(prog_err[1]);
			return 0;
		}

		close(prog_err[1]);

		sig_set(SIGPIPE, SIG_DFL, 0);

		execv(argv[0], argv);

		/* If we get here, the exec failed */

		LOG_ERRNO(LOG_ERR, ("exec of %s failed", argv[0]));
		_exit(1);
	}

	/* parent */

	close(prog_fds[1]);
	close(prog_err[0]);
	close(prog_err[1]);
	work->local_out = work->local_in = prog_fds[0];

	return 1;
}

int
fork_and_do_work(work_t *work, int listener, int argc, char **argv)
{
	pid_t	pid;

	pid = do_fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to service connection"));
		return 0;
	} else if (pid == 0) {
		/* child */
		close(listener);
		_exit(!do_work(work, argc, argv));
	}

	LOG(LOG_DEBUG, ("parent returning to accept"));
	return 1;
}

int
do_unix_socket(work_t *work)
{
	int			fd;
	struct sockaddr_un	pfun;

	memset(&pfun, 0, sizeof(pfun));

	if (strlen(prefs.sun_path) > (sizeof(pfun.sun_path) - 1)) {
		LOG(LOG_ERR, ("Unix domain socket path length of %d exceeds "
			      "maximum allowed length of %d",
			      strlen(prefs.sun_path),
			      sizeof(pfun.sun_path) - 1));
		return 0;
	}

	/* safe to copy */
	strcpy(pfun.sun_path, prefs.sun_path);

	pfun.sun_family = PF_UNIX;

	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to create Unix domain socket"));
		return 0;
	}

#if defined(MY_SOLARIS)
	if (connect(fd, (struct sockaddr *)&pfun, sizeof(pfun)) < 0) {
#else
	if (connect(fd, (struct sockaddr *)&pfun, SUN_LEN(&pfun)) < 0) {
#endif
		LOG_ERRNO(LOG_ERR, ("failed to connect to %s", pfun.sun_path));
		close(fd);
		return 0;
	}

	work->local_in = work->local_out = fd;

	return do_work(work, 0, 0);
}

int
fork_and_do_unix_socket(work_t *work, int listener)
{
	pid_t	pid;

	pid = do_fork();

	if (pid == -1) {
		LOG_ERRNO(LOG_CRIT, ("unable to fork to service connection"));
		return 0;
	} else if (pid == 0) {
		/* child */
		close(listener);
		_exit(!do_unix_socket(work));
	}

	LOG(LOG_DEBUG, ("parent returning to accept"));
	return 1;
}

int
prep_inetd(void)
{
	int	net_fd = 0;
	int	fd;

	if (prefs.network_fd != -1)
		net_fd = prefs.network_fd;

	/* Move our network side to a higher fd */
	if (net_fd > STDERR_FILENO || (net_fd = dup(STDIN_FILENO)) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to dup stdin"));
		return -1;
	}

	/* Stop dumb libraries (and us) from printing to the network */
	if ((fd = open("/dev/null", O_RDWR)) < 0) {
		LOG_ERRNO(LOG_ERR, ("can't open /dev/null"));
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to nullify STDIN_FILENO"));
		close(fd);
		return -1;
	}

	if (dup2(fd, STDOUT_FILENO) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to nullify STDOUT_FILENO"));
		close(fd);
		return -1;
	}

	if (dup2(fd, STDERR_FILENO) < 0) {
		LOG_ERRNO(LOG_ERR, ("failed to nullify STDERR_FILENO"));
		close(fd);
		return -1;
	}

	close(fd);
	return net_fd;
}

int
do_inetd_wait(int argc, char **argv)
{
	int	listener;

	listener = prep_inetd();
	return do_listener(listener, argc, argv);
}

int
do_inetd_nowait(int argc, char **argv)
{
	struct sockaddr_storage	ss;
	work_t			work;
	socklen_t               len;
	int			ret;
 
	work_init(&work);

	work.network_fd = prep_inetd();
	if (work.network_fd == -1)
		return 0;

	/* Obtain the remote TCP info */
	len = sizeof(ss);
	ret = getpeername(work.network_fd, (struct sockaddr *)&ss, &len);
	if (ret == -1) {
		LOG(LOG_ERR, ("getpeername: %s", strerror(errno)));
	} else {
		sockaddr_2str(&work, (struct sockaddr *)&ss, len);
	}

	if (prefs.sun_path != NULL)
		ret = do_unix_socket(&work);
	else
		ret = do_work(&work, argc, argv);

	work_free(&work);

	return ret;
}

int
do_inetd(int argc, char **argv)
{
	socklen_t	len = sizeof(int);
	int		ret;
	int		val;

	if (prefs.is_wait_service)
		return do_inetd_wait(argc, argv);

	ret = getsockopt(prefs.network_fd == -1 ? 0 : prefs.network_fd,
	    SOL_SOCKET, SO_ACCEPTCONN, &val, &len);

	if (ret != -1 && val)
		return do_inetd_wait(argc, argv);

	return do_inetd_nowait(argc, argv);
}

int
do_listener_inet(int argc, char **argv)
{
	uint16_t	port;
	int		listener;

	/*
	 * If we haven't been launched from inetd, we'll need to do the usual
	 * listening/accepting, and fork to process an accepted connection
	 */
	port = getport(argv[0], "tcp");
	if ((listener = setup_listener(port)) < 0)
		return 0;

	return do_listener(listener, argc - 1, argv + 1);
}

int
do_listener(int listener, int argc, char **argv)
{
	struct sockaddr_storage	 sa;
	int			 fd;
	int			 num_connections = 0;
	int			 timeout = 60000; /* wake every 60s to reap */
	time_t			 endtime = 0;
	socklen_t		 client_len;
	work_t			 work;
	struct pollfd pfds[1];
	pfds[0].fd = listener;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;

	nonblocking_set(listener);

	sig_set(SIGHUP, sig_handler, 1);
	sig_set(SIGCHLD, sig_handler, 1);
	sig_set(SIGPIPE, SIG_IGN, 0);

	if (prefs.max_time)
		endtime = time(NULL) + prefs.max_time;

	while (!dienow) {
		/* Exit if we have exceeded our maximum time limit */
		if (endtime) {
			time_t now = time(NULL);
			if (now > endtime)
				break;

			timeout = (endtime - now) * 1000 + 1000;
			/* wake every 60 sec to check for children to reap() */
			if (timeout > 60000) timeout = 60000;
		}

		/*
		 * If we have exceeded the maximum number of allowed
		 * child processes, we sleep here.
		 */
		while (num_children >= prefs.num_children_max) {
			LOG(LOG_DEBUG, ("maximum children exceeded, %d > %d",
					num_children, prefs.num_children_max));
			num_children -= sleep_reap();
		}

		/* Reap any children who've died */
		num_children -= reap();

		/* poll() is interruptable, even by sigaction w/ SA_RESTART */
		if (poll(pfds, 1, timeout) <= 0) {
			continue;
		}

		client_len = sizeof(sa);
		if ((fd = accept(listener, (struct sockaddr *)&sa,
				 &client_len)) < 0) {

			if (   errno != EINTR
			    && errno != EAGAIN
			    && errno != EWOULDBLOCK)
				LOG_ERRNO(LOG_WARNING, ("failed to accept"));

			continue;
		}

		work_init(&work);

		sockaddr_2str(&work, (struct sockaddr *)&sa, client_len);
		num_connections++;

		LOG(LOG_INFO, ("Accepted connection from %s port %s",
			       work.network_addr, work.network_port));

		work.network_fd = fd;

		if (prefs.sun_path != NULL) {
			/* Connecting to a unix domain socket */
			if (prefs.no_fork)
				do_unix_socket(&work);
			else {
				fork_and_do_unix_socket(&work, listener);
			}
		} else {
			/* execing a program */
			if (prefs.no_fork)
				do_work(&work, argc, argv);
			else {
				fork_and_do_work(&work, listener, argc, argv);
			}
		}

		/* And now, as the parent, we no longer need this work
		   structure or file descriptor */
		work_free(&work);

		/* Exit if we've processed the maximum number of connections */
		if (prefs.max_connections &&
		    num_connections >= prefs.max_connections)
			break;
	}

	return 0;
}

int
do_client(int argc, char **argv)
{
	const char *svchost    = argv[0];
	const char *defservice = "HTTP";
	const char *defport    = argv[1]; /*(can be NULL)*/

	knc_ctx ctx = knc_ctx_init();
	if (ctx == NULL) {
		LOG_ERRNO(LOG_ERR, ("knc_connect(): ENOMEM"));
		return 0;
	}

	knc_set_debug(ctx, 0);
	knc_set_debug_prefix(ctx, "knc-client");

	if (prefs.network_fd != -1) {
		LOG(LOG_DEBUG, ("wrapping existing fd %d", prefs.network_fd));

		if (prefs.network_fd == STDIN_FILENO
		    || prefs.network_fd == STDOUT_FILENO)
			return report_ctx_err(ctx,
			                      "network socket conflicts with "
			                      "stdin or stdout");

		if (!init_ctx_network_fd(ctx, &prefs.network_fd))
			return report_ctx_err(ctx, NULL);

		if (prefs.sprinc) {
			knc_import_set_service(ctx, prefs.sprinc, GSS_C_NO_OID);
		} else {
			char *colon = strchr(argv[0], ':');
			if (colon) *colon = '\0';
			knc_import_set_hb_service(ctx, svchost, defservice);
			if (colon) *colon = ':';
		}
		if (knc_error(ctx) != 0)
			return report_ctx_err(ctx, "knc_import_set_service()");

		knc_initiate(ctx);
		if (knc_error(ctx) != 0)
			return report_ctx_err(ctx, "knc_initiate()");
	} else {
		/* knc_connect() expects blocking connect,
		 * so omit KNC_SOCK_NONBLOCK and set flag after knc_connect()
		 * (knc_connect() does not handle EINPROGRESS)
		 */
		int opts = KNC_SOCK_CLOEXEC
		         | (prefs.so_keepalive ? KNC_SO_KEEPALIVE : 0);

		if (prefs.sprinc) {
			knc_import_set_service(ctx, prefs.sprinc, GSS_C_NO_OID);
			if (knc_error(ctx) != 0)
				return
				  report_ctx_err(ctx,
				                 "knc_import_set_service()");
		}

		/* N.B.: blocking connect() */
		knc_connect(ctx, svchost, defservice, defport, opts);
		if (knc_error(ctx) != 0)
			return report_ctx_err(ctx, "knc_connect()");

		if (!knc_set_optb(ctx, KNC_SOCK_NONBLOCK, 1))
			return report_ctx_errno(ctx,
			                        "unable to set O_NONBLOCK on "
			                        "network socket");
	}
	knc_authenticate(ctx);
	if (knc_error(ctx) != 0)
		return report_ctx_err(ctx, "knc_authenticate()");

	nonblocking_set(STDIN_FILENO);
	nonblocking_set(STDOUT_FILENO);

	knc_set_local_fds(ctx, STDIN_FILENO, STDOUT_FILENO);
	if (knc_error(ctx) != 0)
		return report_ctx_err(ctx, "knc_set_local_fds()");

	return move_data_ctx(ctx);
}

void
work_init(work_t *work)
{

	memset(work, 0, sizeof(work_t));

	work->network_fd = -1;
	work->local_in = -1;
	work->local_out = -1;
	work->local_err = -1;
}

void
work_free(work_t *work)
{

	if (work->network_fd != -1)
		close(work->network_fd);

	if (work->local_in != -1)
		close(work->local_in);

	if (work->local_out != -1 && work->local_out != work->local_in)
		close(work->local_out);

	if (work->local_err != -1)
		close(work->local_err);

	work->network_fd = -1;
	work->local_in   = -1;
	work->local_out  = -1;
	work->local_err  = -1;
}

int
nonblocking_set(int fd)
{
	long	curflags;

	/*
	 * XXXrcd: lame hack for me.  don't set non-blocking on terminals
	 *         as this leaves my terminal in an annoying state...  This
	 *         should not be an issue for any protocols as they are not
	 *         generally run over terminals...
	 */
	if (isatty(fd))
		return 0;

	if ((curflags = fcntl(fd, F_GETFL)) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to get flags"));
		return -1;
	}

	curflags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, curflags) < 0) {
		LOG_ERRNO(LOG_ERR, ("unable to set O_NONBLOCK"));
		return -1;
	}

	return 0;
}

int
nonblocking_clr(int fd)
{
	long	curflags;

	if ((curflags = fcntl(fd, F_GETFL)) < 0)
		return -1;

	curflags &= ~O_NONBLOCK;

	if (fcntl(fd, F_SETFL, curflags) < 0)
		return -1;

	return 0;
}
