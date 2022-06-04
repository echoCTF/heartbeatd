/*
 * Based on spamlogd.c,v 1.27
 * ORIGINAL COPYRIGHTS
 * Copyright (c) 2006 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2006 Berk D. Demir.
 * Copyright (c) 2004-2007 Bob Beck.
 * Copyright (c) 2001 Theo de Raadt.
 * Copyright (c) 2001 Can Erkin Acar.
 * All rights reserved
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* watch pf log for connections, update findings entries. */
#include <libmemcached/memcached.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/signal.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <net/pfvar.h>
#include <net/if_pflog.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#define MIN_PFLOG_HDRLEN  45
#define PCAPSNAP    512
#define PCAPTIMO    500  /* ms */
#define PCAPOPTZ    1  /* optimize filter */
#define PCAPFSIZ    512  /* pcap filter string size */



int debug = 1;
int wait_timeout=60*60;

u_int8_t  flag_debug = 0;
char      *FINDINGSD_USER = "_memcached";
char      *pflogif = "pflog0";
char      errbuf[PCAP_ERRBUF_SIZE];
pcap_t    *hpcap = NULL;
char  *filter = "ip and ( (tcp[tcpflags] & (tcp-syn) != 0) or udp or icmp)";

struct syslog_data   sdata  = SYSLOG_DATA_INIT;
memcached_st *memc;
memcached_return rc;

extern char    *__progname;

void  logmsg(int , const char *, ...);
void  sighandler_close(int);
int   init_pcap(void);
void  logpkt_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
int   set_target_heartbeat(char *, char *, u_int16_t, char *);
__dead void  usage(void);

void
logmsg(int pri, const char *msg, ...)
{
  va_list  ap;
  va_start(ap, msg);

  if (flag_debug) {
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
  } else {
    vsyslog_r(pri, &sdata, msg, ap);
  }

  va_end(ap);
}

void
sighandler_close(int signal)
{
  if (hpcap != NULL)
    pcap_breakloop(hpcap);  /* sighdlr safe */
}

int
init_pcap(void)
{
  struct bpf_program  bpfp;

  if ((hpcap = pcap_open_live(pflogif, PCAPSNAP, 1, PCAPTIMO,
      errbuf)) == NULL) {
        logmsg(LOG_ERR, "Failed to initialize: %s", errbuf);
        return (-1);
  }

  if (pcap_datalink(hpcap) != DLT_PFLOG) {
    logmsg(LOG_ERR, "Invalid datalink type");
    pcap_close(hpcap);
    hpcap = NULL;
    return (-1);
  }

  if (pcap_compile(hpcap, &bpfp, filter, PCAPOPTZ, 0) == -1 ||
      pcap_setfilter(hpcap, &bpfp) == -1) {
        logmsg(LOG_ERR, "%s", pcap_geterr(hpcap));
        return (-1);
  }

  pcap_freecode(&bpfp);

  if (ioctl(pcap_fileno(hpcap), BIOCLOCK) < 0) {
    logmsg(LOG_ERR, "BIOCLOCK: %s", strerror(errno));
    return (-1);
  }

  return (0);
}

void
logpkt_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
  sa_family_t        af;
  u_int8_t           hdrlen;
  u_int32_t          caplen = h->caplen;
  const struct ip    *ip = NULL;
  const struct pfloghdr  *hdr;
  struct protoent *pp;
  char straddr_src[40] = { '\0' }, straddr_dst[40] = { '\0' };
  u_int16_t dport=0;
  time_t _tm =time(NULL );
  struct tm * curtime = localtime ( &_tm );
  char *timestring=asctime(curtime);
  timestring[strlen(timestring) - 1] = 0;
  hdr = (const struct pfloghdr *)sp;
  if (hdr->length < MIN_PFLOG_HDRLEN) {
    logmsg(LOG_WARNING, "invalid pflog header length (%u/%u). "
      "packet dropped.", hdr->length, MIN_PFLOG_HDRLEN);
    return;
  }
  hdrlen = BPF_WORDALIGN(hdr->length);

  if (caplen < hdrlen) {
    logmsg(LOG_WARNING, "pflog header larger than caplen (%u/%u). "
      "packet dropped.", hdrlen, caplen);
    return;
  }

  af = hdr->af;
  if (af == AF_INET) {
    ip = (const struct ip *)(sp + hdrlen);
    inet_ntop(af, &ip->ip_src, straddr_src,sizeof(straddr_src));
    inet_ntop(af, &ip->ip_dst, straddr_dst,sizeof(straddr_dst));
    if (ip->ip_p == IPPROTO_UDP) {
        dport = ntohs(hdr->dport);
        pp=getprotobynumber(IPPROTO_UDP);
    } else if (ip->ip_p == IPPROTO_ICMP) {
        dport = 0;
        pp=getprotobynumber(IPPROTO_ICMP);
    } else if (ip->ip_p == IPPROTO_TCP) {
        dport = ntohs(hdr->dport);
        pp=getprotobynumber(IPPROTO_TCP);
    }
  }

  if (straddr_dst[0] != '\0' && straddr_src[0] != '\0') {
    logmsg(LOG_DEBUG,"[%s] SRC: %s => DST: => %s:%d, PROTO: %s",timestring,straddr_src,straddr_dst, dport, pp->p_name);
    set_target_heartbeat(straddr_src,straddr_dst, dport, pp->p_name);
  }
}

int
set_target_heartbeat(char *ip_src, char *ip_dst, u_int16_t port_dst, char *p_name)
{
  static unsigned long srcLen=0,dstLen=0,p_nameLen=0;
  static int port[1]={0};
  static char src[15]={0},dst[15]={0},proto[6]={0};
  char key[128];

  sprintf(key,"target_heartbeat:%s",ip_dst);
  rc = memcached_set(memc, key, strlen(key), ip_dst, strlen(ip_dst), (time_t)wait_timeout, (uint32_t)0);
  if (rc != MEMCACHED_SUCCESS)
  {
    logmsg(LOG_ERR, "Couldn't store key: %s\n", memcached_strerror(memc, rc));
    return (-1);
  }

  return 0;
}

void
usage(void)
{
  fprintf(stderr,
      "usage: %s [-D] [-l pflog_interface] [-u user] [-s socket] [-t wait_timeout] [-f pcap filter]\n",
      __progname);
  exit(1);
}

int
main(int argc, char **argv)
{
  int     ch;
  struct passwd  *pw;
  char *sock;
  pcap_handler   phandler = logpkt_handler;
  memcached_server_st *servers = NULL;

  while ((ch = getopt(argc, argv, "Dl:s:t:u:f:")) != -1) {
    switch (ch) {
      case 'D':
        flag_debug = 1;
        break;
      case 'l':
        pflogif = optarg;
        break;
      case 'u':
        FINDINGSD_USER = optarg;
        break;
      case 's':
        sock = optarg;
        break;
      case 'f':
        filter = optarg;
        break;
      case 't':
        wait_timeout = atoi(optarg);
        break;
      default:
        usage();
    }
  }
  if (geteuid())
    errx(1, "need root privileges");



  signal(SIGINT , sighandler_close);
  signal(SIGQUIT, sighandler_close);
  signal(SIGTERM, sighandler_close);

  logmsg(LOG_DEBUG, "Listening on %s", pflogif);
  //
  //
  // CONNECT TO MEMCACHED
  memc = memcached_create(NULL);
  servers = memcached_server_list_append(servers, sock, 0, &rc);
  rc = memcached_server_push(memc, servers);
//rc = memcached_server_add_unix_socket(memc, sock);

  if (rc == MEMCACHED_SUCCESS)
  {
    logmsg(LOG_DEBUG, "Added server successfully");
  }
  else
  {
    errx(1, "Couldn't add server: %s\n", memcached_strerror(memc, rc));
  }

  // and set options and settings
  //
  //

  if (init_pcap() == -1)
    err(1, "couldn't initialize pcap");

  /* privdrop */
  if ((pw = getpwnam(FINDINGSD_USER)) == NULL)
    errx(1, "no such user %s", FINDINGSD_USER);

  if (setgroups(1, &pw->pw_gid) ||
      setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
      setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {
    err(1, "failed to drop privs");
  }

  if (!flag_debug) {
    if (daemon(0, 0) == -1)
      err(1, "daemon");

    tzset();
    openlog_r(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON, &sdata);
  }

  pcap_loop(hpcap, -1, phandler, NULL);

  logmsg(LOG_NOTICE, "exiting");
  if (!flag_debug)
    closelog_r(&sdata);

  exit(0);
}
