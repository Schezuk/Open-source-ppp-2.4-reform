/*
 * main.c - Point-to-Point Protocol main module
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright (c) 1999-2004 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define RCSID	"$Id: main.c,v 1.153 2006/06/04 03:52:50 paulus Exp $"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <netdb.h>
#include <utmp.h>
#include <pwd.h>
#include <setjmp.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pppd.h"
#include "magic.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#ifdef INET6
#include "ipv6cp.h"
#endif
#include "upap.h"
#include "chap-new.h"
#include "eap.h"
#include "ccp.h"
#include "ecp.h"
#include "pathnames.h"
#include "ppp_remark.h"
#include "pppd_tmp.h"
#include "fsm.h"

#ifdef USE_TDB
#include "tdb.h"
#endif

#ifdef CBCP_SUPPORT
#include "cbcp.h"
#endif

#ifdef IPX_CHANGE
#include "ipxcp.h"
#endif /* IPX_CHANGE */
#ifdef AT_CHANGE
#include "atcp.h"
#endif

#include "ppp_remark.h"
#include "ppp_vty.h"
#include <pthread.h>
#include "fsm.h"


static const char rcsid[] = RCSID;

/* interface vars */
char ifname[32];		/* Interface name */ //ppp0
int ifunit;			/* Interface unit number */ //可以由这里赋值 req_unit unit命令设置

struct channel *the_channel;//the_channel = &tty_channel; remark_channel  见tty_init  内核驱动相关的都在这里面的回调函数里面操作

char *progname;			/* Name of this program */
char hostname[MAXNAMELEN];	/* Our hostname  main函数中执行if (gethostname(hostname, MAXNAMELEN) < 0 ) {*/  //root@darkstar @后面的字符串
static char pidfilename[MAXPATHLEN];	/* name of pid file */
static char linkpidfile[MAXPATHLEN];	/* name of linkname pid file */
char ppp_devnam[MAXPATHLEN];	/* name of PPP tty (maybe ttypx) */ //dev/ttyS1
uid_t uid;			/* Our real user-id */
struct notifier *pidchange = NULL;
struct notifier *phasechange = NULL;
struct notifier *exitnotify = NULL;
struct notifier *sigreceived = NULL;
struct notifier *fork_notifier = NULL;

int hungup;			/* terminal has been hung up */
int privileged;			/* we're running as real uid root */ //是否在root目录下面跑pppd
int need_holdoff;		/* need holdoff period before restarting */
int detached = 1;			/* have detached from terminal */
volatile int status;		/* exit status for pppd */
int unsuccess;			/* # unsuccessful connection attempts */
int ppp_session_number;		/* Session number, for channels with such a
				   concept (eg PPPoE) */
int childwait_done;		/* have timed out waiting for children */

#ifdef USE_TDB
TDB_CONTEXT *pppdb;		/* database for storing status etc. */
#endif

char db_key[32]; //slprintf(db_key, sizeof(db_key), "pppd%d", getpid());

int (*holdoff_hook) __P((void)) = NULL;
int (*new_phase_hook) __P((int, int)) = NULL;
void (*snoop_recv_hook) __P((unsigned char *p, int len)) = NULL;
void (*snoop_send_hook) __P((unsigned char *p, int len)) = NULL;

static int conn_running;	/* we have a [dis]connector running */

int fd_devnull;			/* fd for /dev/null */
int devfd = -1;			/* fd of underlying device */
int fd_ppp = -1;		/* fd for talking PPP */
int phase;			/* where the link is at */
int kill_link;
int asked_to_quit;
int open_ccp_flag;
int listen_time; //一直为0
int got_sigusr2;
int got_sigterm; //term函数中赋值
int got_sighup;

static sigset_t signals_handled;
static int waiting;
static sigjmp_buf sigjmp;

//这个是数字指针，存放的是PPPD_PID=3855;IFNAME=ppp0;BUNDLE=\22paptest\22/local:63.68.61.70.74.65.73.74\00，见update_db_entry
char **script_env;		/* Env. variable values for scripts */ //在执行脚本的时候把该数组中的参数传过去  见函数execve
int s_env_nalloc;		/* # words avail at script_env */

u_char outpacket_buf[PPP_MRU+PPP_HDRLEN]; /* buffer for outgoing packet */
u_char inpacket_buf[PPP_MRU+PPP_HDRLEN]; /* buffer for incoming packet */

static int n_children;		/* # child processes still running */
static int got_sigchld;		/* set if we have received a SIGCHLD */

int privopen;			/* don't lock, open device as root */

char *no_ppp_msg = "Sorry - this system lacks PPP kernel support\n";

GIDSET_TYPE groups[NGROUPS_MAX];/* groups the user is in */
int ngroups;			/* How many groups valid in groups */

static struct timeval start_time;	/* Time when link was started. */

static struct pppd_stats old_link_stats;
struct pppd_stats link_stats;
unsigned link_connect_time;
int link_stats_valid;

int error_count;

bool bundle_eof;
bool bundle_terminating;

/*
 * We maintain a list of child process pids and
 * functions to call when they exit.
 */
struct subprocess {
    pid_t	pid;
    char	*prog;
    void	(*done) __P((void *));
    void	*arg;
    struct subprocess *next;
};

static struct subprocess *children;

/* Prototypes for procedures local to this file. */

static void setup_signals __P((void));
static void create_pidfile __P((int pid));
static void create_linkpidfile __P((int pid));
static void cleanup __P((void));
static void get_input __P((int));
static void calltimeout __P((int));
static struct timeval *timeleft __P((struct timeval *));
static void kill_my_pg __P((int));
static void hup __P((int));
static void term __P((int));
void chld __P((int));
void toggle_debug __P((int));
void open_ccp __P((int));
static void bad_signal __P((int));
static void forget_child __P((int pid, int status));
static int reap_kids __P((void));

#ifdef USE_TDB
static void update_db_entry __P((void));
static void add_db_key __P((const char *));
static void delete_db_key __P((const char *));
static void cleanup_db __P((void));
#endif

static void handle_events __P((void));
void print_link_stats __P((void));

extern	char	*ttyname __P((int));
extern	char	*getlogin __P((void));
int main __P((int, char *[]));

#ifdef ultrix
#undef	O_NONBLOCK
#define	O_NONBLOCK	O_NDELAY
#endif

#ifdef ULTRIX
#define setlogmask(x)
#endif

/*
 * PPP Data Link Layer "protocol" table.
 * One entry per supported protocol.
 * The last entry must be NULL.
 */
struct protent *protocols[] = {
    &lcp_protent,
    &pap_protent,
    &chap_protent,
//#ifdef CBCP_SUPPORT
//    &cbcp_protent,
//#endif
    &ipcp_protent,
//#ifdef INET6
//    &ipv6cp_protent,
//#endif
    &ccp_protent,
//    &ecp_protent,
//#ifdef IPX_CHANGE
//    &ipxcp_protent,
//#endif
//#ifdef AT_CHANGE
//    &atcp_protent,
//#endif
    &eap_protent,
    NULL
};

/*
 * If PPP_DRV_NAME is not defined, use the default "ppp" as the device name.
 */
#if !defined(PPP_DRV_NAME)
#define PPP_DRV_NAME	"ppp"
#endif /* !defined(PPP_DRV_NAME) */

// pppd -detach debug crtscts lock 1.1.1.2:1.1.1.1 /dev/ttyS1 115200
//pppd -detach debug crtscts lock 1.1.1.1:1.1.1.2 /dev/ttyS1 115200
//./pppd -detach debug call options_chan1
/*
09:35:57.015590 00:00:00:00:0e:01 (oui Ethernet) > Broadcast, ethertype Unknown (0xaa00), length 248: 
        0x0000:  ffff ffff ffff 0000 0000 0e01 aa00 0004
        0x0010:  ff03 0021 4500 00e4 0000 4000 4001 f614
        0x0020:  2101 0102 2101 0101 0800 cc67 2405 0000
        0x0030:  32a1 d4f1 0000 0000 0000 0000 0000 0000
        0x0040:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0050:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0060:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0070:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0080:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0090:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00a0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00b0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00c0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00d0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00e0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00f0:  0000 0000 0000 0000
09:35:57.017638 00:00:c0:a8:00:02 (oui Unknown) > 00:00:c0:a8:00:01 (oui Unknown), ethertype Unknown (0xaa00), length 248: 
        0x0000:  0000 c0a8 0001 0000 c0a8 0002 aa00 0004
        0x0010:  ff03 0021 4500 00e4 4fe7 0000 4001 e62d
        0x0020:  2101 0101 2101 0102 0000 d467 2405 0000
        0x0030:  32a1 d4f1 0000 0000 0000 0000 0000 0000
        0x0040:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0050:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0060:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0070:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0080:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0090:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00a0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00b0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00c0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00d0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00e0:  0000 0000 0000 0000 0000 0000 0000 0000
        0x00f0:  0000 0000 0000 0000

*/
/*
PPP驱动程序的基本原理
=====================
1) ppp设备是指在点对点的物理链路之间使用PPP帧进行分组交换的内核网络接口设备,
由于Linux内核将串行设备作为终端设备来驱动,
于是引入PPP终端规程来实现终端设备与PPP设备的接口. 根据终端设备的物理传输特性的不同,
PPP规程分为异步规程(N_PPP)和同步规程(N_SYNC_PPP)两种, 对于普通串口设备使用异步PPP规程.


2) 在PPP驱动程序中, 每一tty终端设备对应于一条PPP传输通道(chanell),
每一ppp网络设备对应于一个PPP接口单元(unit).
从终端设备上接收到的数据流通过PPP传输通道解码后转换成PPP帧传递到PPP网络接口单元,
PPP接口单元再将PPP帧转换为PPP设备的接收帧. 反之, 当PPP设备发射数据帧时,
发射帧通过PPP接口单元转换成PPP帧传递给PPP通道, PPP通道负责将PPP帧编码后写入终端设备.
在配置了多链路PPP时(CONFIG_PPP_MULTILINK), 多个PPP传输通道可连接到同一PPP接口单元.
PPP接口单元将PPP帧分割成若干个片段传递给不同的PPP传输通道, 反之,
PPP传输通道接收到的PPP帧片段被PPP接口单元重组成完整的PPP帧. 

3) 在Linux-2.4中, 应用程序可通过字符设备/dev/ppp监控内核PPP驱动程序.
用户可以用ioctl(PPPIOCATTACH)将文件绑定到PPP接口单元上, 来读写PPP接口单元的输出帧,
也可以用ioctl(PPPIOCATTCHAN)将文件绑定到PPP传输通道上, 来读写PPP传输通道的输入帧. 

4) PPP传输通道用channel结构描述, 系统中所有打开的传输通道在all_channels链表中.
PPP接口单元用ppp结构描述, 系统中所有建立的接口单元在all_ppp_units链表中.
当终端设备的物理链路连接成功后, 用户使用ioctl(TIOCSETD)将终端切换到PPP规程.
PPP规程初始化时, 将建立终端设备的传输通道和通道驱动结构. 对于异步PPP规程来说,
通道驱动结构为asyncppp, 它包含通道操作表async_ops.
传输通道和接口单元各自包含自已的设备文件(/dev/ppp)参数结构(ppp_file). 

http://blog.csdn.net/istone107/article/details/8065758
*/
//64位库地址10.135.127.4 /opt/sdk-base/toolchains_bin/mipscross/ 
//make CC=mips64-nlm-linux-gcc
//enable_jumbo=1 大包取消限制
#include "log.h"  
#include "sigevent.h" 
//#include "linklist.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "stdio.h"

/*
问题: lcp_addci(地址为8) upap_authwithpeer (u->us_outbuf地址为0)里面偶尔会挂死
*/
int
main(argc, argv)
    int argc;
    char *argv[];
{
//    int i;
    int k;
    char *p;
    struct passwd *pw;
//    struct protent *protp;
    pthread_t id1;
    int ret;
    char numbuf[16];
    char tmp_buf[50];
    char *progname;
    struct ppp_interface *pif;

    umask(0027);
    progname = ( (p = strrchr (argv[0], '/') ) ? ++p : argv[0]);
    zlog_default = openzlog (progname, ZLOG_MCP, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
    zlog_default->maxlvl[ZLOG_DEST_STDOUT] = zlog_default->default_lvl;
    zlog_default->maxlvl[ZLOG_DEST_MONITOR] = zlog_default->default_lvl;
    zlog_default->maxlvl[ZLOG_DEST_FILE] = zlog_default->default_lvl;

    link_stats_valid = 0;

    /* Initialize syslog facilities */
    reopen_log();
    if (gethostname(hostname, MAXNAMELEN) < 0 ) {
    	ZLOG_INFO("Couldn't get hostname: %m ");
    	exit(1);
    }
    hostname[MAXNAMELEN-1] = 0;

    /* make sure we don't create world or group writable files. */
    umask(umask(0777) | 022);

    uid = getuid();
    privileged = uid == 0;
    ngroups = getgroups(NGROUPS_MAX, groups);
    magic_init();

    if (debug)
	    setlogmask(LOG_UPTO(LOG_DEBUG));

    if (!ppp_available()) {
    	ZLOG_INFO("%s\n", no_ppp_msg);
    	exit(EXIT_NO_KERNEL_SUPPORT);
    }

    check_options();//改函数没什么用
    if (!sys_check_options()) {//检测系统参数，比如内核是否支持Multilink等
        ZLOG_INFO("sys check optons error");
	    exit(EXIT_OPTION_ERROR);   
    }

    sys_init();

    ppp_init_db_file();
    pppdb = tdb_open(_PATH_PPPDB, 0, 0, O_RDWR|O_CREAT, 0644);
    if (pppdb != NULL) {
    	slprintf(db_key, sizeof(db_key), "pppd%d", getpid());
    	update_db_entry();
    } else {
    	warn("Warning: couldn't open ppp database %s", _PATH_PPPDB);
    }

    p = getlogin();
    if (p == NULL) {
    	pw = getpwuid(uid);
    	if (pw != NULL && pw->pw_name != NULL)
    	    p = pw->pw_name;
    	else
    	    p = "(unknown)";
    }

    slprintf(numbuf, sizeof(numbuf), "%d", getpid());
    script_setenv("PPPD_PID", numbuf, 1);
    setup_signals();
  //  create_pidfile(getpid());	/* write pid to file */
 //   create_linkpidfile(getpid());
//    create_linkpidfile(getpid());

    
    ppp_remark_mem_init();
    ret = pthread_create(&id1, NULL, &ppp_vty_init, NULL);
    if(ret!=0) {
      ZLOG_INFO("Create pppd vty process pthread error!");
      exit (1);
    }

    sleep(3);

    waiting = 0;
    for (;;) {
    	listen_time = 0;
    	devfd = -1;
    	status = EXIT_OK;

    	gettimeofday(&start_time, NULL);

    	while (1) {//PPPD状态机循环进行事件处理
    	    if(ppp_have_interface_is_enable() == 0) /* 必须保证有fd加入到in_fds中，如果不加这个，在handle_events里面的wait函数中讲一直select阻塞 */
    	        continue;

            //for(k = 0; k < NUM_PPP; k++)
    	    //    calltimeout(k);
    	        
    	    handle_events();
    	    
            for(k = 0; k < NUM_PPP; k++){
                pif = ppp_if[k];
                if(pif == NULL)
                    continue;

                if(pif->ppp_dev_fd < 0 || pif->dev_fd < 0)
                    continue;

                calltimeout(k);
                if (is_have_fd(pif->ppp_dev_fd) || is_have_fd(pif->dev_fd))
                    get_input(k);

                if (open_ccp_flag) {
                    if (pif->phase == PHASE_NETWORK || pif->phase == PHASE_RUNNING) {
                        ccp_fsm[0].flags = OPT_RESTART; /* clears OPT_SILENT */
                        (*ccp_protent.open)(0);
                    }
                }
            }

    	    if (kill_link || asked_to_quit) 
    		    break;
    	}

    	if (asked_to_quit)
    	    break;
    }

    exit(1);
    return 0;
}

/*
 * handle_events - wait for something to happen and respond to it.
 //这个函数里面重点是调用了wait_input对前面加入的/dev/ppp文件描述符调用select监听事件。
 */
static void
handle_events()
{
    struct timeval timo;

    kill_link = open_ccp_flag = 0;
    if (sigsetjmp(sigjmp, 1) == 0) {
    	sigprocmask(SIG_BLOCK, &signals_handled, NULL);
    	if (got_sighup || got_sigterm || got_sigusr2 || got_sigchld) {
    	    sigprocmask(SIG_UNBLOCK, &signals_handled, NULL);
    	} else {
    	    waiting = 1;
    	    sigprocmask(SIG_UNBLOCK, &signals_handled, NULL);
    	    wait_input(timeleft(&timo));
    	}
    }
    waiting = 0;
    
    if (got_sighup) {
    	info("Hangup (SIGHUP)");
    	kill_link = 1;
    	got_sighup = 0;
    	if (status != EXIT_HANGUP)
    	    status = EXIT_USER_REQUEST;
    }
    if (got_sigterm) { //收到ctrl+c信号
    	info("Terminating on signal %d", got_sigterm);
    	kill_link = 1;
    	asked_to_quit = 1;
    	persist = 0;
    	status = EXIT_USER_REQUEST;
    	got_sigterm = 0;
    }
    if (got_sigchld) {
    	got_sigchld = 0;
    	reap_kids();	/* Don't leave dead kids lying around */
    }
    if (got_sigusr2) {
    	open_ccp_flag = 1;
    	got_sigusr2 = 0;
    }
}

/*
 * setup_signals - initialize signal handling.
 */
static void
setup_signals()
{
    struct sigaction sa;

    /*
     * Compute mask of all interesting signals and install signal handlers
     * for each.  Only one signal handler may be active at a time.  Therefore,
     * all other signals should be masked when any handler is executing.
     */
    sigemptyset(&signals_handled);
    sigaddset(&signals_handled, SIGHUP);
    sigaddset(&signals_handled, SIGINT);
    sigaddset(&signals_handled, SIGTERM);
    sigaddset(&signals_handled, SIGCHLD);
    sigaddset(&signals_handled, SIGUSR2);

#define SIGNAL(s, handler)	do { \
	sa.sa_handler = handler; \
	if (sigaction(s, &sa, NULL) < 0) \
	    fatal("Couldn't establish signal handler (%d): %m", s); \
    } while (0)

    sa.sa_mask = signals_handled;
    sa.sa_flags = 0;
    SIGNAL(SIGHUP, hup);		/* Hangup */
    SIGNAL(SIGINT, term);		/* Interrupt */
    SIGNAL(SIGTERM, term);		/* Terminate */
   // SIGNAL(SIGCHLD, chld);

    //SIGNAL(SIGUSR1, toggle_debug);	/* Toggle debug flag */
   // SIGNAL(SIGUSR2, open_ccp);		/* Reopen CCP */

    /*
     * Install a handler for other signals which would otherwise
     * cause pppd to exit without cleaning up.
     */
    SIGNAL(SIGABRT, bad_signal);
    SIGNAL(SIGALRM, bad_signal);
    SIGNAL(SIGFPE, bad_signal);
    SIGNAL(SIGILL, bad_signal);
    SIGNAL(SIGPIPE, bad_signal);
    SIGNAL(SIGQUIT, bad_signal);
    SIGNAL(SIGSEGV, bad_signal);
#ifdef SIGBUS
    SIGNAL(SIGBUS, bad_signal);
#endif
#ifdef SIGEMT
    SIGNAL(SIGEMT, bad_signal);
#endif
#ifdef SIGPOLL
    SIGNAL(SIGPOLL, bad_signal);
#endif
#ifdef SIGPROF
    SIGNAL(SIGPROF, bad_signal);
#endif
#ifdef SIGSYS
    SIGNAL(SIGSYS, bad_signal);
#endif
#ifdef SIGTRAP
    SIGNAL(SIGTRAP, bad_signal);
#endif
#ifdef SIGVTALRM
    SIGNAL(SIGVTALRM, bad_signal);
#endif
#ifdef SIGXCPU
    SIGNAL(SIGXCPU, bad_signal);
#endif
#ifdef SIGXFSZ
    SIGNAL(SIGXFSZ, bad_signal);
#endif

    /*
     * Apparently we can get a SIGPIPE when we call syslog, if
     * syslogd has died and been restarted.  Ignoring it seems
     * be sufficient.
     */
    signal(SIGPIPE, SIG_IGN);
}

/*
 * set_ifunit - do things we need to do once we know which ppp
 * unit we are using.
 */

/*
{
key(11) = "IFNAME=ppp3"
data(9) = "pppd14507"
}
*/
void
set_ifunit(int unit, int iskey)
{
    struct ppp_interface *pif = ppp_if[unit];

    info("Using interface %s%d", PPP_DRV_NAME, unit);
    script_setenv("IFNAME", pif->ifname, iskey); 
    if (iskey) { 
    	create_pidfile(getpid());	/* write pid to file */
    	create_linkpidfile(getpid());
    }
}

/*
 * detach - detach us from the controlling terminal.
 */
void
detach()
{
    int pid;
    char numbuf[16];
    int pipefd[2];

    if (detached)
	    return;
    if (pipe(pipefd) == -1)
	    pipefd[0] = pipefd[1] = -1;
    if ((pid = fork()) < 0) {
    	error("Couldn't detach (fork failed: %m)");
    	die(1);			/* or just return? */
    }
    if (pid != 0) {
	    /* parent */
    	notify(pidchange, pid);
    	/* update pid files if they have been written already */
    	if (pidfilename[0])
    	    create_pidfile(pid);
    	if (linkpidfile[0])
    	    create_linkpidfile(pid);
    	exit(0);		/* parent dies */
    }
    setsid();
    chdir("/");
    dup2(fd_devnull, 0);
    dup2(fd_devnull, 1);
    dup2(fd_devnull, 2);
    detached = 1;
    if (log_default)
	log_to_fd = -1;
    slprintf(numbuf, sizeof(numbuf), "%d", getpid());
    script_setenv("PPPD_PID", numbuf, 1);

    /* wait for parent to finish updating pid & lock files and die */
    close(pipefd[1]);
    complete_read(pipefd[0], numbuf, 1);
    close(pipefd[0]);
}

/*
 * reopen_log - (re)open our connection to syslog.
 */
void
reopen_log()
{
    openlog("pppd", LOG_PID | LOG_NDELAY, LOG_PPP);//创建守护进程日志，在/var/log/pppd中查看
    setlogmask(LOG_UPTO(LOG_INFO));
}

/*
 * Create a file containing our process ID.
 */
static void
create_pidfile(int pid)
{
    FILE *pidfile;
    struct ppp_interface *pif = ppp_if[0];

    slprintf(pidfilename, sizeof(pidfilename), "%s%s.pid",
	     _PATH_VARRUN, pif->ifname);
    if ((pidfile = fopen(pidfilename, "w")) != NULL) {
	fprintf(pidfile, "%d\n", pid);
	(void) fclose(pidfile);
    } else {
    	error("Failed to create pid file %s: %m", pidfilename);
    	pidfilename[0] = 0;
    }
}

void
create_linkpidfile(int pid)
{
    FILE *pidfile;
    struct ppp_interface *pif = ppp_if[0];

    if (linkname[0] == 0)
	    return;
    script_setenv("LINKNAME", linkname, 1);
    slprintf(linkpidfile, sizeof(linkpidfile), "%sppp-%s.pid",
	     _PATH_VARRUN, linkname);
    if ((pidfile = fopen(linkpidfile, "w")) != NULL) {
    	fprintf(pidfile, "%d\n", pid);
    	if (pif->ifname[0])
    	    fprintf(pidfile, "%s\n", pif->ifname);
    	(void) fclose(pidfile);
    } else {
    	error("Failed to create pid file %s: %m", linkpidfile);
    	linkpidfile[0] = 0;
    }
}

/*
 * remove_pidfile - remove our pid files
 */
void remove_pidfiles()
{
    if (pidfilename[0] != 0 && unlink(pidfilename) < 0 && errno != ENOENT)
	    warn("unable to delete pid file %s: %m", pidfilename);

    pidfilename[0] = 0;
    
    if (linkpidfile[0] != 0 && unlink(linkpidfile) < 0 && errno != ENOENT)
	warn("unable to delete pid file %s: %m", linkpidfile);

    linkpidfile[0] = 0;
}


/* List of protocol names, to make our messages a little more informative. */
struct protocol_list {
    u_short	proto;
    const char	*name;
} protocol_list[] = {
    { 0x21,	"IP" },
    { 0x23,	"OSI Network Layer" },
    { 0x25,	"Xerox NS IDP" },
    { 0x27,	"DECnet Phase IV" },
    { 0x29,	"Appletalk" },
    { 0x2b,	"Novell IPX" },
    { 0x2d,	"VJ compressed TCP/IP" },
    { 0x2f,	"VJ uncompressed TCP/IP" },
    { 0x31,	"Bridging PDU" },
    { 0x33,	"Stream Protocol ST-II" },
    { 0x35,	"Banyan Vines" },
    { 0x39,	"AppleTalk EDDP" },
    { 0x3b,	"AppleTalk SmartBuffered" },
    { 0x3d,	"Multi-Link" },
    { 0x3f,	"NETBIOS Framing" },
    { 0x41,	"Cisco Systems" },
    { 0x43,	"Ascom Timeplex" },
    { 0x45,	"Fujitsu Link Backup and Load Balancing (LBLB)" },
    { 0x47,	"DCA Remote Lan" },
    { 0x49,	"Serial Data Transport Protocol (PPP-SDTP)" },
    { 0x4b,	"SNA over 802.2" },
    { 0x4d,	"SNA" },
    { 0x4f,	"IP6 Header Compression" },
    { 0x51,	"KNX Bridging Data" },
    { 0x53,	"Encryption" },
    { 0x55,	"Individual Link Encryption" },
    { 0x57,	"IPv6" },
    { 0x59,	"PPP Muxing" },
    { 0x5b,	"Vendor-Specific Network Protocol" },
    { 0x61,	"RTP IPHC Full Header" },
    { 0x63,	"RTP IPHC Compressed TCP" },
    { 0x65,	"RTP IPHC Compressed non-TCP" },
    { 0x67,	"RTP IPHC Compressed UDP 8" },
    { 0x69,	"RTP IPHC Compressed RTP 8" },
    { 0x6f,	"Stampede Bridging" },
    { 0x73,	"MP+" },
    { 0xc1,	"NTCITS IPI" },
    { 0xfb,	"single-link compression" },
    { 0xfd,	"Compressed Datagram" },
    { 0x0201,	"802.1d Hello Packets" },
    { 0x0203,	"IBM Source Routing BPDU" },
    { 0x0205,	"DEC LANBridge100 Spanning Tree" },
    { 0x0207,	"Cisco Discovery Protocol" },
    { 0x0209,	"Netcs Twin Routing" },
    { 0x020b,	"STP - Scheduled Transfer Protocol" },
    { 0x020d,	"EDP - Extreme Discovery Protocol" },
    { 0x0211,	"Optical Supervisory Channel Protocol" },
    { 0x0213,	"Optical Supervisory Channel Protocol" },
    { 0x0231,	"Luxcom" },
    { 0x0233,	"Sigma Network Systems" },
    { 0x0235,	"Apple Client Server Protocol" },
    { 0x0281,	"MPLS Unicast" },
    { 0x0283,	"MPLS Multicast" },
    { 0x0285,	"IEEE p1284.4 standard - data packets" },
    { 0x0287,	"ETSI TETRA Network Protocol Type 1" },
    { 0x0289,	"Multichannel Flow Treatment Protocol" },
    { 0x2063,	"RTP IPHC Compressed TCP No Delta" },
    { 0x2065,	"RTP IPHC Context State" },
    { 0x2067,	"RTP IPHC Compressed UDP 16" },
    { 0x2069,	"RTP IPHC Compressed RTP 16" },
    { 0x4001,	"Cray Communications Control Protocol" },
    { 0x4003,	"CDPD Mobile Network Registration Protocol" },
    { 0x4005,	"Expand accelerator protocol" },
    { 0x4007,	"ODSICP NCP" },
    { 0x4009,	"DOCSIS DLL" },
    { 0x400B,	"Cetacean Network Detection Protocol" },
    { 0x4021,	"Stacker LZS" },
    { 0x4023,	"RefTek Protocol" },
    { 0x4025,	"Fibre Channel" },
    { 0x4027,	"EMIT Protocols" },
    { 0x405b,	"Vendor-Specific Protocol (VSP)" },
    { 0x8021,	"Internet Protocol Control Protocol" },
    { 0x8023,	"OSI Network Layer Control Protocol" },
    { 0x8025,	"Xerox NS IDP Control Protocol" },
    { 0x8027,	"DECnet Phase IV Control Protocol" },
    { 0x8029,	"Appletalk Control Protocol" },
    { 0x802b,	"Novell IPX Control Protocol" },
    { 0x8031,	"Bridging NCP" },
    { 0x8033,	"Stream Protocol Control Protocol" },
    { 0x8035,	"Banyan Vines Control Protocol" },
    { 0x803d,	"Multi-Link Control Protocol" },
    { 0x803f,	"NETBIOS Framing Control Protocol" },
    { 0x8041,	"Cisco Systems Control Protocol" },
    { 0x8043,	"Ascom Timeplex" },
    { 0x8045,	"Fujitsu LBLB Control Protocol" },
    { 0x8047,	"DCA Remote Lan Network Control Protocol (RLNCP)" },
    { 0x8049,	"Serial Data Control Protocol (PPP-SDCP)" },
    { 0x804b,	"SNA over 802.2 Control Protocol" },
    { 0x804d,	"SNA Control Protocol" },
    { 0x804f,	"IP6 Header Compression Control Protocol" },
    { 0x8051,	"KNX Bridging Control Protocol" },
    { 0x8053,	"Encryption Control Protocol" },
    { 0x8055,	"Individual Link Encryption Control Protocol" },
    { 0x8057,	"IPv6 Control Protovol" },
    { 0x8059,	"PPP Muxing Control Protocol" },
    { 0x805b,	"Vendor-Specific Network Control Protocol (VSNCP)" },
    { 0x806f,	"Stampede Bridging Control Protocol" },
    { 0x8073,	"MP+ Control Protocol" },
    { 0x80c1,	"NTCITS IPI Control Protocol" },
    { 0x80fb,	"Single Link Compression Control Protocol" },
    { 0x80fd,	"Compression Control Protocol" },
    { 0x8207,	"Cisco Discovery Protocol Control" },
    { 0x8209,	"Netcs Twin Routing" },
    { 0x820b,	"STP - Control Protocol" },
    { 0x820d,	"EDPCP - Extreme Discovery Protocol Ctrl Prtcl" },
    { 0x8235,	"Apple Client Server Protocol Control" },
    { 0x8281,	"MPLSCP" },
    { 0x8285,	"IEEE p1284.4 standard - Protocol Control" },
    { 0x8287,	"ETSI TETRA TNP1 Control Protocol" },
    { 0x8289,	"Multichannel Flow Treatment Protocol" },
    { 0xc021,	"Link Control Protocol" },
    { 0xc023,	"Password Authentication Protocol" },
    { 0xc025,	"Link Quality Report" },
    { 0xc027,	"Shiva Password Authentication Protocol" },
    { 0xc029,	"CallBack Control Protocol (CBCP)" },
    { 0xc02b,	"BACP Bandwidth Allocation Control Protocol" },
    { 0xc02d,	"BAP" },
    { 0xc05b,	"Vendor-Specific Authentication Protocol (VSAP)" },
    { 0xc081,	"Container Control Protocol" },
    { 0xc223,	"Challenge Handshake Authentication Protocol" },
    { 0xc225,	"RSA Authentication Protocol" },
    { 0xc227,	"Extensible Authentication Protocol" },
    { 0xc229,	"Mitsubishi Security Info Exch Ptcl (SIEP)" },
    { 0xc26f,	"Stampede Bridging Authorization Protocol" },
    { 0xc281,	"Proprietary Authentication Protocol" },
    { 0xc283,	"Proprietary Authentication Protocol" },
    { 0xc481,	"Proprietary Node ID Authentication Protocol" },
    { 0,	NULL },
};

/*
 * protocol_name - find a name for a PPP protocol.
 */
const char *
protocol_name(proto)
    int proto;
{
    struct protocol_list *lp;

    for (lp = protocol_list; lp->proto != 0; ++lp)
	if (proto == lp->proto)
	    return lp->name;
    return NULL;
}

/*
 * get_input - called when incoming data is available.
 */
static void
get_input(int unit)
{
    int len, i;
    char buf[30];
    u_char *p;
    int attach_to_unit;
    u_short protocol;
    struct protent *protp;
    struct ppp_interface *pif = ppp_if[unit];
    
    p = inpacket_buf;	/* point to beginning of packet buffer */

    len = read_packet(unit, pif->dev_fd, pif->ppp_dev_fd, inpacket_buf);
    if (len < 0)
	    return;

    if (len == 0 && pif->multilink_flags&& !pif->is_master)  /* 这个一定要,因为slave的unit是和通道分离的 */
        return;
    
    if (len == 0) { 
        return;
    	ZLOG_INFO("Modem hangup");
    	pif->hungup = 1;
    	status = EXIT_HANGUP;
    	lcp_lowerdown(unit);	/* serial link is no longer available */
    	link_terminated(unit);
    	return;
    }
    
    if (len < PPP_HDRLEN) {
    	dbglog("received short packet:%.*B", len, p);
    	return;
    }

    snprintf(buf, sizeof(buf), "unit:%u: rcvd", unit);
    dump_packet(unit, buf, p, len);//rcvd [LCP ConfReq id=0x1 <asyncmap 0x0> <magic 0x3defe78d> <pcomp> <accomp>]
    pppd_print_buffer("input", unit, p, len);
    
    if (snoop_recv_hook) 
        snoop_recv_hook(p, len);

    p += 2;				/* Skip address and control */
    GETSHORT(protocol, p);
    len -= PPP_HDRLEN;

    /*
     * Toss all non-LCP packets unless LCP is OPEN.
     */
    if (protocol != PPP_LCP && (GET_LCP_FSM(unit))->state != OPENED) {
    	dbglog("Discarded non-LCP packet when LCP not open");
    	return;
    }

    /*
     * Until we get past the authentication phase, toss all packets
     * except LCP, LQR and authentication packets.
     */
    if (pif->phase <= PHASE_AUTHENTICATE
	&& !(protocol == PPP_LCP || protocol == PPP_LQR
	     || protocol == PPP_PAP || protocol == PPP_CHAP ||
		protocol == PPP_EAP)) {
    	dbglog("discarding proto 0x%x in phase %d",
    		   protocol, pif->phase);
    	return;
    }

    if(protocol == PPP_IPCP && (attach_to_unit = ppp_if_get_mp_mater(unit)) >= 0) {
        printf("ipcp, unit:% is son unit, use master unit:%u\n", unit, attach_to_unit);
        unit = attach_to_unit;
    }

    /*
     * Upcall the proper protocol input routine.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i) {
    	if (protp->protocol == protocol && protp->enabled_flag) {// //调用每个协议块的input函数来处理接收报文
    	    (*protp->input)(unit, p, len);//如果是LCP协商节点，调用lcp_input 
    	    return;
    	}
        if (protocol == (protp->protocol & ~0x8000) && protp->enabled_flag
    	    && protp->datainput != NULL) {
    	    (*protp->datainput)(unit, p, len);
    	    return;
    	}
    }

    if (1) {
    	const char *pname = protocol_name(protocol);
    	if (pname != NULL)
    	    warn("Unsupported protocol '%s' (0x%x) received", pname, protocol);
    	else
    	    warn("Unsupported protocol 0x%x received", protocol);
    }

    //goto err_out;
    lcp_sprotrej(unit, p - PPP_HDRLEN, len + PPP_HDRLEN); //yang add change
}

/*
 * ppp_send_config - configure the transmit-side characteristics of
 * the ppp interface.  Returns -1, indicating an error, if the channel
 * send_config procedure called error() (or incremented error_count
 * itself), otherwise 0.
 */
int
ppp_send_config(unit, mtu, accm, pcomp, accomp)
    int unit, mtu;
    u_int32_t accm;
    int pcomp, accomp;
{
	int errs;

	if (the_channel->send_config == NULL)
		return 0;
	errs = error_count;
	(*the_channel->send_config)(mtu, accm, pcomp, accomp);
	return (error_count != errs)? -1: 0;
}

/*
 * ppp_recv_config - configure the receive-side characteristics of
 * the ppp interface.  Returns -1, indicating an error, if the channel
 * recv_config procedure called error() (or incremented error_count
 * itself), otherwise 0.
 */
int
ppp_recv_config(unit, mru, accm, pcomp, accomp)
    int unit, mru;
    u_int32_t accm;
    int pcomp, accomp;
{
	int errs;

	if (the_channel->recv_config == NULL)
		return 0;
	errs = error_count;
	(*the_channel->recv_config)(mru, accm, pcomp, accomp);
	return (error_count != errs)? -1: 0;
}

/*
 * new_phase - signal the start of a new phase of pppd's operation.
 */
void new_phase(int unit, int p)
{
    struct ppp_interface *pif;

    pif = ppp_if[unit];
    pif->phase = p;
}

/*
 * die - clean up state and exit with the specified status.
 */
void
die(status)
    int status;
{
   // exit(status);
    return;
    
    printf("begin to die");
    if (!doing_multilink || multilink_master)
	    print_link_stats();
    cleanup();
    notify(exitnotify, status);
    syslog(LOG_INFO, "Exit.");
    exit(status);
}

/*
 * cleanup - restore anything which needs to be restored before we exit
 */
/* ARGSUSED */
static void
cleanup()
{
    sys_cleanup();

    if (fd_ppp >= 0)
	the_channel->disestablish_ppp(devfd);
	
    if (the_channel->cleanup)
	(*the_channel->cleanup)();
    remove_pidfiles();

#ifdef USE_TDB
    if (pppdb != NULL)
	cleanup_db();
#endif

}

void
print_link_stats()
{
    /*
     * Print connect time and statistics.
     */
    if (link_stats_valid) { //link_down里面获取这些值的
       int t = (link_connect_time + 5) / 6;    /* 1/10ths of minutes */
       info("Connect time %d.%d minutes.", t/10, t%10);
       info("Sent %u bytes, received %u bytes.",
	    link_stats.bytes_out, link_stats.bytes_in);
       link_stats_valid = 0;
    }
}

/*
 * reset_link_stats - "reset" stats when link goes up.
 */
void
reset_link_stats(u)
    int u;
{
    struct ppp_interface *pif = ppp_if[u];
    

    gettimeofday(&pif->linkup_time, NULL);
}

/*
 * update_link_stats - get stats at link termination.
 */
void
update_link_stats(u)
    int u;
{
    struct timeval now;
    char numbuf[32];

    return;
    if (!get_ppp_stats(u, &link_stats)
	|| gettimeofday(&now, NULL) < 0)
	return;
    link_connect_time = now.tv_sec - start_time.tv_sec;
    link_stats_valid = 1;

    link_stats.bytes_in  -= old_link_stats.bytes_in;
    link_stats.bytes_out -= old_link_stats.bytes_out;
    link_stats.pkts_in   -= old_link_stats.pkts_in;
    link_stats.pkts_out  -= old_link_stats.pkts_out;

    slprintf(numbuf, sizeof(numbuf), "%u", link_connect_time);
    script_setenv("CONNECT_TIME", numbuf, 0);
    slprintf(numbuf, sizeof(numbuf), "%u", link_stats.bytes_out);
    script_setenv("BYTES_SENT", numbuf, 0);
    slprintf(numbuf, sizeof(numbuf), "%u", link_stats.bytes_in);
    script_setenv("BYTES_RCVD", numbuf, 0);
}


struct	callout {
    struct timeval	c_time;		/* time at which to call routine */
    void		*c_arg;		/* argument to routine */
    void		(*c_func) __P((int, void *)); /* routine */
    struct		callout *c_next;
};

static struct callout *callout = NULL;	/* Callout list */
static struct timeval timenow;		/* Current time */

/*
 * timeout - Schedule a timeout.
 */
//把新的节点添加到定时队列callout中
void
timeout(func, arg, secs, usecs)
    void (*func) __P((int, void *));
    void *arg;
    int secs, usecs;
{
    struct callout *newp, *p, **pp;

    /*
     * Allocate timeout.
     */
    if ((newp = (struct callout *) malloc(sizeof(struct callout))) == NULL)
	    fatal("Out of memory in timeout()!");
	    
    newp->c_arg = arg;
    newp->c_func = func;
    gettimeofday(&timenow, NULL);
    newp->c_time.tv_sec = timenow.tv_sec + secs;
    newp->c_time.tv_usec = timenow.tv_usec + usecs;
    if (newp->c_time.tv_usec >= 1000000) {
    	newp->c_time.tv_sec += newp->c_time.tv_usec / 1000000;
    	newp->c_time.tv_usec %= 1000000;
    }

    /*
     * Find correct place and link it in.
     */ //按照时间顺序插入到callout链表中。当时间到的时候在calltimeout执行func
    for (pp = &callout; (p = *pp); pp = &p->c_next)
	if (newp->c_time.tv_sec < p->c_time.tv_sec
	    || (newp->c_time.tv_sec == p->c_time.tv_sec
		&& newp->c_time.tv_usec < p->c_time.tv_usec))
	    break;
    newp->c_next = p;
    *pp = newp;
}


/*
 * untimeout - Unschedule a timeout.
 */
void
untimeout(func, arg)
    void (*func) __P((int, void *));
    void *arg;
{
    struct callout **copp, *freep;

    /*
     * Find first matching timeout and remove it from the list.
     */
    for (copp = &callout; (freep = *copp); copp = &freep->c_next)
	if (freep->c_func == func && freep->c_arg == arg) {
	    *copp = freep->c_next;
	    free((char *) freep);
	    break;
	}
}


/*
 * calltimeout - Call any timeout routines which are now due.
 */ //在main的while循环中检查时间函数
static void
calltimeout(int unit)
{
    struct callout *p;

    while (callout != NULL) {
    	p = callout;

    	if (gettimeofday(&timenow, NULL) < 0)
    	    fatal("Failed to get time of day: %m");
    	if (!(p->c_time.tv_sec < timenow.tv_sec
    	      || (p->c_time.tv_sec == timenow.tv_sec
    		  && p->c_time.tv_usec <= timenow.tv_usec))) //有时间到，则调用对应的func函数
    	    break;		/* no, it's not time yet */

    	callout = p->c_next;
    	(*p->c_func)(unit, p->c_arg);

    	free((char *) p);
    }
}


/*
 * timeleft - return the length of time until the next timeout is due.
 */
static struct timeval *
timeleft(tvp)
    struct timeval *tvp;
{
    if (callout == NULL)
		return NULL;

    gettimeofday(&timenow, NULL);
    tvp->tv_sec = callout->c_time.tv_sec - timenow.tv_sec;
    tvp->tv_usec = callout->c_time.tv_usec - timenow.tv_usec;
    if (tvp->tv_usec < 0) {
    	tvp->tv_usec += 1000000;
    	tvp->tv_sec -= 1;
    }
    if (tvp->tv_sec < 0)
	    tvp->tv_sec = tvp->tv_usec = 0;
    
    return tvp;
}


/*
 * kill_my_pg - send a signal to our process group, and ignore it ourselves.
 * We assume that sig is currently blocked.
 */
static void
kill_my_pg(sig)
    int sig;
{
    struct sigaction act, oldact;

    sigemptyset(&act.sa_mask);		/* unnecessary in fact */
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    kill(0, sig);
    /*
     * The kill() above made the signal pending for us, as well as
     * the rest of our process group, but we don't want it delivered
     * to us.  It is blocked at the moment.  Setting it to be ignored
     * will cause the pending signal to be discarded.  If we did the
     * kill() after setting the signal to be ignored, it is unspecified
     * (by POSIX) whether the signal is immediately discarded or left
     * pending, and in fact Linux would leave it pending, and so it
     * would be delivered after the current signal handler exits,
     * leading to an infinite loop.
     */
    sigaction(sig, &act, &oldact);
    sigaction(sig, &oldact, NULL);
}


/*
 * hup - Catch SIGHUP signal.
 *
 * Indicates that the physical layer has been disconnected.
 * We don't rely on this indication; if the user has sent this
 * signal, we just take the link down.
 */
static void
hup(sig)
    int sig;
{
    ZLOG_INFO("recv hup %u", sig);
    exit(1);
    return;
    /* can't log a message here, it can deadlock */
    got_sighup = 1;
    if (conn_running)
	/* Send the signal to the [dis]connector process(es) also */
	kill_my_pg(sig);
    notify(sigreceived, sig);
    if (waiting)
	siglongjmp(sigjmp, 1);
}


/*
 * term - Catch SIGTERM signal and SIGINT signal (^C/del).
 *
 * Indicates that we should initiate a graceful disconnect and exit.
 */
/*ARGSUSED*/
static void
term(sig) //setup_signals
    int sig;
{
    /* can't log a message here, it can deadlock */
    got_sigterm = sig;
   // if (conn_running)
	/* Send the signal to the [dis]connector process(es) also */
	//    kill_my_pg(sig);
   //notify(sigreceived, sig);
  //  if (waiting)
	//    siglongjmp(sigjmp, 1);

	ZLOG_INFO("recv term signal %u", sig);
    exit(1);
    return;
}


/*
 * chld - Catch SIGCHLD signal.
 * Sets a flag so we will call reap_kids in the mainline.
 
static void
chld(sig)
    int sig;
{
    got_sigchld = 1;
    if (waiting)
	siglongjmp(sigjmp, 1);
}*/


/*
 * toggle_debug - Catch SIGUSR1 signal.
 *
 * Toggle debug flag.
 */
/*ARGSUSED
static void
toggle_debug(sig)
    int sig;
{
    debug = !debug;
    if (debug) {
	setlogmask(LOG_UPTO(LOG_DEBUG));
    } else {
	setlogmask(LOG_UPTO(LOG_WARNING));
    }
}*/


/*
 * open_ccp - Catch SIGUSR2 signal.
 *
 * Try to (re)negotiate compression.
 */
/*ARGSUSED
static void
open_ccp(sig)
    int sig;
{
    got_sigusr2 = 1;
    if (waiting)
	siglongjmp(sigjmp, 1);
}*/

char* get_current_datetime2(void)
{
	static char time_buffer[16];
	memset(time_buffer, 0, sizeof(time_buffer));
	
	time_t rawtime; 
	struct tm * timeinfo = NULL; 
	
	time(&rawtime); 
	timeinfo = localtime(&rawtime);
	
    snprintf (time_buffer, sizeof(time_buffer), "%04d%02d%02d%02d%02d%02d",
             timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
             timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
	return time_buffer;
}

static void pppd_sigsegv(int signo)
{
    void *array[10];
    size_t size;
    char **strings;
    size_t i;

    printf("err Tracer received SIGSEGV! Stack trace: mcp sigsegv\n");

    return;
	char szFileName[256];
	snprintf(szFileName, sizeof(szFileName), "/var/pppd.%s.%s", "backtrace", get_current_datetime2());

	FILE* pCoreFile = fopen(szFileName, "w+");
	if(NULL == pCoreFile)
		printf("Error open file %s for mcp dump. errno %d\n", szFileName, errno);		

    size = backtrace (array, 10);
    strings = (char **)backtrace_symbols (array, size);

    ZLOG_INFO("Tracer received SIGSEGV! Stack trace:");
    for (i = 0; i < size; i++) {
        printf("  %d %s \n",i,strings[i]);

		if(pCoreFile)
			fprintf(pCoreFile, "%d %s\n", i,strings[i]);
		
    }

	if(pCoreFile)
		fclose(pCoreFile);

    free (strings);

    return;
}

/*
 * bad_signal - We've caught a fatal signal.  Clean up state and exit.
 */
static void
bad_signal(sig)
    int sig;
{
    ZLOG_INFO("recv bad signal %u", sig);
    pppd_sigsegv(sig);
    exit(1);
    return;
    
    static int crashed = 0;
    if (crashed)
	_exit(127);
    crashed = 1;
    error("Fatal signal %d", sig);
    if (conn_running)
	kill_my_pg(SIGTERM);
    notify(sigreceived, sig);
    die(127);
}

/*
 * safe_fork - Create a child process.  The child closes all the
 * file descriptors that we don't want to leak to a script.
 * The parent waits for the child to do this before returning.
 * This also arranges for the specified fds to be dup'd to
 * fds 0, 1, 2 in the child.
 */
pid_t
safe_fork(int infd, int outfd, int errfd)
{
	pid_t pid;
	int fd, pipefd[2];
	char buf[1];

	/* make sure fds 0, 1, 2 are occupied (probably not necessary) */
	while ((fd = dup(fd_devnull)) >= 0) {
		if (fd > 2) {
			close(fd);
			break;
		}
	}

	if (pipe(pipefd) == -1)
		pipefd[0] = pipefd[1] = -1;
	pid = fork();
	if (pid < 0) {
		error("fork failed: %m");
		return -1;
	}
	if (pid > 0) {
		/* parent */
		close(pipefd[1]);
		/* this read() blocks until the close(pipefd[1]) below */
		complete_read(pipefd[0], buf, 1);
		close(pipefd[0]);
		return pid;
	}

	/* Executing in the child */
	sys_close();
#ifdef USE_TDB
	tdb_close(pppdb);
#endif

	/* make sure infd, outfd and errfd won't get tromped on below */
	if (infd == 1 || infd == 2)
		infd = dup(infd);
	if (outfd == 0 || outfd == 2)
		outfd = dup(outfd);
	if (errfd == 0 || errfd == 1)
		errfd = dup(errfd);

	/* dup the in, out, err fds to 0, 1, 2 */
	if (infd != 0)
		dup2(infd, 0);
	if (outfd != 1)
		dup2(outfd, 1);
	if (errfd != 2)
		dup2(errfd, 2);

	closelog();
	if (log_to_fd > 2)
		close(log_to_fd);
	if (the_channel->close)
		(*the_channel->close)();
	else
		close(devfd);	/* some plugins don't have a close function */
	close(fd_ppp);
	close(fd_devnull);
	if (infd != 0)
		close(infd);
	if (outfd != 1)
		close(outfd);
	if (errfd != 2)
		close(errfd);

	notify(fork_notifier, 0);
	close(pipefd[0]);
	/* this close unblocks the read() call above in the parent */
	close(pipefd[1]);

	return 0;
}

/*
 * device_script - run a program to talk to the specified fds
 * (e.g. to run the connector or disconnector script).
 * stderr gets connected to the log fd or to the _PATH_CONNERRS file.
 */
int
device_script(program, in, out, dont_wait)
    char *program;
    int in, out;
    int dont_wait;
{
    int pid;
    int status = -1;
    int errfd;

    if (log_to_fd >= 0)
	errfd = log_to_fd;
    else
	errfd = open(_PATH_CONNERRS, O_WRONLY | O_APPEND | O_CREAT, 0600);

    ++conn_running;
    pid = safe_fork(in, out, errfd);

    if (pid != 0 && log_to_fd < 0)
	close(errfd);

    if (pid < 0) {
	--conn_running;
	error("Failed to create child process: %m");
	return -1;
    }

    if (pid != 0) {
	if (dont_wait) {
	    record_child(pid, program, NULL, NULL);
	    status = 0;
	} else {
	    while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
		    continue;
		fatal("error waiting for (dis)connection process: %m");
	    }
	    --conn_running;
	}
	return (status == 0 ? 0 : -1);
    }

    /* here we are executing in the child */

    setgid(getgid());
    setuid(uid);
    if (getuid() != uid) {
	fprintf(stderr, "pppd: setuid failed\n");
	exit(1);
    }
    execl("/bin/sh", "sh", "-c", program, (char *)0);
    perror("pppd: could not exec /bin/sh");
    exit(99);
    /* NOTREACHED */
}


/*
 * run-program - execute a program with given arguments,
 * but don't wait for it unless wait is non-zero.
 * If the program can't be executed, logs an error unless
 * must_exist is 0 and the program file doesn't exist.
 * Returns -1 if it couldn't fork, 0 if the file doesn't exist
 * or isn't an executable plain file, or the process ID of the child.
 * If done != NULL, (*done)(arg) will be called later (within
 * reap_kids) iff the return value is > 0.
 */
pid_t
run_program(prog, args, must_exist, done, arg, wait)
    char *prog;
    char **args;
    int must_exist;
    void (*done) __P((void *));
    void *arg;
    int wait;
{
    int pid, status;
    struct stat sbuf;
    /*
     * First check if the file exists and is executable.
     * We don't use access() because that would use the
     * real user-id, which might not be root, and the script
     * might be accessible only to root.
     */
    errno = EINVAL;
    if (stat(prog, &sbuf) < 0 || !S_ISREG(sbuf.st_mode)
	|| (sbuf.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)) == 0) {
    	if (must_exist || errno != ENOENT)
    	    warn("Can't execute %s: %m", prog);
    	return 0;
    }

    pid = safe_fork(fd_devnull, fd_devnull, fd_devnull);
    if (pid == -1) {
    	error("Failed to create child process for %s: %m", prog);
    	return -1;
    }
    if (pid != 0) {
	if (debug)
	    dbglog("Script %s started (pid %d)", prog, pid);
	record_child(pid, prog, done, arg);
	if (wait) {
	    while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
		    continue;
		fatal("error waiting for script %s: %m", prog);
	    }
	    forget_child(pid, status);
	}
	return pid;
    }

    /* Leave the current location */
    (void) setsid();	/* No controlling tty. */
    (void) umask (S_IRWXG|S_IRWXO);
    (void) chdir ("/");	/* no current directory. */
    setuid(0);		/* set real UID = root */
    setgid(getegid());

#ifdef BSD
    /* Force the priority back to zero if pppd is running higher. */
    if (setpriority (PRIO_PROCESS, 0, 0) < 0)
	warn("can't reset priority to 0: %m");
#endif

    /* run the program */
    execve(prog, args, script_env);
    if (must_exist || errno != ENOENT) {
	/* have to reopen the log, there's nowhere else
	   for the message to go. */
	reopen_log();
	syslog(LOG_ERR, "Can't execute %s: %m", prog);
	closelog();
    }
    _exit(-1);
}


/*
 * record_child - add a child process to the list for reap_kids
 * to use.
 */
void
record_child(pid, prog, done, arg)
    int pid;
    char *prog;
    void (*done) __P((void *));
    void *arg;
{
    struct subprocess *chp;

    ++n_children;

    chp = (struct subprocess *) malloc(sizeof(struct subprocess));
    if (chp == NULL) {
	warn("losing track of %s process", prog);
    } else {
	chp->pid = pid;
	chp->prog = prog;
	chp->done = done;
	chp->arg = arg;
	chp->next = children;
	children = chp;
    }
}

/*
 * forget_child - clean up after a dead child
 */
static void
forget_child(pid, status)
    int pid, status;
{
    struct subprocess *chp, **prevp;

    for (prevp = &children; (chp = *prevp) != NULL; prevp = &chp->next) {
        if (chp->pid == pid) {
	    --n_children;
	    *prevp = chp->next;
	    break;
	}
    }
    if (WIFSIGNALED(status)) {
        warn("Child process %s (pid %d) terminated with signal %d",
	     (chp? chp->prog: "??"), pid, WTERMSIG(status));
    } else if (debug)
        dbglog("Script %s finished (pid %d), status = 0x%x",
	       (chp? chp->prog: "??"), pid,
	       WIFEXITED(status) ? WEXITSTATUS(status) : status);
    if (chp && chp->done)
        (*chp->done)(chp->arg);
    if (chp)
        free(chp);
}

/*
 * reap_kids - get status from any dead child processes,
 * and log a message for abnormal terminations.
 */
static int
reap_kids()
{
    int pid, status;

    if (n_children == 0)
	return 0;
    while ((pid = waitpid(-1, &status, WNOHANG)) != -1 && pid != 0) {
        forget_child(pid, status);
    }
    if (pid == -1) {
    	if (errno == ECHILD)
    	    return -1;
    	if (errno != EINTR)
    	    error("Error waiting for child process: %m");
    }
    return 0;
}

/*
 * add_notifier - add a new function to be called when something happens.
 */
void
add_notifier(notif, func, arg)
    struct notifier **notif;
    notify_func func;
    void *arg;
{
    struct notifier *np;

    np = malloc(sizeof(struct notifier));
    if (np == 0)
	novm("notifier struct");
    np->next = *notif;
    np->func = func;
    np->arg = arg;
    *notif = np;
}

/*
 * remove_notifier - remove a function from the list of things to
 * be called when something happens.
 */
void
remove_notifier(notif, func, arg)
    struct notifier **notif;
    notify_func func;
    void *arg;
{
    struct notifier *np;

    for (; (np = *notif) != 0; notif = &np->next) {
	if (np->func == func && np->arg == arg) {
	    *notif = np->next;
	    free(np);
	    break;
	}
    }
}

/*
 * notify - call a set of functions registered with add_notifier.
 */
void
notify(notif, val)
    struct notifier *notif;
    int val;
{
    struct notifier *np;

    while ((np = notif) != 0) {
	notif = np->next;
	(*np->func)(np->arg, val);
    }
}

/*
 * novm - log an error message saying we ran out of memory, and die.
 */
void
novm(msg)
    char *msg;
{
    fatal("Virtual memory exhausted allocating %s\n", msg);
}

/*
 * script_setenv - set an environment variable value to be used
 * for scripts that we run (e.g. ip-up, auth-up, etc.)
 */
void
script_setenv(var, value, iskey)  //这里面会写数据库
//如果iskey=1,则按照var=value写入数据库
//pppd2.tdb中的key(后面字符串长度)="var=value"  data(后面的字符串长度) = "pppd%u(pid号)"
    char *var, *value;
    int iskey;
{
    size_t varl = strlen(var);
    size_t vl = varl + strlen(value) + 2;
    int i;
    char *p, *newstring;

    newstring = (char *) malloc(vl+1);
    if (newstring == 0)
	    return;
    *newstring++ = iskey;
    slprintf(newstring, vl, "%s=%s", var, value);
    /* check if this variable is already set */
    if (script_env != 0) {
	    for (i = 0; (p = script_env[i]) != 0; ++i) {
    	    if (strncmp(p, var, varl) == 0 && p[varl] == '=') {
        #ifdef USE_TDB
        		if (p[-1] && pppdb != NULL)
        		    delete_db_key(p);
        #endif
        		free(p-1);
        		script_env[i] = newstring;
        #ifdef USE_TDB
        		if (iskey && pppdb != NULL)
        		    add_db_key(newstring);
        		update_db_entry();
        #endif
        		return;
        	    }
    	}
    } else {
    	/* no space allocated for script env. ptrs. yet */
    	i = 0;
    	script_env = (char **) malloc(16 * sizeof(char *));
    	if (script_env == 0)
    	    return;
    	s_env_nalloc = 16;
    }

    /* reallocate script_env with more space if needed */
    if (i + 1 >= s_env_nalloc) {
    	int new_n = i + 17;
    	char **newenv = (char **) realloc((void *)script_env,
    					  new_n * sizeof(char *));
    	if (newenv == 0)
    	    return;
    	script_env = newenv;
    	s_env_nalloc = new_n;
    }

    script_env[i] = newstring;
    script_env[i+1] = 0;

#ifdef USE_TDB
    if (pppdb != NULL) {
    	if (iskey)
    	    add_db_key(newstring);
    	update_db_entry();
    }
#endif
}

/*
 * script_unsetenv - remove a variable from the environment
 * for scripts.
 */
/*
root@darkstar:/var/testpppd# tdbdump pppd2_budle3_025 
{
key(46) = "BUNDLE=\22paptest\22/local:63.68.61.70.74.65.73.74"//是通过mp_join_bundle->script_setenv设置
data(8) = "pppd3855"
}
{
key(52) = "BUNDLE_LINKS=\22paptest\22/local:63.68.61.70.74.65.73.74"  mp_join_bundle->make_bundle_links
data(10) = "pppd3855;\00"
}
{
key(11) = "IFNAME=ppp0"  //是通过mp_join_bundle->set_ifunit函数中调用script_setenv设置
data(8) = "pppd3855"  
}
{
key(13) = "PPPD_PID=3855" //这个是main一起来的时候就调用script_setenv设置
data(8) = "pppd3855"
}
{
key(8) = "pppd3855" //这个是每次调用script_setenv中的update_db_entry时候都会更新一次，把上面所有设置过的data联系在一起
data(73) = "PPPD_PID=3855;IFNAME=ppp0;BUNDLE=\22paptest\22/local:63.68.61.70.74.65.73.74\00"
}
*/

void
script_unsetenv(var) //这里面会删除数据库相关key信息
    char *var;
{
    int vl = strlen(var);
    int i;
    char *p;

    if (script_env == 0)
	    return;
    for (i = 0; (p = script_env[i]) != 0; ++i) {
    	if (strncmp(p, var, vl) == 0 && p[vl] == '=') {
    #ifdef USE_TDB
    	    if (p[-1] && pppdb != NULL)
    		delete_db_key(p);
    #endif
    	    free(p-1);
    	    while ((script_env[i] = script_env[i+1]) != 0)
    		    ++i;
    	    break;
    	}
    }
#ifdef USE_TDB
    if (pppdb != NULL)
	    update_db_entry();
#endif
}

/*
 * Any arbitrary string used as a key for locking the database.
 * It doesn't matter what it is as long as all pppds use the same string.
 */
#define PPPD_LOCK_KEY	"pppd lock"

/*
 * lock_db - get an exclusive lock on the TDB database.
 * Used to ensure atomicity of various lookup/modify operations.
 */
void lock_db()
{
#ifdef USE_TDB
	TDB_DATA key;

	key.dptr = PPPD_LOCK_KEY;
	key.dsize = strlen(key.dptr);
	tdb_chainlock(pppdb, key);
#endif
}

/*
 * unlock_db - remove the exclusive lock obtained by lock_db.
 */
void unlock_db()
{
#ifdef USE_TDB
	TDB_DATA key;

	key.dptr = PPPD_LOCK_KEY;
	key.dsize = strlen(key.dptr);
	tdb_chainunlock(pppdb, key);
#endif
}

#ifdef USE_TDB
/*
 * update_db_entry - update our entry in the database.
 */
static void
update_db_entry()
{
    TDB_DATA key, dbuf;
    int vlen, i;
    char *p, *q, *vbuf;

    if (script_env == NULL)
	return;
    vlen = 0;
    for (i = 0; (p = script_env[i]) != 0; ++i)
	vlen += strlen(p) + 1; //data(73) = "PPPD_PID=3855;IFNAME=ppp0;BUNDLE=\22paptest\22/local:63.68.61.70.74.65.73.74\00"
    vbuf = malloc(vlen + 1);
    if (vbuf == 0)
	novm("database entry");
    q = vbuf;
    for (i = 0; (p = script_env[i]) != 0; ++i)
	q += slprintf(q, vbuf + vlen - q, "%s;", p);

    key.dptr = db_key;
    key.dsize = strlen(db_key);
    dbuf.dptr = vbuf;
    dbuf.dsize = vlen;
    if (tdb_store(pppdb, key, dbuf, TDB_REPLACE))
	error("tdb_store failed: %s", tdb_error(pppdb));

    if (vbuf)
        free(vbuf);

}

/*
 * add_db_key - add a key that we can use to look up our database entry.
 */
static void
add_db_key(str)
    const char *str;
{
    TDB_DATA key, dbuf;

    key.dptr = (char *) str;
    key.dsize = strlen(str);
    dbuf.dptr = db_key; //slprintf(db_key, sizeof(db_key), "pppd%d", getpid());
    dbuf.dsize = strlen(db_key);
    if (tdb_store(pppdb, key, dbuf, TDB_REPLACE)) 
	error("tdb_store key failed: %s", tdb_error(pppdb));
}

/*
 * delete_db_key - delete a key for looking up our database entry.
 */
static void
delete_db_key(str)
    const char *str;
{
    TDB_DATA key;

    key.dptr = (char *) str;
    key.dsize = strlen(str);
    tdb_delete(pppdb, key);
}

/*
 * cleanup_db - delete all the entries we put in the database.
 */
static void
cleanup_db()
{
    TDB_DATA key;
    int i;
    char *p;

    key.dptr = db_key;
    key.dsize = strlen(db_key);
    tdb_delete(pppdb, key);
    for (i = 0; (p = script_env[i]) != 0; ++i)
	if (p[-1])
	    delete_db_key(p);
}
#endif /* USE_TDB */
