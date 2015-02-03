/*
 * auth.c - PPP authentication and phase control.
 *
 * Copyright (c) 1993-2002 Paul Mackerras. All rights reserved.
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
 *
 * Derived from main.c, which is:
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
 */

#define RCSID	"$Id: auth.c,v 1.112 2006/06/18 11:26:00 paulus Exp $"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <utmp.h>
#include <fcntl.h>
#if defined(_PATH_LASTLOG) && defined(__linux__)
#include <lastlog.h>
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef USE_PAM
#include <security/pam_appl.h>
#endif

#ifdef HAS_SHADOW
#include <shadow.h>
#ifndef PW_PPP
#define PW_PPP PW_LOGIN
#endif
#endif
#include <time.h>

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "ccp.h"
#include "ecp.h"
#include "ipcp.h"
#include "upap.h"
#include "chap-new.h"
#include "eap.h"
#ifdef CBCP_SUPPORT
#include "cbcp.h"
#endif
#include "pathnames.h"
#include "ppp_remark.h"
#include "pppd_debug.h"
#include "ppp_remark.h"
#include "pppd_tmp.h"

static const char rcsid[] = RCSID;

/* Bits in scan_authfile return value */
#define NONWILD_SERVER	1
#define NONWILD_CLIENT	2

#define ISWILD(word)	(word[0] == '*' && word[1] == 0)

/* The name by which the peer authenticated itself to us. */
char peer_authname[MAXNAMELEN]; //本端为服务器端，客户端发送req，我们服务器端密码验证通过后，记录客户端用户名到该结构体中

/* Records which authentication operations haven't completed yet. */
//static int auth_pending[NUM_PPP];//在函数link_established中标记了是否认证都认证结束了，例如是双向认证，则需要两方都认证成功才算成功  见link_established

/* Records which authentication operations have been completed. */
int auth_done[NUM_PPP];

/* Set if we have successfully called plogin() */
static int logged_in;

/* List of addresses which the peer may use. */
static struct permitted_ip *addresses[NUM_PPP];

/* Wordlist giving addresses which the peer may use
   without authenticating itself. */
static struct wordlist *noauth_addrs; //在命令中allow-ip设置，该变量设置的ip地址不需要认证，就算是设置了auth命令，则该addr也是可以直接分片出去的，见link_established

/* Remote telephone number, if available */
char remote_number[MAXNAMELEN];

/* Wordlist giving remote telephone numbers which may connect. */
static struct wordlist *permitted_numbers;  //在allow-number中配置

/* Extra options to apply, from the secrets file entry for the peer. */
static struct wordlist *extra_options;

/* Number of network protocols which we have opened. */
//static int num_np_open;

/* Number of network protocols which have come up. */
//static int num_np_up;

/* Set if we got the contents of passwd[] from the pap-secrets file. */
static int passwd_from_file;// 如果if (passwd[0] == 0)，则从文件中获取密码

/* Set if we require authentication only because we have a default route. */
static bool default_auth;

/* Hook to enable a plugin to control the idle time limit */
int (*idle_time_hook) __P((struct ppp_idle *)) = NULL;

/* Hook for a plugin to say whether we can possibly authenticate any peer */
int (*pap_check_hook) __P((void)) = NULL;

/* Hook for a plugin to check the PAP user and password */
int (*pap_auth_hook) __P((char *user, char *passwd, char **msgp,
			  struct wordlist **paddrs,
			  struct wordlist **popts)) = NULL;

/* Hook for a plugin to know about the PAP user logout */
void (*pap_logout_hook) __P((void)) = NULL;

/* Hook for a plugin to get the PAP password for authenticating us */
int (*pap_passwd_hook) __P((char *user, char *passwd)) = NULL;

/* Hook for a plugin to say if we can possibly authenticate a peer using CHAP */
int (*chap_check_hook) __P((void)) = NULL;

/* Hook for a plugin to get the CHAP password for authenticating us */
int (*chap_passwd_hook) __P((char *user, char *passwd)) = NULL;

/* Hook for a plugin to say whether it is OK if the peer
   refuses to authenticate. */
int (*null_auth_hook) __P((struct wordlist **paddrs,
			   struct wordlist **popts)) = NULL;

int (*allowed_address_hook) __P((u_int32_t addr)) = NULL;

/* A notifier for when the peer has authenticated itself,
   and we are proceeding to the network phase. */
struct notifier *auth_up_notifier = NULL;

/* A notifier for when the link goes down. */
struct notifier *link_down_notifier = NULL;

/*
 * This is used to ensure that we don't start an auth-up/down
 * script while one is already running.
 */
enum script_state {
    s_down,
    s_up
};

static enum script_state auth_state = s_down;
static enum script_state auth_script_state = s_down;
static pid_t auth_script_pid = 0;

static int used_login;		/* peer authenticated against login database */                 //如果客户端发送过来的密码是@login，该变量置1 或者是配置了uselogin

/*
 * Option variables.
 */
bool uselogin = 0;		/* Use /etc/passwd for checking PAP */ //见check_passwd //在参数login中配置  Use system password database for PAP  如果配置了该项，则服务器端收到客户端密码后，用/etc/passwd文件来查找是否有与req中相同的用户名和密码
bool cryptpap = 0;		/* Passwords in pap-secrets are encrypted */ //本段为客户端，对端发送authreq过来后，如果改为为1，需要对密码部分解密，配置方式papcrypt
bool refuse_pap = 0;		/* Don't wanna auth. ourselves with PAP */
bool refuse_chap = 0;		/* Don't wanna auth. ourselves with CHAP */
bool refuse_eap = 0;		/* Don't wanna auth. ourselves with EAP */
#ifdef CHAPMS
bool refuse_mschap = 0;		/* Don't wanna auth. ourselves with MS-CHAP */
bool refuse_mschap_v2 = 0;	/* Don't wanna auth. ourselves with MS-CHAPv2 */
#else
bool refuse_mschap = 1;		/* Don't wanna auth. ourselves with MS-CHAP */
bool refuse_mschap_v2 = 1;	/* Don't wanna auth. ourselves with MS-CHAPv2 */
#endif
bool usehostname = 0;		/* Use hostname for our_name */
bool auth_required = 0;		/* Always require authentication from peer *///在auth中配置,或者满足下面条件也需要认证have_route_to(0) && !privileged
bool allow_any_ip = 0;		/* Allow peer to use any IP address 如果配置了noauth则任意ip，默认是不认证*/
bool explicit_remote = 0;	/* User specified explicit remote name */ //remotename中设置
char remote_name[MAXNAMELEN];	/* Peer's name for authentication */ //setipaddr <local_IP_address>:<remote_IP_address>或者remote_name中设置,只有出错的时候才会设置
                                 //在remotename命令中也可以设置
static char *uafname;		/* name of most recent +ua file */

extern char *crypt __P((const char *, const char *));

/* Prototypes for procedures local to this file. */

static void network_phase __P((int));
static void check_idle __P((int, void *));
static void connect_time_expired __P((int, void *));
static int  plogin __P((char *, char *, char **));
static void plogout __P((void));
static int  null_login __P((int));
static int  get_pap_passwd __P((char *));
static int  have_pap_secret __P((int *));
static int  have_chap_secret __P((char *, char *, int, int *));
static int  have_srp_secret __P((char *client, char *server, int need_ip,
    int *lacks_ipp));
static int  ip_addr_check __P((u_int32_t, struct permitted_ip *));
static int  scan_authfile __P((FILE *, char *, char *, char *,
			       struct wordlist **, struct wordlist **,
			       char *, int));
static void free_wordlist __P((struct wordlist *));
static void auth_script __P((char *));
static void auth_script_done __P((void *));
static void set_allowed_addrs __P((int, struct wordlist *, struct wordlist *));
static int  some_ip_ok __P((struct wordlist *));
static int  setupapfile __P((char **));
static int  privgroup __P((char **));
static int  set_noauth_addr __P((char **));
static int  set_permitted_number __P((char **));
static void check_access __P((FILE *, char *));
static int  wordlist_count __P((struct wordlist *));

#ifdef MAXOCTETS
static void check_maxoctets __P((void *));
#endif

/*
 * Authentication-related options.
 */
option_t auth_options[] = {
    { "auth", o_bool, &auth_required,
      "Require authentication from peer", OPT_PRIO | 1},
    { "noauth", o_bool, &auth_required,
      "Don't require peer to authenticate", OPT_PRIOSUB | OPT_PRIV,
      &allow_any_ip },
    { "require-pap", o_bool, &lcp_wantoptions[0].neg_upap,//告诉对方，你需要向我们认证，你需要发送auth req请求过来
      "Require PAP authentication from peer", 
      OPT_PRIOSUB | 1, &auth_required},
    { "+pap", o_bool, &lcp_wantoptions[0].neg_upap,
      "Require PAP authentication from peer",
      OPT_ALIAS | OPT_PRIOSUB | 1, &auth_required},
    { "require-chap", o_bool, &auth_required,
      "Require CHAP authentication from peer",
      OPT_PRIOSUB | OPT_A2OR | MDTYPE_MD5,
      &lcp_wantoptions[0].chap_mdtype },
    { "+chap", o_bool, &auth_required,
      "Require CHAP authentication from peer",
      OPT_ALIAS | OPT_PRIOSUB | OPT_A2OR | MDTYPE_MD5,
      &lcp_wantoptions[0].chap_mdtype },
#ifdef CHAPMS
    { "require-mschap", o_bool, &auth_required,
      "Require MS-CHAP authentication from peer",
      OPT_PRIOSUB | OPT_A2OR | MDTYPE_MICROSOFT,
      &lcp_wantoptions[0].chap_mdtype },
    { "+mschap", o_bool, &auth_required,
      "Require MS-CHAP authentication from peer",
      OPT_ALIAS | OPT_PRIOSUB | OPT_A2OR | MDTYPE_MICROSOFT,
      &lcp_wantoptions[0].chap_mdtype },
    { "require-mschap-v2", o_bool, &auth_required,
      "Require MS-CHAPv2 authentication from peer",
      OPT_PRIOSUB | OPT_A2OR | MDTYPE_MICROSOFT_V2,
      &lcp_wantoptions[0].chap_mdtype },
    { "+mschap-v2", o_bool, &auth_required,
      "Require MS-CHAPv2 authentication from peer",
      OPT_ALIAS | OPT_PRIOSUB | OPT_A2OR | MDTYPE_MICROSOFT_V2,
      &lcp_wantoptions[0].chap_mdtype },
#endif

    { "refuse-pap", o_bool, &refuse_pap,
      "Don't agree to auth to peer with PAP", 1 },
    { "-pap", o_bool, &refuse_pap,
      "Don't allow PAP authentication with peer", OPT_ALIAS | 1 },
    { "refuse-chap", o_bool, &refuse_chap,
      "Don't agree to auth to peer with CHAP",
      OPT_A2CLRB | MDTYPE_MD5,
      &lcp_allowoptions[0].chap_mdtype },
    { "-chap", o_bool, &refuse_chap,
      "Don't allow CHAP authentication with peer",
      OPT_ALIAS | OPT_A2CLRB | MDTYPE_MD5,
      &lcp_allowoptions[0].chap_mdtype },
#ifdef CHAPMS
    { "refuse-mschap", o_bool, &refuse_mschap,
      "Don't agree to auth to peer with MS-CHAP",
      OPT_A2CLRB | MDTYPE_MICROSOFT,
      &lcp_allowoptions[0].chap_mdtype },
    { "-mschap", o_bool, &refuse_mschap,
      "Don't allow MS-CHAP authentication with peer",
      OPT_ALIAS | OPT_A2CLRB | MDTYPE_MICROSOFT,
      &lcp_allowoptions[0].chap_mdtype },
    { "refuse-mschap-v2", o_bool, &refuse_mschap_v2,
      "Don't agree to auth to peer with MS-CHAPv2",
      OPT_A2CLRB | MDTYPE_MICROSOFT_V2,
      &lcp_allowoptions[0].chap_mdtype },
    { "-mschap-v2", o_bool, &refuse_mschap_v2,
      "Don't allow MS-CHAPv2 authentication with peer",
      OPT_ALIAS | OPT_A2CLRB | MDTYPE_MICROSOFT_V2,
      &lcp_allowoptions[0].chap_mdtype },
#endif

    { "require-eap", o_bool, &lcp_wantoptions[0].neg_eap,
      "Require EAP authentication from peer", OPT_PRIOSUB | 1,
      &auth_required },
    { "refuse-eap", o_bool, &refuse_eap,
      "Don't agree to authenticate to peer with EAP", 1 },

    { "name", o_string, our_name,
      "Set local name for authentication",
      OPT_PRIO | OPT_PRIV | OPT_STATIC, NULL, MAXNAMELEN },

    { "+ua", o_special, (void *)setupapfile,
      "Get PAP user and password from file",
      OPT_PRIO | OPT_A2STRVAL, &uafname },

    { "user", o_string, user,
      "Set name for auth with peer", OPT_PRIO | OPT_STATIC, NULL, MAXNAMELEN },

    { "password", o_string, passwd,
      "Password for authenticating us to the peer",
      OPT_PRIO | OPT_STATIC | OPT_HIDE, NULL, MAXSECRETLEN },

    { "usehostname", o_bool, &usehostname,
      "Must use hostname for authentication", 1 },

    { "remotename", o_string, remote_name,
      "Set remote name for authentication", OPT_PRIO | OPT_STATIC,
      &explicit_remote, MAXNAMELEN },

    { "login", o_bool, &uselogin,
      "Use system password database for PAP", 1 },

    { "papcrypt", o_bool, &cryptpap,
      "PAP passwords are encrypted", 1 },

    { "privgroup", o_special, (void *)privgroup,
      "Allow group members to use privileged options", OPT_PRIV | OPT_A2LIST },

    { "allow-ip", o_special, (void *)set_noauth_addr,
      "Set IP address(es) which can be used without authentication",
      OPT_PRIV | OPT_A2LIST },

    { "remotenumber", o_string, remote_number,
      "Set remote telephone number for authentication", OPT_PRIO | OPT_STATIC,
      NULL, MAXNAMELEN },

    { "allow-number", o_special, (void *)set_permitted_number,
      "Set telephone number(s) which are allowed to connect",
      OPT_PRIV | OPT_A2LIST },

    { NULL }
};

/*
 * setupapfile - specifies UPAP info for authenticating with peer.
 */
static int
setupapfile(argv)
    char **argv;
{
    FILE *ufile;
    int l;
    uid_t euid;
    char u[MAXNAMELEN], p[MAXSECRETLEN];
    char *fname;

    lcp_allowoptions[0].neg_upap = 1;

    /* open user info file */
    fname = strdup(*argv);
    if (fname == NULL)
	novm("+ua file name");
    euid = geteuid();
    if (seteuid(getuid()) == -1) {
	option_error("unable to reset uid before opening %s: %m", fname);
	return 0;
    }
    ufile = fopen(fname, "r");
    if (seteuid(euid) == -1)
	fatal("unable to regain privileges: %m");
    if (ufile == NULL) {
	option_error("unable to open user login data file %s", fname);
	return 0;
    }
    check_access(ufile, fname);
    uafname = fname;

    /* get username */
    if (fgets(u, MAXNAMELEN - 1, ufile) == NULL
	|| fgets(p, MAXSECRETLEN - 1, ufile) == NULL) {
	fclose(ufile);
	option_error("unable to read user login data file %s", fname);
	return 0;
    }
    fclose(ufile);

    /* get rid of newlines */
    l = strlen(u);
    if (l > 0 && u[l-1] == '\n')
	u[l-1] = 0;
    l = strlen(p);
    if (l > 0 && p[l-1] == '\n')
	p[l-1] = 0;

    if (override_value("user", option_priority, fname))
	strlcpy(user, u, sizeof(user));
    if (override_value("passwd", option_priority, fname))
	strlcpy(passwd, p, sizeof(passwd));

    return (1);
}


/*
 * privgroup - allow members of the group to have privileged access.
 */
static int
privgroup(argv)
    char **argv;
{
    struct group *g;
    int i;

    g = getgrnam(*argv);
    if (g == 0) {
	option_error("group %s is unknown", *argv);
	return 0;
    }
    for (i = 0; i < ngroups; ++i) {
	if (groups[i] == g->gr_gid) {
	    privileged = 1;
	    break;
	}
    }
    return 1;
}


/*
 * set_noauth_addr - set address(es) that can be used without authentication.
 * Equivalent to specifying an entry like `"" * "" addr' in pap-secrets.
 */
static int
set_noauth_addr(argv)
    char **argv;
{
    char *addr = *argv;
    int l = strlen(addr) + 1;
    struct wordlist *wp;

    wp = (struct wordlist *) malloc(sizeof(struct wordlist) + l);
    if (wp == NULL)
	novm("allow-ip argument");
    wp->word = (char *) (wp + 1);
    wp->next = noauth_addrs;
    BCOPY(addr, wp->word, l);
    noauth_addrs = wp;
    return 1;
}


/*
 * set_permitted_number - set remote telephone number(s) that may connect.
 */
static int
set_permitted_number(argv)
    char **argv;
{
    char *number = *argv;
    int l = strlen(number) + 1;
    struct wordlist *wp;

    wp = (struct wordlist *) malloc(sizeof(struct wordlist) + l);
    if (wp == NULL)
	novm("allow-number argument");
    wp->word = (char *) (wp + 1);
    wp->next = permitted_numbers;
    BCOPY(number, wp->word, l);
    permitted_numbers = wp;
    return 1;
}


/*
 * An Open on LCP has requested a change from Dead to Establish phase.
 */
void
link_required(unit)
    int unit;
{
}

/*
 * Bring the link up to the point of being able to do ppp.
 */
void start_link(int unit)
{
    char *msg;
    int fd;
    struct ppp_interface *pif = ppp_if[unit];

    pif->hungup = 0;
    new_phase(unit, PHASE_SERIALCONN); //PPPD状态机为“串口连接”阶段
    fd = the_channel->establish_ppp(unit);//2. 调用 ppp_remark_establish_ppp
    msg = "ppp establishment failed";
    if (fd < 0) {
    	status = EXIT_FATAL_ERROR;
    	goto disconnect;
    }

    if(PPP_CHECK_FLAG(pppd_debug_if, (1 << unit)))   
        PPPD_DEBUG_NEGTIAT("Connect: %s <--> %s", pif->ifname, "/dev/ppp");
    //add_fd(pif->dev_fd); 放ppp_remark_establish_ppp函数里面

    PPPD_DEBUG_NEGTIAT("start_link........ devfd:%u, ppp_devfd:%u", pif->dev_fd, pif->ppp_dev_fd);
    status = EXIT_NEGOTIATION_FAILED;
    new_phase(unit,PHASE_ESTABLISH); //PPPD状态机进入“链路建立”阶段

    lcp_lowerup(unit);//3. 发送LCP Configure Request报文，向对方请求建立LCP链路
    return;

 disconnect:
    new_phase(unit,PHASE_DISCONNECT);
    if (the_channel->disconnect)
	the_channel->disconnect();


    new_phase(unit,PHASE_DEAD);
    if (the_channel->cleanup)
	(*the_channel->cleanup)();
}

/*
 * LCP has terminated the link; go to the Dead phase and take the
 * physical layer down.
 */ //link_terminated和mp_bundle_terminated对应
void  //lcp_finished->link_terminated->fsm_lowerdown->lcp_down
link_terminated(unit) //相当于lcp_finished     如果是multilink,这里面最终还是会在mp_bundle_terminated中调用lcp_close
    int unit;
{
    struct ppp_interface *pif = ppp_if[unit];
    
    if (pif->phase == PHASE_DEAD || pif->phase == PHASE_MASTER)
		return;
	
    new_phase(unit, PHASE_DISCONNECT);

    if (!pif->doing_multilink) {
    	notice("Connection terminated.");
    } else
	    notice("Link terminated.");
    
    /*
     * If we may want to bring the link up again, transfer
     * the ppp unit back to the loopback.  Set the
     * real serial device back to its normal mode of operation.
     */
    if (pif->dev_fd >= 0) {
    	//remove_fd(pif->dev_fd);
    	//clean_check();
    	//the_channel->disestablish_ppp(pif->dev_fd);
    	//if(pif->doing_multilink)
    	//    mp_exit_bundle(unit);

    	 //pif->dev_fd = -1;
    }
    if (!pif->hungup) //如果是main接收的时候返回长度为0，在里面会赋值hungup为1,那里面已经指向了lcp_lowerdown
		lcp_lowerdown(unit);

    /*
     * Run disconnector script, if requested.
     * XXX we may not be able to do this if the line has hung up!
     */
    if (the_channel->disconnect) { 
    	the_channel->disconnect();  //NULL
    }
    
    if (the_channel->cleanup)
	    (*the_channel->cleanup)(); //NULL

    if (pif->multilink_flags && pif->is_master == 1) {
    	//if (pif->bundle_terminating)
    	//    new_phase(unit, PHASE_MASTER);
    	//else
    	    //mp_bundle_terminated(unit);放在link_down中执行
    } else
	    new_phase(unit,PHASE_DEAD);
}

/*
 * LCP has gone down; it will either die or try to re-establish.
 */
//                                                                                                                 |-1.ipcp_lowerdown->ipcp_down
//lcp_close->fsm_close->terminate_layer->(如果这里lcp是协商成功的继续后面)lcp_down->link_down->upper_layers_down->                                      
//                                                                                                                 |-2.ipcp_close->fsm_close->terminate_layer(不在执行ipcp_down，因为前面的ipcp_lowerdown把状态该为closing)
//lcp_finished->link_terminated->fsm_lowerdown->lcp_down

void link_down(int unit)  
{
    struct ppp_interface *pif = ppp_if[unit];
    struct multilink_if_info* mul_if;
    
    if (auth_state != s_down) {
    	notify(link_down_notifier, 0);
    	auth_state = s_down;
    	if (auth_script_state == s_up && auth_script_pid == 0) {
    	    update_link_stats(unit);
    	    auth_script_state = s_down;
    	    auth_script(_PATH_AUTHDOWN);
    	}
    }
    if (!pif->doing_multilink) {
    	upper_layers_down(unit); //这里面会清除接口等信息，如果为multilink这里不能执行这些
    	if (pif->phase != PHASE_DEAD && pif->phase != PHASE_MASTER)
    	    new_phase(unit,PHASE_ESTABLISH);
    } 

    if(pif->multilink_flags == 1 && pif->is_master == 0 && pif->doing_multilink == 1) {    
        //if(pif->enable == 0) /* 如果不使能PPP，这里不用调用del connect ，因为pppd_interface_disable的the_channel->disestablish_ppp(unit)会调用，避免重复	 */
        //    ppp_remark_del_connect_channel(unit); 
        mul_if = ppp_remark_lookup_multilink_interface(pif->mp_ifindex);
        if(mul_if == NULL) 
            PPPD_DEBUG_NEGTIAT("can not find mp num:%u, unit:%u", pif->mp_ifindex, unit);
        else
            PPP_CLEAR_MULTI_BIT(mul_if->interface_bit, unit);

        ppp_remark_del_connect_channel(unit);
        ppp_remark_connect_channel_to_unit(unit);//使channel连接到自己对应的unit,unit=channel
    } else if(pif->multilink_flags == 1 && pif->is_master == 1) {
        mp_bundle_terminated(unit);
    }

   /* pif->is_master = 0;
    pif->doing_multilink = 0;
    pif->is_ipcp_up = 0;
    pif->attach_to_unit = -1;
     pif->is_lcp_up = 0;
    pif->auth_ok = 0;*/
    if(remark_ipinfo_all[unit].his_ip != 0) {
        struct remark_ipinfo *ipinfo = &remark_ipinfo_all[unit];
    	memset(ipinfo, 0, sizeof(struct remark_ipinfo));
    	remark_all_ipinfo_notify_mcp();
	}
    pppd_interface_neg_variable_init(pif);
    /* XXX if doing_multilink, should do something to stop
       network-layer traffic on the link */
}
//                                                                                                                 |-1.ipcp_lowerdown->ipcp_down
//lcp_close->fsm_close->terminate_layer->(如果这里lcp是协商成功的继续后面)lcp_down->link_down->upper_layers_down->                                      
//                                                                                                                 |-2.ipcp_close->fsm_close->terminate_layer(不在执行ipcp_down，因为前面的ipcp_lowerdown把状态该为closing)
//lcp_finished->link_terminated->fsm_lowerdown->lcp_down

//这个函数只能由multilink方式的主或者非multilink方式调用，因为会清除接口等信息
void upper_layers_down(int unit) //通知ipcp清除ipcp的各种状态机 接口信息等，同时发送ipcp-term-req
{
    int i;
    struct protent *protp;

    for (i = 0; (protp = protocols[i]) != NULL; ++i) { //注意这里是所有的协议都调用了down
	if (!protp->enabled_flag)
	    continue;
        if (protp->protocol != PPP_LCP && protp->lowerdown != NULL) //肯定会执行ipcp_lowerdown和ipcp_close
	        (*protp->lowerdown)(unit);//只有IPCP才执行这个
        if (protp->protocol < 0xC000 && protp->close != NULL)
	        (*protp->close)(unit, "LCP down"); //只有IPCP才执行这个
    }
    SET_IF_NP_OPEN(unit, 0);
	SET_IF_NP_UP(unit, 0);
}

/*
 * The link is established.
 * Proceed to the Dead, Authenticate or Network phase as appropriate.
 */
void
link_established(int unit)
{
    int auth;
    lcp_options *wo = GET_LCP_WANT_OPT(unit);
	lcp_options *go = GET_LCP_GOTO_OPT(unit);
	lcp_options *ho = GET_LCP_HIS_OPT(unit);
	int i;
	struct protent *protp;
	struct ppp_interface *pif = ppp_if[unit];


    pif->is_lcp_up = 1;
    if(PPP_CHECK_FLAG(pppd_debug_if, (1 << unit)))   
        PPPD_DEBUG_NEGTIAT("if %d: link established", unit);
    /*
     * Tell higher-level protocols that LCP is up.
     */
    if (!pif->doing_multilink) {// || !ppp_if_exist_mp_mater(pif->mp_ifindex)) { /* doing_multilink在mp_join_bundle中设置，所以这里的doing_multilink一定为0 */
    	for (i = 0; (protp = protocols[i]) != NULL; ++i)
    	    if (protp->protocol != PPP_LCP && protp->enabled_flag && protp->lowerup != NULL) { //ipcp_lowerup
    		    (*protp->lowerup)(unit); //在upap_lowerup中， u->us_serverstate = UPAPSS_CLOSED;  u->us_clientstate = UPAPCS_CLOSED;
    		 } //这里就是让pap upap状态进入closed状态,ipcp也进入close状态，由后面的continue_networks触发send-ipcp-req
    }

    if ((wo->neg_upap || wo->neg_chap) && !(go->neg_upap || go->neg_chap || go->neg_eap)) {
    	/*
        	 * We wanted the peer to authenticate itself, and it refused:
        	 * if we have some address(es) it can use without auth, fine,
        	 * otherwise treat it as though it authenticated with PAP using
        	 * a username of "" and a password of "".  If that's not OK,
        	 * boot it out.
        	 */
        
    	if (noauth_addrs != NULL) {
    	    set_allowed_addrs(unit, NULL, NULL);
    	} else if (!wo->neg_upap || uselogin || !null_login(unit)) {
    	    warn("peer refused to authenticate: terminating link");
    	    status = EXIT_PEER_AUTH_FAILED;
    	    lcp_close(unit, "peer refused to authenticate");
    	    return;
    	}
    }

    new_phase(unit,PHASE_AUTHENTICATE);
    used_login = 0;
    auth = 0;
    //pap本端需要对端来本端进行认证，也就是对端是客户端，本端是进行验证密码的一端，如果是pap方式，则受到客户端密码后，本端和内存中的用户名密码比较，匹配则认为是认证成功。
    //pap下面这些满足条件说明本端是验证端，需要对方向本端认证
    //chap由服务端发起挑战字开始认证
    if (go->neg_eap) {
    	eap_authpeer(unit, our_name);
    	auth |= EAP_PEER;
    } else if (go->neg_chap) {
    	chap_auth_peer(unit, pif->chap_user, CHAP_DIGEST(go->chap_mdtype));
    	auth |= CHAP_PEER;
    } else if (go->neg_upap) { //本端需要对端来本端进行pap认证，如果超时还没成功，直接认证失败，并lcp_close
    	upap_authpeer(unit);
    	auth |= PAP_PEER;
    }

    //pap对端需要本端向它认证，
    //pap本端是被验证端，需要对端对本端用户名密码进行验证
    if (ho->neg_eap) {
    	eap_authwithpeer(unit, user);
    	auth |= EAP_WITHPEER;
    } else if (ho->neg_chap) { //对端发过来的lcp_req中说明需要进行chap认证，本端需要得到对方认证
    	chap_auth_with_peer(unit, pif->chap_user, CHAP_DIGEST(ho->chap_mdtype)); //客户端
    	auth |= CHAP_WITHPEER;
    } else if (ho->neg_upap) { //对方需要我们进行pap认证
	    upap_authwithpeer(unit, pif->pap_user, pif->pap_passwd); //这里面直接调用upap_sauthreq
	    auth |= PAP_WITHPEER;
    }
    pif->auth_pending = auth; //如果双方都需要验证，则为CHAP_WITHPEER |  CHAP_PEER     pap的同理
	pif->auth_done = 0;

    if (!auth)//如果是不需要认证，则直接进入IPCP中
	    network_phase(unit);
}

/*
 * Proceed to the network phase.
 *///网络层阶段  AUTH认证成功后才走这里面
static void
network_phase(unit)
    int unit;
{
    lcp_options *go = GET_LCP_GOTO_OPT(unit);
    /* Log calling number. */
    if (*remote_number)
	    notice("peer from calling number %q authorized", remote_number);

    /*
     * If the peer had to authenticate, run the auth-up script now.
     */
    if (go->neg_chap || go->neg_upap || go->neg_eap) {
    	notify(auth_up_notifier, 0);
    	auth_state = s_up;
    }

    /*
     * Process extra options from the secrets file
     */
    if (extra_options) {
    	options_from_list(extra_options, 1);
    	free_wordlist(extra_options);
    	extra_options = 0;
    }
    start_networks(unit);
}

void
start_networks(unit)
    int unit;
{
    int i;
    struct protent *protp;
    int ecp_required, mppe_required;
    struct ppp_interface *pif = ppp_if[unit];
    struct ppp_interface *tmp_if;

    new_phase(unit,PHASE_NETWORK);

    pif->auth_ok = 1;

  /*  tmp_if = ppp_if_exist_mp_mater(pif->mp_ifindex);
    PPPD_DEBUG_NEGTIAT("start networks, tmp_if:%s", tmp_if == NULL?"YES":"NO");
    if (pif->multilink_flags && tmp_if != NULL) {
        if(tmp_if->is_ipcp_up == 1)
            mp_join_bundle(unit, 1);  如果是master执行该函数返回0，如果是slave执行该函数attach到主返回1 
        return;  multilink方式如果已经有mster存在，直接退出 
    }*/

    if (pif->multilink_flags) {  
    	if (mp_join_bundle(unit, 0)) { /* 如果是master执行该函数返回0，如果是slave执行该函数attach到主返回1 */
    	    return;
    	}
    }

    //只有master会继续往下执行ipcp_open协商
#ifdef PPP_FILTER
    if (!demand)
	    set_filters(&pass_filter, &active_filter);
#endif
    /* Start CCP and ECP */
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
    	if ((protp->protocol == PPP_ECP || protp->protocol == PPP_CCP)
    	    && protp->enabled_flag && protp->open != NULL) {
    	    (*protp->open)(unit);
    }
    /*
     * Bring up other network protocols iff encryption is not required.
     */
    ecp_required = ecp_gotoptions[unit].required;
    mppe_required = ccp_gotoptions[unit].mppe;
    if (!ecp_required && !mppe_required)
	    continue_networks(unit);
}

void
continue_networks(unit)
    int unit;
{
    int i;
    struct protent *protp;

    /*
     * Start the "real" network protocols.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
    	if (protp->protocol < 0xC000   /* 小于这个值则只能为IPCP */
    	    && protp->protocol != PPP_CCP && protp->protocol != PPP_ECP
    	    && protp->enabled_flag && protp->open != NULL) {
    	    (*protp->open)(unit); //这里只会调用ipcp_open
    	    ++(GET_IF_NP_OPEN(unit));
    	}

    if (GET_IF_NP_OPEN(unit) == 0)
    	/* nothing to do */
    	lcp_close(unit, "No network protocols running");

    reset_link_stats(unit);
}

/*
 * The peer has failed to authenticate himself using `protocol'.
 */
void
auth_peer_fail(unit, protocol)
    int unit, protocol;
{
    /*
     * Authentication failure: take the link down
     */
    status = EXIT_PEER_AUTH_FAILED;
    lcp_close(unit, "Authentication failed");
}

/*
 * The peer has been successfully authenticated using `protocol'.
 *///这里面会设置环境变量PEERNAME为name //auth_withpeer_success这个是对方认证本端，auth_peer_success为本端认证对端
void
auth_peer_success(unit, protocol, prot_flavor, name, namelen)
    int unit, protocol, prot_flavor;
    char *name;
    int namelen;
{
    int bit;
    struct ppp_interface *pif = ppp_if[unit];
    
    switch (protocol) {
    case PPP_CHAP:
    	bit = CHAP_PEER;
    	switch (prot_flavor) {
        	case CHAP_MD5:
        	    bit |= CHAP_MD5_PEER;
        	    break;
        #ifdef CHAPMS
        	case CHAP_MICROSOFT:
        	    bit |= CHAP_MS_PEER;
        	    break;
        	case CHAP_MICROSOFT_V2:
        	    bit |= CHAP_MS2_PEER;
        	    break;
        #endif
    	}
    	break;
    	
    case PPP_PAP:
    	bit = PAP_PEER;
    	break;
    	
    case PPP_EAP:
    	bit = EAP_PEER;
    	break;
    default:
    	warn("auth_peer_success: unknown protocol %x", protocol);
    	return;
    	
    }

    /*
     * Save the authenticated name of the peer for later.
     */
    if (namelen > sizeof(pif->peer_authname) - 1)
	    namelen = sizeof(pif->peer_authname) - 1;
	    
    BCOPY(name, pif->peer_authname, namelen);
    pif->peer_authname[namelen] = 0;

    /* Save the authentication method for later. */
    pif->auth_done |= bit;

    /*
     * If there is no more authentication still to be done,
     * proceed to the network (or callback) phase.
     */
    if ((pif->auth_pending &= ~bit) == 0)
        network_phase(unit);
}

/*
 * We have failed to authenticate ourselves to the peer using `protocol'.
 */
void
auth_withpeer_fail(unit, protocol)
    int unit, protocol;
{
    struct ppp_interface *pif = ppp_if[unit];

    dbglog("%s: authentication failed\n", pif->our_name);
    
    /*
     * We've failed to authenticate ourselves to our peer.
     * Some servers keep sending CHAP challenges, but there
     * is no point in persisting without any way to get updated
     * authentication secrets.
     */
    status = EXIT_AUTH_TOPEER_FAILED;
    lcp_close(unit, "Failed to authenticate ourselves to peer");
}

/*
 * We have successfully authenticated ourselves with the peer using `protocol'.
 *///auth_withpeer_success这个是对方认证本端，auth_peer_success为本端认证对端
void
auth_withpeer_success(unit, protocol, prot_flavor)
    int unit, protocol, prot_flavor;
{
    int bit;
    struct ppp_interface *pif = ppp_if[unit];
    const char *prot = "";

    switch (protocol) {
    case PPP_CHAP:
	bit = CHAP_WITHPEER;
	prot = "CHAP";
	switch (prot_flavor) {
	case CHAP_MD5:
	    bit |= CHAP_MD5_WITHPEER;
	    break;
#ifdef CHAPMS
	case CHAP_MICROSOFT:
	    bit |= CHAP_MS_WITHPEER;
	    break;
	case CHAP_MICROSOFT_V2:
	    bit |= CHAP_MS2_WITHPEER;
	    break;
#endif
	}
	break;
    case PPP_PAP:
	if (passwd_from_file)
	    BZERO(passwd, MAXSECRETLEN);
	bit = PAP_WITHPEER;
	prot = "PAP";
	break;
    case PPP_EAP:
	bit = EAP_WITHPEER;
	prot = "EAP";
	break;
    default:
	warn("auth_withpeer_success: unknown protocol %x", protocol);
	bit = 0;
    }

    notice("%s authentication succeeded", prot);

    /* Save the authentication method for later. */
    pif->auth_done |= bit;

    /*
     * If there is no more authentication still being done,
     * proceed to the network (or callback) phase.
     */
    if ((pif->auth_pending &= ~bit) == 0)
	    network_phase(unit);
}


/*
 * np_up - a network protocol has come up.
 */
void
np_up(unit, proto)
    int unit, proto;
{
    int tlim;

    if (GET_IF_NP_UP(unit) == 0) {
    	/*
        	 * At this point we consider that the link has come up successfully.
        	 */
    	status = EXIT_OK;
    	unsuccess = 0;
    	new_phase(unit,PHASE_RUNNING);

    	if (idle_time_hook != 0)
    	    tlim = (*idle_time_hook)(NULL);
    	else
    	    tlim = idle_time_limit;
    	if (tlim > 0)
    	    TIMEOUT(check_idle, NULL, tlim);

    	 /*
        	 * Set a timeout to close the connection once the maximum
        	 * connect time has expired.
        	 */
    	if (maxconnect > 0)
    	    TIMEOUT(connect_time_expired, 0, maxconnect);

    	/*
    	 * Detach now, if the updetach option was given.
    	 */
    	if (updetach && !nodetach)
    	    detach();
    }
    ++(GET_IF_NP_UP(unit));
}

/*
 * np_down - a network protocol has gone down.
 */
void
np_down(unit, proto)
    int unit, proto;
{
    if (--(GET_IF_NP_UP(unit)) == 0) {
	UNTIMEOUT(check_idle, NULL);
	UNTIMEOUT(connect_time_expired, NULL);

	new_phase(unit,PHASE_NETWORK);
    }
}

/*
 * np_finished - a network protocol has finished using the link.
 */
void
np_finished(unit, proto)
    int unit, proto;
{
    if (--(GET_IF_NP_OPEN(unit)) <= 0) {
	/* no further use for the link: shut up shop. */
	    lcp_close(unit, "No network protocols running");
    }
}
#if 0
#ifdef MAXOCTETS
static void
check_maxoctets(arg)
    void *arg;
{
    int diff;
    unsigned int used;

    update_link_stats(ifunit);
    link_stats_valid=0;
    
    switch(maxoctets_dir) {
	case PPP_OCTETS_DIRECTION_IN:
	    used = link_stats.bytes_in;
	    break;
	case PPP_OCTETS_DIRECTION_OUT:
	    used = link_stats.bytes_out;
	    break;
	case PPP_OCTETS_DIRECTION_MAXOVERAL:
	case PPP_OCTETS_DIRECTION_MAXSESSION:
	    used = (link_stats.bytes_in > link_stats.bytes_out) ? link_stats.bytes_in : link_stats.bytes_out;
	    break;
	default:
	    used = link_stats.bytes_in+link_stats.bytes_out;
	    break;
    }
    diff = maxoctets - used;
    if(diff < 0) {
	notice("Traffic limit reached. Limit: %u Used: %u", maxoctets, used);
	status = EXIT_TRAFFIC_LIMIT;
	lcp_close(0, "Traffic limit");
	need_holdoff = 0;
    } else {
        ;//TIMEOUT(check_maxoctets, NULL, maxoctets_timeout);
    }
}
#endif
#endif
/*
 * check_idle - check whether the link has been idle for long
 * enough that we can shut it down.
 */
static void
check_idle(int unit, void *arg)
{
    struct ppp_idle idle;
    time_t itime;
    int tlim;

    if (!get_idle_time(unit, &idle))
	return;
    if (idle_time_hook != 0) {
	tlim = idle_time_hook(&idle);
    } else {
	itime = MIN(idle.xmit_idle, idle.recv_idle);
	tlim = idle_time_limit - itime;
    }
    if (tlim <= 0) {
    	/* link is idle: shut it down. */
    	notice("Terminating connection due to lack of activity.");
    	status = EXIT_IDLE_TIMEOUT;
    	lcp_close(unit, "Link inactive");
    	need_holdoff = 0;
    } else {
	    TIMEOUT(check_idle, NULL, tlim);
    }
}

/*
 * connect_time_expired - log a message and close the connection.
 */
static void
connect_time_expired(int unit, void* arg)
{
    info("Connect time expired");
    status = EXIT_CONNECT_TIME;
    lcp_close(unit, "Connect time expired");	/* Close connection */
}

/*
 * auth_check_options - called to check authentication options.
 */
void
auth_check_options()
{
    lcp_options *wo = &lcp_wantoptions[0];
    int can_auth;
    int lacks_ip;

    /* Default our_name to hostname, and user to our_name */
    if (our_name[0] == 0 || usehostname)
	    strlcpy(our_name, hostname, sizeof(our_name));
    if (user[0] == 0)
	    strlcpy(user, our_name, sizeof(user));

    /*
     * If we have a default route, require the peer to authenticate
     * unless the noauth option was given or the real user is root.
     */
    
    if (!auth_required && !allow_any_ip && have_route_to(0) && !privileged) {
    	auth_required = 1;
    	default_auth = 1;
    }

    /* If we selected any CHAP flavors, we should probably negotiate it. :-) */
    if (wo->chap_mdtype)
	    wo->neg_chap = 1;

    /* If authentication is required, ask peer for CHAP, PAP, or EAP. */
    if (auth_required) {
	    allow_any_ip = 0;
	    
    	if (!wo->neg_chap && !wo->neg_upap && !wo->neg_eap) {
    	    wo->neg_chap = chap_mdtype_all != MDTYPE_NONE;
    	    wo->chap_mdtype = chap_mdtype_all;
    	    wo->neg_upap = 1;
    	    wo->neg_eap = 1;
    	}
    } else {
    	wo->neg_chap = 0;
    	wo->chap_mdtype = MDTYPE_NONE;
    	wo->neg_upap = 0;
    	wo->neg_eap = 0;
    }

    /*
     * Check whether we have appropriate secrets to use
     * to authenticate the peer.  Note that EAP can authenticate by way
     * of a CHAP-like exchanges as well as SRP.
     */
    lacks_ip = 0;
    can_auth = wo->neg_upap && (uselogin || have_pap_secret(&lacks_ip));

    if (!can_auth && (wo->neg_chap || wo->neg_eap)) {
    	can_auth = have_chap_secret((explicit_remote? remote_name: NULL),
    				    our_name, 1, &lacks_ip);
    }
    if (!can_auth && wo->neg_eap) {
    	can_auth = have_srp_secret((explicit_remote? remote_name: NULL),
    				    our_name, 1, &lacks_ip);
    }

    if (auth_required && !can_auth && noauth_addrs == NULL) {
    	if (default_auth) {
        	    option_error("By default the remote system is required to authenticate itself");
        	    option_error("(because this system has a default route to the internet)");
    	} else if (explicit_remote)
    	    option_error( "The remote system (%s) is required to authenticate itself",remote_name);
    	else
    	    option_error("The remote system is required to authenticate itself");
    	    option_error("but I couldn't find any suitable secret (password) for it to use to do so.");

    	if (lacks_ip)
    	    option_error("(None of the available passwords would let it use an IP address.)");

    	exit(1);
    }

    /*
     * Early check for remote number authorization.
     */
    if (!auth_number()) {
    	warn("calling number %q is not authorized", remote_number);
    	exit(EXIT_CNID_AUTH_FAILED);
    }
}

/*
 * auth_reset - called when LCP is starting negotiations to recheck
 * authentication options, i.e. whether we have appropriate secrets
 * to use for authenticating ourselves and/or the peer.
 *///获取AUTH相关信息
void
auth_reset(unit)
    int unit;
{
    lcp_options *ao = GET_LCP_ALLOW_OPT(unit);
	struct ppp_interface *pif = ppp_if[unit];

	//ao->neg_upap = (pif->pap_passwd[0] != 0 && pif->pap_user[0] != 0); 这个应该要去掉，例如对端需要本端进行认证，二本端不需要对方认证，也就是单向认证的情况
}

/*
 * check_passwd - Check the user name and passwd against the PAP secrets
 * file.  If requested, also check against the system password database,
 * and login the user if OK.
 *
 * returns:
 *	UPAP_AUTHNAK: Authentication failed.
 *	UPAP_AUTHACK: Authentication succeeded.
 * In either case, msg points to an appropriate message.
 */
int
check_passwd(unit, auser, userlen, apasswd, passwdlen, msg)
    int unit;
    char *auser;
    int userlen;
    char *apasswd;
    int passwdlen;
    char **msg;
{
    int ret;
    char *filename;
    //FILE *f;
    struct wordlist *addrs = NULL, *opts = NULL;
    char passwd[256], user[256];
    char secret[MAXWORDLEN];
    //static int attempts = 0;

    /*
     * Make copies of apasswd and auser, then null-terminate them.
     * If there are unprintable characters in the password, make
     * them visible.
     */
    slprintf(passwd, sizeof(passwd), "%.*v", passwdlen, apasswd);
    slprintf(user, sizeof(user), "%.*v", userlen, auser);
    *msg = "";

    /*
     * Check if a plugin wants to handle this.
     */
    if (pap_auth_hook) {
    	ret = (*pap_auth_hook)(user, passwd, msg, &addrs, &opts);
    	if (ret >= 0) {
    	    /* note: set_allowed_addrs() saves opts (but not addrs):
    	       don't free it! */
    	    if (ret)
    		set_allowed_addrs(unit, addrs, opts);
    	    else if (opts != 0)
    		free_wordlist(opts);
    	    if (addrs != 0)
    		free_wordlist(addrs);
    	    BZERO(passwd, sizeof(passwd));
    	    return ret? UPAP_AUTHACK: UPAP_AUTHNAK;
    	}
    }

    /*
     * Open the file of pap secrets and scan for a suitable secret
     * for authenticating this user.
     */
    filename = _PATH_UPAPFILE;
    addrs = opts = NULL;
    ret = UPAP_AUTHACK;

    if(PPP_CHECK_FLAG(pppd_debug_if, (1 << unit)))   
        PPPD_DEBUG_NEGTIAT("recv remote user:%s, pwd:%s", user, passwd);
    if(ppp_remark_check_remote_userinfo(user, passwd) == 0)
        *msg = "AUTH successfully";
    else
        ret = UPAP_AUTHNAK;
        
    if (ret == UPAP_AUTHNAK) {
        if (**msg == 0)
	        *msg = "Login incorrect";
    	/*
        	 * XXX can we ever get here more than once??
        	 * Frustrate passwd stealer programs.
        	 * Allow 10 tries, but start backing off after 3 (stolen from login).
        	 * On 10'th, drop the connection.
        	 */
    	if (opts != NULL)
    	    free_wordlist(opts);

    } else {
    	if (**msg == 0)
    	    *msg = "Login ok";
    	set_allowed_addrs(unit, addrs, opts);
    }

    if (addrs != NULL)
	    free_wordlist(addrs);
	    
    BZERO(passwd, sizeof(passwd));
    BZERO(secret, sizeof(secret));

    return ret;
}

/*
 * This function is needed for PAM.
 */

#ifdef USE_PAM
/* Static variables used to communicate between the conversation function
 * and the server_login function 
 */
static char *PAM_username;
static char *PAM_password;
static int PAM_error = 0;
static pam_handle_t *pamh = NULL;

/* PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */

static int PAM_conv (int num_msg,
#ifndef SOL2
    const
#endif
    struct pam_message **msg,
    struct pam_response **resp, void *appdata_ptr)
{
    int replies = 0;
    struct pam_response *reply = NULL;

#define COPY_STRING(s) (s) ? strdup(s) : NULL

    reply = malloc(sizeof(struct pam_response) * num_msg);
    if (!reply) return PAM_CONV_ERR;

    for (replies = 0; replies < num_msg; replies++) {
        switch (msg[replies]->msg_style) {
            case PAM_PROMPT_ECHO_ON:
                reply[replies].resp_retcode = PAM_SUCCESS;
                reply[replies].resp = COPY_STRING(PAM_username);
                /* PAM frees resp */
                break;
            case PAM_PROMPT_ECHO_OFF:
                reply[replies].resp_retcode = PAM_SUCCESS;
                reply[replies].resp = COPY_STRING(PAM_password);
                /* PAM frees resp */
                break;
            case PAM_TEXT_INFO:
                /* fall through */
            case PAM_ERROR_MSG:
                /* ignore it, but pam still wants a NULL response... */
                reply[replies].resp_retcode = PAM_SUCCESS;
                reply[replies].resp = NULL;
                break;
            default:       
                /* Must be an error of some sort... */
                free (reply);
                PAM_error = 1;
                return PAM_CONV_ERR;
        }
    }
    *resp = reply;     
    return PAM_SUCCESS;
}

static struct pam_conv PAM_conversation = {
    &PAM_conv,
    NULL
};
#endif  /* USE_PAM */

/*
 * plogin - Check the user name and password against the system
 * password database, and login the user if OK.
 *
 * returns:
 *	UPAP_AUTHNAK: Login failed.
 *	UPAP_AUTHACK: Login succeeded.
 * In either case, msg points to an appropriate message.
 */

//在/etc/passwd文件中检查用户名和密码
#if 0
static int
plogin(user, passwd, msg)
    char *user;
    char *passwd;
    char **msg;
{
    char *tty;

#ifdef USE_PAM
    int pam_error;

    pam_error = pam_start ("ppp", user, &PAM_conversation, &pamh);
    if (pam_error != PAM_SUCCESS) {
        *msg = (char *) pam_strerror (pamh, pam_error);
	reopen_log();
	return UPAP_AUTHNAK;
    }
    /*
     * Define the fields for the credential validation
     */
     
    PAM_username = user;
    PAM_password = passwd;
    PAM_error = 0;
    pam_set_item (pamh, PAM_TTY, devnam); /* this might be useful to some modules */

    /*
     * Validate the user
     */
    pam_error = pam_authenticate (pamh, PAM_SILENT);
    if (pam_error == PAM_SUCCESS && !PAM_error) {    
        pam_error = pam_acct_mgmt (pamh, PAM_SILENT);
        if (pam_error == PAM_SUCCESS)
	    pam_error = pam_open_session (pamh, PAM_SILENT);
    }

    *msg = (char *) pam_strerror (pamh, pam_error);

    /*
     * Clean up the mess
     */
    reopen_log();	/* apparently the PAM stuff does closelog() */
    PAM_username = NULL;
    PAM_password = NULL;
    if (pam_error != PAM_SUCCESS)
        return UPAP_AUTHNAK;
#else /* #ifdef USE_PAM */

/*
 * Use the non-PAM methods directly
 */

#ifdef HAS_SHADOW
    struct spwd *spwd;
    struct spwd *getspnam();
#endif
    struct passwd *pw = getpwnam(user);

    endpwent();
    if (pw == NULL)
	return (UPAP_AUTHNAK);

#ifdef HAS_SHADOW
    spwd = getspnam(user);
    endspent();
    if (spwd) {
	/* check the age of the password entry */
	long now = time(NULL) / 86400L;

	if ((spwd->sp_expire > 0 && now >= spwd->sp_expire)
	    || ((spwd->sp_max >= 0 && spwd->sp_max < 10000)
		&& spwd->sp_lstchg >= 0
		&& now >= spwd->sp_lstchg + spwd->sp_max)) {
	    warn("Password for %s has expired", user);
	    return (UPAP_AUTHNAK);
	}
	pw->pw_passwd = spwd->sp_pwdp;
    }
#endif

    /*
     * If no passwd, don't let them login.
     */
    if (pw->pw_passwd == NULL || strlen(pw->pw_passwd) < 2
	|| strcmp(crypt(passwd, pw->pw_passwd), pw->pw_passwd) != 0)
	return (UPAP_AUTHNAK);

#endif /* #ifdef USE_PAM */

    /*
     * Write a wtmp entry for this user.
     */

    tty = devnam;
    if (strncmp(tty, "/dev/", 5) == 0)
	tty += 5;
    logwtmp(tty, user, ifname);		/* Add wtmp login entry */

#if defined(_PATH_LASTLOG) && !defined(USE_PAM)
    if (pw != (struct passwd *)NULL) {
	    struct lastlog ll;
	    int fd;

	    if ((fd = open(_PATH_LASTLOG, O_RDWR, 0)) >= 0) {
		(void)lseek(fd, (off_t)(pw->pw_uid * sizeof(ll)), SEEK_SET);
		memset((void *)&ll, 0, sizeof(ll));
		(void)time(&ll.ll_time);
		(void)strncpy(ll.ll_line, tty, sizeof(ll.ll_line));
		(void)write(fd, (char *)&ll, sizeof(ll));
		(void)close(fd);
	    }
    }
#endif /* _PATH_LASTLOG and not USE_PAM */

    info("user %s logged in", user);
    logged_in = 1;

    return (UPAP_AUTHACK);
}

/*
 * plogout - Logout the user.
 */
static void
plogout()
{
    char *tty;
#ifdef USE_PAM
    int pam_error;

    if (pamh != NULL) {
	pam_error = pam_close_session (pamh, PAM_SILENT);
	pam_end (pamh, pam_error);
	pamh = NULL;
    }
    /* Apparently the pam stuff does closelog(). */
    reopen_log();
#endif /* USE_PAM */

    tty = devnam;
    if (strncmp(tty, "/dev/", 5) == 0)
	tty += 5;
    logwtmp(tty, "", "");		/* Wipe out utmp logout entry */
    logged_in = 0;
}
#endif

/*
 * null_login - Check if a username of "" and a password of "" are
 * acceptable, and iff so, set the list of acceptable IP addresses
 * and return 1.
 */
static int
null_login(unit)
    int unit;
{
    char *filename;
    FILE *f;
    int i, ret;
    struct wordlist *addrs, *opts;
    char secret[MAXWORDLEN];

    /*
     * Check if a plugin wants to handle this.
     */
    ret = -1;
    if (null_auth_hook)
	    ret = (*null_auth_hook)(&addrs, &opts);

    /*
     * Open the file of pap secrets and scan for a suitable secret.
     */
    if (ret <= 0) {
    	filename = _PATH_UPAPFILE;
    	addrs = NULL;
    	f = fopen(filename, "r");
    	if (f == NULL)
    	    return 0;
    	check_access(f, filename);

    	i = scan_authfile(f, "", our_name, secret, &addrs, &opts, filename, 0);
    	ret = i >= 0 && secret[0] == 0;
    	BZERO(secret, sizeof(secret));
    	fclose(f);
    }

    if (ret)
	    set_allowed_addrs(unit, addrs, opts);
    else if (opts != 0)
	    free_wordlist(opts);
    if (addrs != 0)
	    free_wordlist(addrs);

    return ret;
}


/*
 * get_pap_passwd - get a password for authenticating ourselves with
 * our peer using PAP.  Returns 1 on success, 0 if no suitable password
 * could be found. 获取我们自己的迷药，用于向对方发送认证请求
 * Assumes passwd points to MAXSECRETLEN bytes of space (if non-null).
 */ //从文件_PATH_UPAPFILE中获取peer的PAP 用户名 密码 peer ip

 #if 0
static int
get_pap_passwd(passwd)
    char *passwd;
{
    char *filename;
    FILE *f;
    int ret;
    char secret[MAXWORDLEN];

    /*
     * Check whether a plugin wants to supply this.
     */
    if (pap_passwd_hook) {
    	ret = (*pap_passwd_hook)(user, passwd);
    	if (ret >= 0)
    	    return ret;
    }

    filename = _PATH_UPAPFILE;
    f = fopen(filename, "r");
    if (f == NULL)
	    return 0;
	    
    check_access(f, filename);
    ret = scan_authfile(f, user,(remote_name[0]? remote_name: NULL), secret, NULL, NULL, filename, 0);
    fclose(f);
    if (ret < 0)
	    return 0;
    if (passwd != NULL)
	    strlcpy(passwd, secret, MAXSECRETLEN);
    BZERO(secret, sizeof(secret));
    return 1;
}
#endif

/*
 * have_pap_secret - check whether we have a PAP file with any
 * secrets that we could possibly use for authenticating the peer.
 */ //是否有对方的密码，用于对对端进行认证，也就是我们是服务器端
static int
have_pap_secret(lacks_ipp)
    int *lacks_ipp;
{
    FILE *f;
    int ret;
    char *filename;
    struct wordlist *addrs;

    /* let the plugin decide, if there is one */
    if (pap_check_hook) {
    	ret = (*pap_check_hook)();
    	if (ret >= 0)
    	    return ret;
    }

    filename = _PATH_UPAPFILE;
    f = fopen(filename, "r");
    if (f == NULL)
	    return 0;

    ret = scan_authfile(f, (explicit_remote? remote_name: NULL), our_name,
			NULL, &addrs, NULL, filename, 0);
    PPPD_DEBUG_NEGTIAT("remote_name:%s, our_name:%s ret:%u\n", remote_name, our_name, ret);
    fclose(f);
    if (ret >= 0 && !some_ip_ok(addrs)) {
    	if (lacks_ipp != 0)
    	    *lacks_ipp = 1;
    	ret = -1;
    }
    if (addrs != 0)
	    free_wordlist(addrs);

    return ret >= 0;
}

/*
 * have_chap_secret - check whether we have a CHAP file with a
 * secret that we could possibly use for authenticating `client'
 * on `server'.  Either can be the null string, meaning we don't
 * know the identity yet.
 */
static int
have_chap_secret(client, server, need_ip, lacks_ipp)
    char *client;
    char *server;
    int need_ip;
    int *lacks_ipp;
{
    FILE *f;
    int ret;
    char *filename;
    struct wordlist *addrs;

    if (chap_check_hook) {
	ret = (*chap_check_hook)();
	if (ret >= 0) {
	    return ret;
	}
    }

    filename = _PATH_CHAPFILE;
    f = fopen(filename, "r");
    if (f == NULL)
	return 0;

    if (client != NULL && client[0] == 0)
	    client = NULL;
    else if (server != NULL && server[0] == 0)
	    server = NULL;

    ret = scan_authfile(f, client, server, NULL, &addrs, NULL, filename, 0);
    fclose(f);
    if (ret >= 0 && need_ip && !some_ip_ok(addrs)) {
	if (lacks_ipp != 0)
	    *lacks_ipp = 1;
	ret = -1;
    }
    if (addrs != 0)
	free_wordlist(addrs);

    return ret >= 0;
}


/*
 * have_srp_secret - check whether we have a SRP file with a
 * secret that we could possibly use for authenticating `client'
 * on `server'.  Either can be the null string, meaning we don't
 * know the identity yet.
 */
static int
have_srp_secret(client, server, need_ip, lacks_ipp)
    char *client;
    char *server;
    int need_ip;
    int *lacks_ipp;
{
    FILE *f;
    int ret;
    char *filename;
    struct wordlist *addrs;

    filename = _PATH_SRPFILE;
    f = fopen(filename, "r");
    if (f == NULL)
	return 0;

    if (client != NULL && client[0] == 0)
	client = NULL;
    else if (server != NULL && server[0] == 0)
	server = NULL;

    ret = scan_authfile(f, client, server, NULL, &addrs, NULL, filename, 0);
    fclose(f);
    if (ret >= 0 && need_ip && !some_ip_ok(addrs)) {
	if (lacks_ipp != 0)
	    *lacks_ipp = 1;
	ret = -1;
    }
    if (addrs != 0)
	free_wordlist(addrs);

    return ret >= 0;
}


/*
 * get_secret - open the CHAP secret file and return the secret
 * for authenticating the given client on the given server.
 * (We could be either client or server).
 */
int
get_secret(unit, client, server, secret, secret_len, am_server)
    int unit;
    char *client;
    char *server;
    char *secret;
    int *secret_len;
    int am_server;
{
    FILE *f;
    int ret, len;
    char *filename;
    struct wordlist *addrs, *opts;
    char secbuf[MAXWORDLEN];

    if (!am_server && passwd[0] != 0) {
	strlcpy(secbuf, passwd, sizeof(secbuf));
    } else if (!am_server && chap_passwd_hook) {
	if ( (*chap_passwd_hook)(client, secbuf) < 0) {
	    error("Unable to obtain CHAP password for %s on %s from plugin",
		  client, server);
	    return 0;
	}
    } else {
	filename = _PATH_CHAPFILE;
	addrs = NULL;
	secbuf[0] = 0;

	f = fopen(filename, "r");
	if (f == NULL) {
	    error("Can't open chap secret file %s: %m", filename);
	    return 0;
	}
	check_access(f, filename);

	ret = scan_authfile(f, client, server, secbuf, &addrs, &opts, filename, 0);
	fclose(f);
	if (ret < 0)
	    return 0;

	if (am_server)
	    set_allowed_addrs(unit, addrs, opts);
	else if (opts != 0)
	    free_wordlist(opts);
	if (addrs != 0)
	    free_wordlist(addrs);
    }

    len = strlen(secbuf);
    if (len > MAXSECRETLEN) {
	error("Secret for %s on %s is too long", client, server);
	len = MAXSECRETLEN;
    }
    BCOPY(secbuf, secret, len);
    BZERO(secbuf, sizeof(secbuf));
    *secret_len = len;

    return 1;
}


/*
 * get_srp_secret - open the SRP secret file and return the secret
 * for authenticating the given client on the given server.
 * (We could be either client or server).
 */
int
get_srp_secret(unit, client, server, secret, am_server)
    int unit;
    char *client;
    char *server;
    char *secret;
    int am_server;
{
    FILE *fp;
    int ret;
    char *filename;
    struct wordlist *addrs, *opts;

    if (!am_server && passwd[0] != '\0') {
	strlcpy(secret, passwd, MAXWORDLEN);
    } else {
	filename = _PATH_SRPFILE;
	addrs = NULL;

	fp = fopen(filename, "r");
	if (fp == NULL) {
	    error("Can't open srp secret file %s: %m", filename);
	    return 0;
	}
	check_access(fp, filename);

	secret[0] = '\0';
	ret = scan_authfile(fp, client, server, secret, &addrs, &opts,
	    filename, am_server);
	fclose(fp);
	if (ret < 0)
	    return 0;

	if (am_server)
	    set_allowed_addrs(unit, addrs, opts);
	else if (opts != NULL)
	    free_wordlist(opts);
	if (addrs != NULL)
	    free_wordlist(addrs);
    }

    return 1;
}

/*
 * set_allowed_addrs() - set the list of allowed addresses.
 * Also looks for `--' indicating options to apply for this peer
 * and leaves the following words in extra_options.
 */
static void
set_allowed_addrs(unit, addrs, opts)
    int unit;
    struct wordlist *addrs;
    struct wordlist *opts;
{
    int n;
    struct wordlist *ap, **plink;
    struct permitted_ip *ip;
    char *ptr_word, *ptr_mask;
    struct hostent *hp;
    struct netent *np;
    u_int32_t a, mask, ah, offset;
    struct ipcp_options *wo = GET_IPCP_WANT_OPT(unit);
    u_int32_t suggested_ip = 0;

    if (addresses[unit] != NULL)
	    free(addresses[unit]);
    addresses[unit] = NULL;
    if (extra_options != NULL)
	    free_wordlist(extra_options);
    extra_options = opts;

    /*
     * Count the number of IP addresses given.
     */
    n = wordlist_count(addrs) + wordlist_count(noauth_addrs);
    if (n == 0)
	return;
    ip = (struct permitted_ip *) malloc((n + 1) * sizeof(struct permitted_ip));
    if (ip == 0)
	return;

    /* temporarily append the noauth_addrs list to addrs */
    for (plink = &addrs; *plink != NULL; plink = &(*plink)->next)
	;
    *plink = noauth_addrs;

    n = 0;
    for (ap = addrs; ap != NULL; ap = ap->next) {
	/* "-" means no addresses authorized, "*" means any address allowed */
	ptr_word = ap->word;
	if (strcmp(ptr_word, "-") == 0)
	    break;
	if (strcmp(ptr_word, "*") == 0) {
	    ip[n].permit = 1;
	    ip[n].base = ip[n].mask = 0;
	    ++n;
	    break;
	}

	ip[n].permit = 1;
	if (*ptr_word == '!') {
	    ip[n].permit = 0;
	    ++ptr_word;
	}

	mask = ~ (u_int32_t) 0;
	offset = 0;
	ptr_mask = strchr (ptr_word, '/');
	if (ptr_mask != NULL) {
	    int bit_count;
	    char *endp;

	    bit_count = (int) strtol (ptr_mask+1, &endp, 10);
	    if (bit_count <= 0 || bit_count > 32) {
		warn("invalid address length %v in auth. address list",
		     ptr_mask+1);
		continue;
	    }
	    bit_count = 32 - bit_count;	/* # bits in host part */
	    if (*endp == '+') {
		offset = ifunit + 1;
		++endp;
	    }
	    if (*endp != 0) {
		warn("invalid address length syntax: %v", ptr_mask+1);
		continue;
	    }
	    *ptr_mask = '\0';
	    mask <<= bit_count;
	}

	hp = gethostbyname(ptr_word);
	if (hp != NULL && hp->h_addrtype == AF_INET) {
	    a = *(u_int32_t *)hp->h_addr;
	} else {
	    np = getnetbyname (ptr_word);
	    if (np != NULL && np->n_addrtype == AF_INET) {
		a = htonl ((u_int32_t)np->n_net);
		if (ptr_mask == NULL) {
		    /* calculate appropriate mask for net */
		    ah = ntohl(a);
		    if (IN_CLASSA(ah))
			mask = IN_CLASSA_NET;
		    else if (IN_CLASSB(ah))
			mask = IN_CLASSB_NET;
		    else if (IN_CLASSC(ah))
			mask = IN_CLASSC_NET;
		}
	    } else {
		a = inet_addr (ptr_word);
	    }
	}

	if (ptr_mask != NULL)
	    *ptr_mask = '/';

	if (a == (u_int32_t)-1L) {
	    warn("unknown host %s in auth. address list", ap->word);
	    continue;
	}
	if (offset != 0) {
	    if (offset >= ~mask) {
		warn("interface unit %d too large for subnet %v",
		     ifunit, ptr_word);
		continue;
	    }
	    a = htonl((ntohl(a) & mask) + offset);
	    mask = ~(u_int32_t)0;
	}
	ip[n].mask = htonl(mask);
	ip[n].base = a & ip[n].mask;
	++n;
	if (~mask == 0 && suggested_ip == 0)
	    suggested_ip = a;
    }
    *plink = NULL;

    ip[n].permit = 0;		/* make the last entry forbid all addresses */
    ip[n].base = 0;		/* to terminate the list */
    ip[n].mask = 0;

    addresses[unit] = ip;

    /*
     * If the address given for the peer isn't authorized, or if
     * the user hasn't given one, AND there is an authorized address
     * which is a single host, then use that if we find one.
     */
    if (suggested_ip != 0
	&& (wo->hisaddr == 0 || !auth_ip_addr(unit, wo->hisaddr))) {
	wo->hisaddr = suggested_ip;
	/*
	 * Do we insist on this address?  No, if there are other
	 * addresses authorized than the suggested one.
	 */
	if (n > 1)
	    wo->accept_remote = 1;
    }
}

/*
 * auth_ip_addr - check whether the peer is authorized to use
 * a given IP address.  Returns 1 if authorized, 0 otherwise.
 */
int
auth_ip_addr(unit, addr)
    int unit;
    u_int32_t addr;
{
    int ok;

    /* don't allow loopback or multicast address */
    if (bad_ip_adrs(addr))
	    return 0;

    if (allowed_address_hook) {
    	ok = allowed_address_hook(addr);
    	if (ok >= 0) return ok;
    }

    if (addresses[unit] != NULL) {
    	ok = ip_addr_check(addr, addresses[unit]);
    	if (ok >= 0)
    	    return ok;
    }

    if (auth_required)
	    return 0;		/* no addresses authorized */
    return allow_any_ip || privileged || !have_route_to(addr);
}

static int
ip_addr_check(addr, addrs)
    u_int32_t addr;
    struct permitted_ip *addrs;
{
    for (; ; ++addrs)
    	if ((addr & addrs->mask) == addrs->base)
    	    return addrs->permit;
}

/*
 * bad_ip_adrs - return 1 if the IP address is one we don't want
 * to use, such as an address in the loopback net or a multicast address.
 * addr is in network byte order.
 */
int
bad_ip_adrs(addr)
    u_int32_t addr;
{
    addr = ntohl(addr);
    return (addr >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET
	|| IN_MULTICAST(addr) || IN_BADCLASS(addr);
}

/*
 * some_ip_ok - check a wordlist to see if it authorizes any
 * IP address(es).
 */
static int
some_ip_ok(addrs)
    struct wordlist *addrs;
{
    for (; addrs != 0; addrs = addrs->next) {
    	if (addrs->word[0] == '-')
    	    break;
    	if (addrs->word[0] != '!')
    	    return 1;		/* some IP address is allowed */
    }
    return 0;
}

/*
 * auth_number - check whether the remote number is allowed to connect.
 * Returns 1 if authorized, 0 otherwise.
 */
int
auth_number()
{
    struct wordlist *wp = permitted_numbers;
    int l;

    /* Allow all if no authorization list. */
    if (!wp)
	    return 1;

    /* Allow if we have a match in the authorization list. */
    while (wp) {
    	/* trailing '*' wildcard */
    	l = strlen(wp->word);
    	if ((wp->word)[l - 1] == '*')
    	    l--;
    	if (!strncasecmp(wp->word, remote_number, l))
    	    return 1;
    	wp = wp->next;
    }

    return 0;
}

/*
 * check_access - complain if a secret file has too-liberal permissions.
 *//* 检查文件是否可读 */
static void
check_access(f, filename)
    FILE *f;
    char *filename;
{
    struct stat sbuf;

    if (fstat(fileno(f), &sbuf) < 0) {
	    warn("cannot stat secret file %s: %m", filename);
    } else if ((sbuf.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
	    warn("Warning - secret file %s has world and/or group access",
	     filename);
    }
}


/*
 * scan_authfile - Scan an authorization file for a secret suitable
 * for authenticating `client' on `server'.  The return value is -1
 * if no secret is found, otherwise >= 0.  The return value has
 * NONWILD_CLIENT set if the secret didn't have "*" for the client, and
 * NONWILD_SERVER set if the secret didn't have "*" for the server.
 * Any following words on the line up to a "--" (i.e. address authorization
 * info) are placed in a wordlist and returned in *addrs.  Any
 * following words (extra options) are placed in a wordlist and
 * returned in *opts.
 * We assume secret is NULL or points to MAXWORDLEN bytes of space.
 * Flags are non-zero if we need two colons in the secret in order to
 * match.
 */
 //配置文件中的*表示任意都符合，满足前面行后就不再匹配后面行
 //如果client和server都配置了不为*,则必须同时满足才能去密匙和ip
 //如果client和server都为null，则直接去第一行的密码
static int
scan_authfile(f, client, server, secret, addrs, opts, filename, flags)
    FILE *f;
    char *client;
    char *server;
    char *secret;
    struct wordlist **addrs;
    struct wordlist **opts;
    char *filename;
    int flags;
{
    int newline, xxx;
    int got_flag;//用来标示读的是客户端还是服务器端
    int best_flag;
    FILE *sf;
    struct wordlist *ap, *addr_list, *alist, **app;
    char word[MAXWORDLEN];
    char atfile[MAXWORDLEN];
    char lsecret[MAXWORDLEN];
    char *cp;

    if (addrs != NULL)
	    *addrs = NULL;
    if (opts != NULL)
	    *opts = NULL;
    addr_list = NULL;
    if (!getword(f, word, &newline, filename))
	    return -1;		/* file is empty??? */
	    
    newline = 1;
    best_flag = -1;
    
    for (;;) {
    	/*
        	 * Skip until we find a word at the start of a line.
        	 */
    	while (!newline && getword(f, word, &newline, filename))
    	    ;
    	if (!newline)
    	    break;		/* got to end of file */
    	/*
        	 * Got a client - check if it's a match or a wildcard.
        	 */
    	got_flag = 0;
    	if (client != NULL && strcmp(word, client) != 0 && !ISWILD(word)) {
    	    newline = 0;
    	    continue;
    	}
    	if (!ISWILD(word))
    	    got_flag = NONWILD_CLIENT;

    	/*
        	 * Now get a server and check if it matches.
        	 */
    	if (!getword(f, word, &newline, filename))
    	    break;
    	if (newline)
    	    continue;
    	if (!ISWILD(word)) {
    	    if (server != NULL && strcmp(word, server) != 0)//如果想读server并且word与之匹配
    		continue;
    	    got_flag |= NONWILD_SERVER;//标识读的是server
    	}
        
    	/*
        	 * Got some sort of a match - see if it's better than what
        	 * we have already.
        	 */
    	if (got_flag <= best_flag)
    	    continue;

    	/*
        	 * Get the secret.
        	 */
    	if (!getword(f, word, &newline, filename))
    	    break;
  
    	if (newline)
    	    continue;
        
    	/*
        	 * SRP-SHA1 authenticator should never be reading secrets from
        	 * a file.  (Authenticatee may, though.)
        	 */
    	if (flags && ((cp = strchr(word, ':')) == NULL ||
    	    strchr(cp + 1, ':') == NULL))
    	    continue;

    	if (secret != NULL) {
    	    /*
        	     * Special syntax: @/pathname means read secret from file.
        	     */
    	    if (word[0] == '@' && word[1] == '/') {
        		strlcpy(atfile, word+1, sizeof(atfile));
        		if ((sf = fopen(atfile, "r")) == NULL) {
        		    warn("can't open indirect secret file %s", atfile);
        		    continue;
        		}
        		check_access(sf, atfile);
        		if (!getword(sf, word, &xxx, atfile)) {
        		    warn("no secret in indirect secret file %s", atfile);
        		    fclose(sf);
        		    continue;
        		}
        		fclose(sf);
    	    }
    	    strlcpy(lsecret, word, sizeof(lsecret));
    	}

    	/*
        	 * Now read address authorization info and make a wordlist.
        	 */
    	app = &alist;
    	for (;;) {
    	    if (!getword(f, word, &newline, filename) || newline)
    		    break;
    	    ap = (struct wordlist *)malloc(sizeof(struct wordlist) + strlen(word) + 1);
    	    if (ap == NULL)
    		    novm("authorized addresses");
    	    ap->word = (char *) (ap + 1);
    	    strcpy(ap->word, word);
    	    *app = ap;
    	    app = &ap->next;
    	}
    	*app = NULL;

    	/*
        	 * This is the best so far; remember it.
        	 */
    	best_flag = got_flag;
    	if (addr_list)
    	    free_wordlist(addr_list);
    	addr_list = alist;
    	if (secret != NULL)
    	    strlcpy(secret, lsecret, MAXWORDLEN);

    	if (!newline)
    	    break;
    }

    /* scan for a -- word indicating the start of options */
    for (app = &addr_list; (ap = *app) != NULL; app = &ap->next)
	if (strcmp(ap->word, "--") == 0)
	    break;
    /* ap = start of options */
    if (ap != NULL) {
    	ap = ap->next;		/* first option */
    	free(*app);			/* free the "--" word */
    	*app = NULL;		/* terminate addr list */
    }
    if (opts != NULL)
	    *opts = ap;
    else if (ap != NULL)    
	    free_wordlist(ap);
	    
    if (addrs != NULL)
	    *addrs = addr_list;
    else if (addr_list != NULL)
	    free_wordlist(addr_list);

    return best_flag;
}

/*
 * wordlist_count - return the number of items in a wordlist
 */
static int
wordlist_count(wp)
    struct wordlist *wp;
{
    int n;

    for (n = 0; wp != NULL; wp = wp->next)
	    ++n;
    return n;
}

/*
 * free_wordlist - release memory allocated for a wordlist.
 */
static void
free_wordlist(wp)
    struct wordlist *wp;
{
    struct wordlist *next;

    while (wp != NULL) {
    	next = wp->next;
    	free(wp);
    	wp = next;
    }
}

/*
 * auth_script_done - called when the auth-up or auth-down script
 * has finished.
 */
static void
auth_script_done(arg)
    void *arg;
{
    auth_script_pid = 0;
    switch (auth_script_state) {
    case s_up:
	if (auth_state == s_down) {
	    auth_script_state = s_down;
	    auth_script(_PATH_AUTHDOWN);
	}
	break;
    case s_down:
	if (auth_state == s_up) {
	    auth_script_state = s_up;
	    auth_script(_PATH_AUTHUP);
	}
	break;
    }
}

/*
 * auth_script - execute a script with arguments
 * interface-name peer-name real-user tty speed
 */
static void
auth_script(script)
    char *script;
{
    char strspeed[32];
    struct passwd *pw;
    char struid[32];
    char *user_name;
    char *argv[8];

    if ((pw = getpwuid(getuid())) != NULL && pw->pw_name != NULL)
	    user_name = pw->pw_name;
    else {
    	slprintf(struid, sizeof(struid), "%d", getuid());
    	user_name = struid;
    }
    slprintf(strspeed, sizeof(strspeed), "%d", baud_rate);

    argv[0] = script;
    argv[1] = ifname;
    argv[2] = peer_authname;
    argv[3] = user_name;
    argv[4] = devnam;
    argv[5] = strspeed;
    argv[6] = NULL;

    auth_script_pid = run_program(script, argv, 0, auth_script_done, NULL, 0);
}

int ppp_if_enable_auth(int unit, int type)
{
	lcp_options *wo = &(ppp_if[unit]->lcp.lcp_wantoptions);
	
	if (type == PPP_IF_AUTH_PAP) {
		wo->neg_upap = 1;
		wo->neg_chap = 0;
		wo->chap_mdtype = 0;
	} else if (type == PPP_IF_AUTH_CHAP) {
		wo->neg_upap = 0;
		wo->neg_chap = 1;
		wo->chap_mdtype = MDTYPE_MD5;
	} else {
		wo->neg_upap = wo->neg_chap = 0;
		wo->chap_mdtype = 0;
	}
	return 0;
}

