/*
 * lcp.h - Link Control Protocol definitions.
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
 * $Id: lcp.h,v 1.20 2004/11/14 22:53:42 carlsonj Exp $
 */

/*
 * Options.
 */

#ifndef __LCP_H__
#define __LCP_H__

#include "fsm.h"
#include "pppd.h"

#define CI_VENDOR	0	/* Vendor Specific */
#define CI_MRU		1	/* Maximum Receive Unit */
#define CI_ASYNCMAP	2	/* Async Control Character Map */
#define CI_AUTHTYPE	3	/* Authentication Type */
#define CI_QUALITY	4	/* Quality Protocol */
#define CI_MAGICNUMBER	5	/* Magic Number */
#define CI_PCOMPRESSION	7	/* Protocol Field Compression */
#define CI_ACCOMPRESSION 8	/* Address/Control Field Compression */
#define CI_FCSALTERN	9	/* FCS-Alternatives */
#define CI_SDP		10	/* Self-Describing-Pad */
#define CI_NUMBERED	11	/* Numbered-Mode */
#define CI_CALLBACK	13	/* callback */
#define CI_MRRU		17	/* max reconstructed receive unit; multilink */
#define CI_SSNHF	18	/* short sequence numbers for multilink */
#define CI_EPDISC	19	/* endpoint discriminator */
#define CI_MPPLUS	22	/* Multi-Link-Plus-Procedure */
#define CI_LDISC	23	/* Link-Discriminator */
#define CI_LCPAUTH	24	/* LCP Authentication */
#define CI_COBS		25	/* Consistent Overhead Byte Stuffing */
#define CI_PREFELIS	26	/* Prefix Elision */
#define CI_MPHDRFMT	27	/* MP Header Format */
#define CI_I18N		28	/* Internationalization */
#define CI_SDL		29	/* Simple Data Link */

/*
 * LCP-specific packet types (code numbers).
 *///code代码域ECHOREQ PROTREJ这几个会走到这里  他们和CONFREQ这里面的几个code代码不一样，单独处理。见fsm_input
#define PROTREJ		8	/* Protocol Reject */
#define ECHOREQ		9	/* Echo Request */
#define ECHOREP		10	/* Echo Reply */
#define DISCREQ		11	/* Discard Request */
#define IDENTIF		12	/* Identification */
#define TIMEREM		13	/* Time Remaining */

/* Value used as data for CI_CALLBACK option */
#define CBCP_OPT	6	/* Use callback control protocol */

/*
 * The state of options is described by an lcp_options structure.
 */ //是否需要协商，参考lcp_init
#define MAX_ENDP_LEN	20	/* maximum length of discriminator value */
struct epdisc {
    unsigned char	class;//"null", "local", "IP", "MAC", "magic", "phone"  分别对应0 1 2 3 4 5 
    unsigned char	length;//为value长度，1.1.1.1暂用四个字节
    unsigned char	value[MAX_ENDP_LEN]; //每个字节存一个数字，如1.1.1.1则前四个字节内容都是1
};
typedef struct lcp_options {
    u8 passive;	//没操作过，一直为0	/* Don't die if we don't get a response */  
    u8 silent;//没操作，一直为0		/* Wait for the other end to start first */
    u8 restart;		/* Restart vs. exit after close */
    u8 neg_mru;		/* Negotiate the MRU? */ //默认应该为1  default-mru或者-mru中设置
    u8 neg_asyncmap;		/* Negotiate the async map? */

    //如果没有设置密码，在auth_reset中会把这个清0
    u8 neg_upap;		/* Ask for UPAP authentication? */ 
    u8 neg_chap;		/* Ask for CHAP authentication? */
    u8 neg_eap;		/* Ask for EAP authentication? */
    u8 neg_magicnumber;	/* Ask for magic number? */ //默认为1

    u8 neg_pcompression;	/* HDLC Protocol Field Compression? */ 

    u8 neg_accompression;	/* HDLC Address/Control Field Compression? */ //地址控制域压缩指示 noaccomp活-ac中配置  默认为1
    u8 neg_lqr;		/* Negotiate use of Link Quality Reports */ //没得陪着，应该没什么用
    u8 neg_cbcp;		/* Negotiate use of CBCP */ //估计没什么用
    u8 neg_mrru;		/* negotiate multilink MRRU */ //配置multlink则默认为1
    u8 neg_ssnhf;		/* negotiate short sequence numbers */ 
    u8 neg_endpoint;		/* negotiate endpoint discriminator(辨别者，鉴别器) */ //multilink相关
    int  mru;			/* Value of MRU */ 
    int	 mrru;			/* Value of MRRU, and multilink enable */
    u_char chap_mdtype;		/* which MD types (hashing algorithm) */ 
    u_int32_t asyncmap;		/* Value of async map */ 
    
    u_int32_t magicnumber; //在lcp_resetci中*go = *wo; 
    int  numloops;		/* Number of loops during magic number neg. */
    u_int32_t lqr_period;	/* Reporting period for LQR 1/100ths second */
    struct epdisc endpoint;	/* endpoint discriminator */
} lcp_options;

struct lcp_parameter {
	fsm lcp_fsm;
	lcp_options lcp_wantoptions;	/* Options that we want to request */
	lcp_options lcp_gotoptions;	/* Options that peer ack'd */
	lcp_options lcp_allowoptions;	/* Options we allow peer to request */
	lcp_options lcp_hisoptions;	/* Options that we ack'd */
	int lcp_echo_unack;	/* Number of unanswered echo-requests */
	int	lcp_echo_max_unack; /* Tolerance to unanswered echo-requests */
	int lcp_echo_number;	/* ID number of next echo frame */
	int lcp_echo_timer_running;  /* set if a timer is running */
	u16 echo_interval;
};

#define GET_LCP_FSM(UNIT) &((ppp_if[(UNIT)]->lcp).lcp_fsm)
#define GET_LCP_FSM_STATE(UNIT) ((ppp_if[(UNIT)]->lcp).lcp_fsm.state)
#define GET_LCP_WANT_OPT(UNIT) &((ppp_if[(UNIT)]->lcp).lcp_wantoptions)
#define GET_LCP_GOTO_OPT(UNIT) &((ppp_if[(UNIT)]->lcp).lcp_gotoptions)
#define GET_LCP_ALLOW_OPT(UNIT) &((ppp_if[(UNIT)]->lcp).lcp_allowoptions)
#define GET_LCP_HIS_OPT(UNIT) &((ppp_if[(UNIT)]->lcp).lcp_hisoptions)

/* 下面这两个结合使用 */
#define GET_LCP_ECHO_PEND(UNIT) ((ppp_if[(UNIT)]->lcp).lcp_echo_unack)
#define GET_LCP_ECHO_MAXPEND(UNIT) ((ppp_if[(UNIT)]->lcp).lcp_echo_max_unack)

#define GET_LCP_ECHO_NUM(UNIT) ((ppp_if[(UNIT)]->lcp).lcp_echo_number)
#define GET_LCP_ECHO_RUN(UNIT) ((ppp_if[(UNIT)]->lcp).lcp_echo_timer_running)
#define GET_LCP_ECHO_INTERVAL(UNIT) ((ppp_if[(UNIT)]->lcp).echo_interval)
#define SET_LCP_ECHO_PEND(UNIT, VALUE) (((ppp_if[(UNIT)]->lcp).lcp_echo_unack) = VALUE)
#define SET_LCP_ECHO_MAXPEND(UNIT, VALUE) (((ppp_if[(UNIT)]->lcp).lcp_echo_max_unack) = VALUE)
#define SET_LCP_ECHO_NUM(UNIT, VALUE) (((ppp_if[(UNIT)]->lcp).lcp_echo_number) = VALUE)
#define SET_LCP_ECHO_RUN(UNIT, VALUE) (((ppp_if[(UNIT)]->lcp).lcp_echo_timer_running) = VALUE)
#define SET_LCP_ECHO_INTERVAL(UNIT, VALUE) (((ppp_if[(UNIT)]->lcp).echo_interval) = VALUE)

#define GET_LCP_FSM_IS_RUNNING(UNIT) (!((GET_LCP_FSM_STATE(UNIT)) == INITIAL \
										|| (GET_LCP_FSM_STATE(UNIT)) == CLOSED \
										|| (GET_LCP_FSM_STATE(UNIT)) == STOPPED))
#define GET_LCP_FSM_IS_OPENED(UNIT) ((GET_LCP_FSM_STATE(UNIT)) == OPENED)	


extern fsm lcp_fsm[];
extern lcp_options lcp_wantoptions[];
extern lcp_options lcp_gotoptions[];
extern lcp_options lcp_allowoptions[];
extern lcp_options lcp_hisoptions[];

#define DEFMRU	1500		/* Try for this */
#define MINMRU	128		/* No MRUs below this */
#define MAXMRU	16384		/* Normally limit MRU to this */

void lcp_open __P((int));
void lcp_close __P((int, char *));
void lcp_lowerup __P((int));
void lcp_lowerdown __P((int));
void lcp_sprotrej __P((int, u_char *, int));	/* send protocol reject */

extern struct protent lcp_protent;

/* Default number of times we receive our magic number from the peer
   before deciding the link is looped-back. */
#define DEFLOOPBACKFAIL	10
void lcp_echo_lowerup (int unit);
void lcp_echo_lowerdown (int unit);

#endif

