/*
 * ipcp.h - IP Control Protocol definitions.
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
 * $Id: ipcp.h,v 1.14 2002/12/04 23:03:32 paulus Exp $
 */

/*
 * Options.
 */
#ifndef __IPCP_H__
#define __IPCP_H__
#include "fsm.h"

#define CI_ADDRS	1	/* IP Addresses */
#define CI_COMPRESSTYPE	2	/* Compression Type */
#define	CI_ADDR		3

#define CI_MS_DNS1	129	/* Primary DNS value */
#define CI_MS_WINS1	130	/* Primary WINS value */
#define CI_MS_DNS2	131	/* Secondary DNS value */
#define CI_MS_WINS2	132	/* Secondary WINS value */

#define MAX_STATES 16		/* from slcompress.h */

#define IPCP_VJMODE_OLD 1	/* "old" mode (option # = 0x0037) */
#define IPCP_VJMODE_RFC1172 2	/* "old-rfc"mode (option # = 0x002d) */
#define IPCP_VJMODE_RFC1332 3	/* "new-rfc"mode (option # = 0x002d, */
                                /*  maxslot and slot number compression) */

#define IPCP_VJ_COMP 0x002d	/* current value for VJ compression option*/
#define IPCP_VJ_COMP_OLD 0x0037	/* "old" (i.e, broken) value for VJ */
				/* compression option*/ 

typedef struct ipcp_options {
    u8 neg_addr;		/* Negotiate IP Address? */ //ipcp-no-address
    u8 old_addrs;		/* Use old (IP-Addresses) option? */ //禁用用命令ipcp-no-addresses
    u8 req_addr;		/* Ask peer to send IP address? */
    u8 default_route;		/* Assign default route through interface? */
    u8 proxy_arp;		/* Make proxy ARP entry for peer? */
    u8 neg_vj;		/* Van Jacobson Compression?  Van Jacobson TCP/IP头部压缩,是否需要进行TCP头部压缩  如果为1，则通知内核SC_COMP_TCP，为0的话SC_NO_TCP_CCID*/
    u8 old_vj;		/* use old (short) form of VJ option? */
    u8 accept_local;		/* accept peer's value for ouraddr */
    u8 accept_remote;		/* accept peer's value for hisaddr */
    u8 req_dns1;		/* Ask peer to send primary DNS address? */
    u8 req_dns2;		/* Ask peer to send secondary DNS address? */
    int  vj_protocol;		/* protocol value to use in VJ option vj压缩方式，默认为IPCP_VJ_COMP，取值可以是 IPCP_VJ_COMP 或者IPCP_VJ_COMP_OLD   cilen == CILEN_COMPRESS*/
    int  maxslotindex;		/* values for RFC1332 VJ compression neg. =MAX_STATES - 1 */ //见ipcp_init  VJ TCP头部压缩的时候需要该值
    u8 cflag;

    /* 
hisip指的是我们给对方的建议，当对方发送过来的ip为0或者与本地建议的ip不一样的时候，就需要会送nak,hisip一般可以从配置文件pap-secret的ip addrs项或者命令中的  a.b.c.d:1.1.1.1中获取
ouraddr默认use hostname for default IP adrs，可以在命令noipdefault配置不适用hostname做为本地Ip. 见ip_check_options
	 */
    u_int32_t ouraddr, hisaddr;	/* Addresses in NETWORK BYTE ORDER */ //ipcp_wantoptions的该字段是从本机获取的，参考ip_check_options  见setipaddr
                                                                //<local_IP_address>:<remote_IP_address> 中设置
                                                                //hisaddr也可以从配置文件pap-secret中获取，在函数中set_allowed_addrs
    u_int32_t dnsaddr[2];	/* Primary and secondary MS DNS entries */
    u_int32_t winsaddr[2];	/* Primary and secondary MS WINS entries */
} ipcp_options;

struct ipcp_parameter
{
	fsm ipcp_fsm;		/* IPCP fsm structure */

	ipcp_options ipcp_wantoptions;	/* Options that we want to request */
	ipcp_options ipcp_gotoptions;	/* Options that peer ack'd */
	ipcp_options ipcp_allowoptions; /* Options we allow peer to request */
	ipcp_options ipcp_hisoptions;	/* Options that we ack'd */

	u8 ipcp_is_up;			/* have called np_up() */
	u8 ipcp_is_open;		/* haven't called np_finished() */
	u_int32_t assigned_ip;
	char ip_pool[50 + 1];
};

#define GET_IPCP_FSM(UNIT) &((ppp_if[(UNIT)]->ipcp).ipcp_fsm)
#define GET_IPCP_WANT_OPT(UNIT) &((ppp_if[(UNIT)]->ipcp).ipcp_wantoptions)
#define GET_IPCP_GOTO_OPT(UNIT) &((ppp_if[(UNIT)]->ipcp).ipcp_gotoptions)
#define GET_IPCP_ALLOW_OPT(UNIT) &((ppp_if[(UNIT)]->ipcp).ipcp_allowoptions)
#define GET_IPCP_HIS_OPT(UNIT) &((ppp_if[(UNIT)]->ipcp).ipcp_hisoptions)
#define GET_IPCP_UP(UNIT) ((ppp_if[(UNIT)]->ipcp).ipcp_is_up)
#define GET_IPCP_OPEN(UNIT) ((ppp_if[(UNIT)]->ipcp).ipcp_is_open)
#define SET_IPCP_UP(UNIT, VALUE) ((ppp_if[(UNIT)]->ipcp).ipcp_is_up = VALUE)
#define SET_IPCP_OPEN(UNIT, VALUE) ((ppp_if[(UNIT)]->ipcp).ipcp_is_open = VALUE)


extern fsm ipcp_fsm[];
extern ipcp_options ipcp_wantoptions[];
extern ipcp_options ipcp_gotoptions[];
extern ipcp_options ipcp_allowoptions[];
extern ipcp_options ipcp_hisoptions[];

char *ip_ntoa __P((u_int32_t));

extern struct protent ipcp_protent;
void ipcp_open __P((int));

#endif

