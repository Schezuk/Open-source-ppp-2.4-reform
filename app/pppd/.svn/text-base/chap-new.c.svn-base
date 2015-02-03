/*
 * chap-new.c - New CHAP implementation.
 *
 * Copyright (c) 2003 Paul Mackerras. All rights reserved.
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

#define RCSID	"$Id: chap-new.c,v 1.8 2005/07/13 10:41:58 paulus Exp $"

#include <stdlib.h>
#include <string.h>
#include "pppd.h"
#include "chap-new.h"
#include "chap-md5.h"
#include "pppd_debug.h"
#ifdef CHAPMS
#include "chap_ms.h"
#define MDTYPE_ALL (MDTYPE_MICROSOFT_V2 | MDTYPE_MICROSOFT | MDTYPE_MD5)
#else
#define MDTYPE_ALL (MDTYPE_MD5)
#endif

int chap_mdtype_all = MDTYPE_ALL;

/* Hook for a plugin to validate CHAP challenge */
int (*chap_verify_hook)(char *name, char *ourname, int id,
			struct chap_digest_type *digest,
			unsigned char *challenge, unsigned char *response,
			char *message, int message_space) = NULL;

/*
 * Option variables.
 */
int chap_timeout_time = 3;
int chap_max_transmits = 10;
int chap_rechallenge_time = 0;

/*
 * Command-line options.
 */
static option_t chap_option_list[] = {
	{ "chap-restart", o_int, &chap_timeout_time,
	  "Set timeout for CHAP", OPT_PRIO },
	{ "chap-max-challenge", o_int, &chap_max_transmits,
	  "Set max #xmits for challenge", OPT_PRIO },
	{ "chap-interval", o_int, &chap_rechallenge_time,
	  "Set interval for rechallenge", OPT_PRIO },
	{ NULL }
};

/*
 * Internal state.
 */


/*
 * These limits apply to challenge and response packets we send.
 * The +4 is the +1 that we actually need rounded up.
 */


/*
 * Prototypes.
 */
static void chap_init(int unit);
static void chap_lowerup(int unit);
static void chap_lowerdown(int unit);
static void chap_timeout(int unit, void *arg);
static void chap_generate_challenge(struct chap_server_state *ss);
static void chap_handle_response(struct chap_server_state *ss, int code,
		unsigned char *pkt, int len);
static int chap_verify_response(char *name, char *ourname, int id,
		struct chap_digest_type *digest,
		unsigned char *challenge, unsigned char *response,
		char *message, int message_space);
static int
chap_verify_response2(char *name, char *ourname, int id,
		     struct chap_digest_type *digest,
		     unsigned char *challenge, unsigned char *response,
		     char *message, int message_space,  char* secret_2);

static void chap_respond(struct chap_client_state *cs, int id,
		unsigned char *pkt, int len);
static void chap_handle_status(struct chap_client_state *cs, int code, int id,
		unsigned char *pkt, int len);
static void chap_protrej(int unit);
static void chap_input(int unit, unsigned char *pkt, int pktlen);
static int chap_print_pkt(unsigned char *p, int plen,
		void (*printer) __P((void *, char *, ...)), void *arg);

/* List of digest types that we know about */
static struct chap_digest_type *chap_digests; //见md5_digest

/*
 * chap_init - reset to initial state.
 */
static void
chap_init(int unit)
{
	struct ppp_interface *pif = ppp_if[unit];

	memset(&(pif->client), 0, sizeof(struct chap_client_state));
	memset(&(pif->server), 0, sizeof(struct chap_server_state));
	pif->client.unit = unit;
	pif->server.unit = unit;

	chap_md5_init();
#ifdef CHAPMS
	chapms_init();
#endif
}

/*
 * Add a new digest type to the list.
 */ //把dp添加到chap_digests链表头部
void
chap_register_digest(struct chap_digest_type *dp)
{
	dp->next = chap_digests;
	chap_digests = dp;
}

/*
 * chap_lowerup - we can start doing stuff now.
 */ //lcp协商成功后执行link_established会调用该函数
static void
chap_lowerup(int unit)
{
	struct ppp_interface *pif = ppp_if[unit];
	struct chap_client_state *cs = &(pif->client);
	struct chap_server_state *ss = &(pif->server);

	cs->flags |= LOWERUP;
	ss->flags |= LOWERUP;
	if (ss->flags & AUTH_STARTED)
		chap_timeout(unit, ss);
}

static void
chap_lowerdown(int unit)
{
	struct ppp_interface *pif = ppp_if[unit];
	struct chap_client_state *cs = &(pif->client);
	struct chap_server_state *ss = &(pif->server);

	cs->flags = 0;
	if (ss->flags & TIMEOUT_PENDING)
		UNTIMEOUT(chap_timeout, ss);
	ss->flags = 0;
}

/*
 * chap_auth_peer - Start authenticating the peer.
 * If the lower layer is already up, we start sending challenges,
 * otherwise we wait for the lower layer to come up.
 */ //认证端(服务器端发起挑战)
void
chap_auth_peer(int unit, char *our_name, int digest_code)
{
	struct ppp_interface *pif = ppp_if[unit];
	//struct chap_client_state *cs = &(pif->client);
	struct chap_server_state *ss = &(pif->server);
    struct chap_digest_type *dp;
    
	if (ss->flags & AUTH_STARTED) {
		PPPD_DEBUG_NEGTIAT("CHAP: peer authentication already started!");
		return;
	}
	for (dp = chap_digests; dp != NULL; dp = dp->next)
		if (dp->code == digest_code)
			break;
	if (dp == NULL) {
		PPPD_DEBUG_NEGTIAT("fatal error, CHAP digest 0x%x requested but not available",
		      digest_code);
        return;
    }
	ss->digest = dp;
	ss->name = our_name;
	/* Start with a random ID value */
	ss->id = (unsigned char)(drand48() * 256);
	ss->flags |= AUTH_STARTED;
	
	if (ss->flags & LOWERUP) //在link_established -> chap_lowerup设置为LOWERUP,所以这里肯定会执行到，触发发起挑战
		chap_timeout(unit, ss);
}

/*
 * chap_auth_with_peer - Prepare to authenticate ourselves to the peer.
 * There isn't much to do until we receive a challenge.
//sent [LCP ConfReq id=0x1 <asyncmap 0x0> <magic 0x9b9ef255> <pcomp> <accomp>]
//rcvd [LCP ConfRej id=0x1 <asyncmap 0x0>]
//sent [LCP ConfReq id=0x2 <magic 0x9b9ef255> <pcomp> <accomp>]
//rcvd [LCP ConfAck id=0x2 <magic 0x9b9ef255> <pcomp> <accomp>]
//rcvd [LCP ConfReq id=0x14 <mru 1500> <auth chap MD5> <magic 0x56a4d504>]
//yang test ..444. lcp_reqci begin ........multilink:0.............
//lcp_reqci: returning CONFACK.
[1970-01-05 00:57:31:]lcp_reqci: returning CONFACK.
//sent [LCP ConfAck id=0x14 <mru 1500> <auth chap MD5> <magic 0x56a4d504>]
//yang test 22222222222222222222 passwd[0]:49 passwd:123 user:paptest gopap:0, hopap:0.. upap.us_clientstate:1      upap.us_serverstate:1
//rcvd [LCP EchoReq id=0x0 magic=0x56a4d504]
//sent [LCP EchoRep id=0x0 magic=0x9b9ef255]
//rcvd [CHAP Challenge id=0xd7 <90a00d3b0052c92b0deb881936865899690bfc>, name = "x1-10"]
//sent [CHAP Response id=0xd7 <8937d0551c9b22cbad237b0198a1dbf4>, name = "paptest"]
//rcvd [CHAP Success id=0xd7 "Access granted"]
//CHAP authentication succeeded: Access granted
//CHAP authentication succeeded
 */
void
chap_auth_with_peer(int unit, char *our_name, int digest_code)
{
	struct ppp_interface *pif = ppp_if[unit];
	struct chap_client_state *cs = &(pif->client); //cs为client结构
	struct chap_digest_type *dp;

	if (cs->flags & AUTH_STARTED) {
		PPPD_DEBUG_NEGTIAT("CHAP: authentication with peer already started!");
		return;
	}
	for (dp = chap_digests; dp != NULL; dp = dp->next)
		if (dp->code == digest_code)
			break;
	if (dp == NULL) {
		PPPD_DEBUG_NEGTIAT("fatal error, CHAP digest 0x%x requested but not available",
		      digest_code);
        return;
    }
	cs->digest = dp;
	cs->name = our_name;
	cs->flags |= AUTH_STARTED;
}

/*
 * chap_timeout - It's time to send another challenge to the peer.
 * This could be either a retransmission of a previous challenge,
 * or a new challenge to start re-authentication.
 
 询问握手认证协议（CHAP）通过三次握手周期性的校验对端的身份，在初始链路建立时完成，可以在链路建立之后的任何时候重复进行。
 1. 链路建立阶段结束之后，认证者向对端点发送“challenge”消息。
 2. 对端点用经过单向哈希函数计算出来的值做应答。
 3. 认证者根据它自己计算的哈希值来检查应答，如果值匹配，认证得到承认；否则，连接应该终止。
 4. 经过一定的随机间隔，认证者发送一个新的 challenge 给端点，重复步骤 1 到 3 。
 通过递增改变的标识符和可变的询问值，CHAP 防止了来自端点的重放攻击，使用重复校验可以限制暴露于单个攻击的时间。认证者控制验证频度和时间。
 *///认证端(服务器端发起挑战)
static void
chap_timeout(int unit, void *arg) 
{
	struct chap_server_state *ss = arg;

	ss->flags &= ~TIMEOUT_PENDING;
	if ((ss->flags & CHALLENGE_VALID) == 0) {
		ss->challenge_xmits = 0;
		chap_generate_challenge(ss);
		ss->flags |= CHALLENGE_VALID;
	} else if (ss->challenge_xmits >= chap_max_transmits) {
		ss->flags &= ~CHALLENGE_VALID;
		ss->flags |= AUTH_DONE | AUTH_FAILED;
		auth_peer_fail(unit, PPP_CHAP);
		return;
	}

	output(unit, ss->challenge, ss->challenge_pktlen); //挑战字 + 服务端用户名
	++ss->challenge_xmits;
	ss->flags |= TIMEOUT_PENDING;
	TIMEOUT(chap_timeout, arg, chap_timeout_time); //会每隔chap_timeout_time时间进行挑战
}

/*
 * chap_generate_challenge - generate a challenge string and format
 * the challenge packet in ss->challenge_pkt.
 */ //挑战字 + 服务端用户名
static void
chap_generate_challenge(struct chap_server_state *ss)
{
	int clen = 1, nlen, len;
	unsigned char *p;

	p = ss->challenge;
	MAKEHEADER(p, PPP_CHAP);
	p += CHAP_HDRLEN;
	ss->digest->generate_challenge(p); //见md5_digest
	clen = *p;
	nlen = strlen(ss->name);
	memcpy(p + 1 + clen, ss->name, nlen);

	len = CHAP_HDRLEN + 1 + clen + nlen;
	ss->challenge_pktlen = PPP_HDRLEN + len;

	p = ss->challenge + PPP_HDRLEN;
	p[0] = CHAP_CHALLENGE;
	p[1] = ++ss->id;
	p[2] = len >> 8;
	p[3] = len;

	//int i;
	//printf("yang test chap...... name:%s, id:%u, %02x, %02x\n", ss->name, p[1], ss->name[0], ss->name[1]);
	//for(i = 0; i < PPP_HDRLEN + len; i++) {
    //    printf("%02x ", p[i]);
	//}

   // printf("\n");
}

/*
 * chap_handle_response - check the response to our challenge.
 */
static void
chap_handle_response(struct chap_server_state *ss, int id,
		     unsigned char *pkt, int len)
{
	int response_len, ok, mlen;
	unsigned char *response, *p;
	char *name = NULL;	/* initialized to shut gcc up */
	int (*verifier)(char *, char *, int, struct chap_digest_type *,
		unsigned char *, unsigned char *, char *, int);
	char rname[MAXNAMELEN+1];
	struct ppp_interface *pif = ppp_if[ss->unit];
	int ret = 0;

	if ((ss->flags & LOWERUP) == 0)
		return;
	if (id != ss->challenge[PPP_HDRLEN+1] || len < 2)
		return;
	if (ss->flags & CHALLENGE_VALID) {
		response = pkt;
		GETCHAR(response_len, pkt);
		len -= response_len + 1;	/* length of name */
		name = (char *)pkt + response_len;
		if (len < 0)
			return;

		if (ss->flags & TIMEOUT_PENDING) {
			ss->flags &= ~TIMEOUT_PENDING;
			UNTIMEOUT(chap_timeout, ss);
		}

		if (explicit_remote) {
			name = remote_name;
		} else {
			/* Null terminate and clean remote name. */
			memset(rname, 0, sizeof(rname));
			slprintf(rname, sizeof(rname), "%.*v", len, name);
			name = rname;
		}

		if (chap_verify_hook)
			verifier = chap_verify_hook;
		else {
			verifier = chap_verify_response;
            ret = 1;
	    }
	    //printf("yang test chap...... name:%s, ss->name:%s, id:%u\n", name, ss->name, id);
	    //把id  (客户端用户名对应的)secret challege三个内容做MD5运算，与从第二步收到的应答CHAP_RESPONSE中获取到的hash值做比较，相等说明成功
		ok = (*verifier)(name, ss->name, id, ss->digest,
				 ss->challenge + PPP_HDRLEN + CHAP_HDRLEN,
				 response, ss->message, sizeof(ss->message)); //digest参考md5_digest

        /*
        if(strlen(rname) != 0 && ret == 1 && pif->chap_passwd[0] != 0) {
            ok = chap_verify_response2(name, ss->name, id, ss->digest,
				 ss->challenge + PPP_HDRLEN + CHAP_HDRLEN,
				 response, ss->message, sizeof(ss->message), pif->chap_passwd);
		}*/

		if (!ok || !auth_number()) 
		{
			ss->flags |= AUTH_FAILED;
			warn("Peer %q failed CHAP authentication", name);
		}
	} else if ((ss->flags & AUTH_DONE) == 0)
		return;

	/* send the response */
	p = pif->out_buf;
	MAKEHEADER(p, PPP_CHAP);
	mlen = strlen(ss->message);
	len = CHAP_HDRLEN + mlen;
	p[0] = (ss->flags & AUTH_FAILED)? CHAP_FAILURE: CHAP_SUCCESS;
	p[1] = id;
	p[2] = len >> 8;
	p[3] = len;
	if (mlen > 0)
		memcpy(p + CHAP_HDRLEN, ss->message, mlen);
	output(ss->unit, pif->out_buf, PPP_HDRLEN + len);

	if (ss->flags & CHALLENGE_VALID) {
		ss->flags &= ~CHALLENGE_VALID;
		if (ss->flags & AUTH_FAILED) {
			auth_peer_fail(ss->unit, PPP_CHAP);
		} else {
			//if ((ss->flags & AUTH_DONE) == 0) {
			    PPPD_DEBUG_NEGTIAT("unit:%u, server chap auth peer) success", ss->unit);
				auth_peer_success(ss->unit, PPP_CHAP, ss->digest->code, name, strlen(name));
			//}
			if (chap_rechallenge_time) {
				ss->flags |= TIMEOUT_PENDING;
				TIMEOUT(chap_timeout, ss,
					chap_rechallenge_time);
			}
		}
		ss->flags |= AUTH_DONE;
	}
}

/*
 * chap_verify_response - check whether the peer's response matches
 * what we think it should be.  Returns 1 if it does (authentication
 * succeeded), or 0 if it doesn't.
 */ ////digest参考md5_digest
 //这里的name会被验证端(客户端)的用户名
static int
chap_verify_response(char *name, char *ourname, int id,
		     struct chap_digest_type *digest,
		     unsigned char *challenge, unsigned char *response,
		     char *message, int message_space)
{
	int ok;
	unsigned char secret[MAXSECRETLEN];
	int secret_len;

    memset(secret, 0, sizeof(secret));
	/* Get the secret that the peer is supposed to know */
	if(ppp_get_user_passwd(name, (char *)secret, &secret_len) == 0) { //取出被验证端(客户端用户名对应的密码)
		PPPD_DEBUG_NEGTIAT("No CHAP secret found for authenticating %s", name);
		return 0;
	}

	ok = digest->verify_response(id, name, secret, secret_len, challenge,
				     response, message, message_space);
	memset(secret, 0, sizeof(secret));

	return ok;
}

static int
chap_verify_response2(char *name, char *ourname, int id,
		     struct chap_digest_type *digest,
		     unsigned char *challenge, unsigned char *response,
		     char *message, int message_space,  char* secret_2)
{
	int ok;
	unsigned char secret[MAXSECRETLEN];
	int secret_len;

    memset(secret, 0, sizeof(secret));
	/* Get the secret that the peer is supposed to know */
	if(ppp_get_user_passwd(name, (char *)secret, &secret_len) == 0) { //取出被验证端(客户端用户名对应的密码)
		//error("No CHAP secret found for authenticating %q", name);
		memset(secret, 0, sizeof(secret));
		strcpy(secret, (unsigned char*)secret_2);
    	secret_len = strlen((unsigned char*)secret);
		//return 0;
	}

	ok = digest->verify_response(id, name, secret, secret_len, challenge,
				     response, message, message_space);
	memset(secret, 0, sizeof(secret));

	return ok;
}


/*
 * chap_respond - Generate and send a response to a challenge.
 */
static void
chap_respond(struct chap_client_state *cs, int id,
	     unsigned char *pkt, int len)
{
	int clen, nlen;
	int secret_len;
	unsigned char *p;
	struct ppp_interface *pif = ppp_if[cs->unit];
	unsigned char response[RESP_MAX_PKTLEN];
	char rname[MAXNAMELEN+1];
	char secret[MAXSECRETLEN+1];
	int ret = 0;

	if ((cs->flags & (LOWERUP | AUTH_STARTED)) != (LOWERUP | AUTH_STARTED))
		return;		/* not ready */
	if (len < 2 || len < pkt[0] + 1)
		return;		/* too short */
	clen = pkt[0];
	nlen = len - (clen + 1);

	/* Null terminate and clean remote name. */
	slprintf(rname, sizeof(rname), "%.*v", nlen, pkt + clen + 1);

	/* Microsoft doesn't send their name back in the PPP packet */
	if (explicit_remote || (remote_name[0] != 0 && rname[0] == 0))
		strlcpy(rname, remote_name, sizeof(rname));

	/* get secret for authenticating ourselves with the specified host */
	if(ppp_get_user_passwd(rname, secret, &secret_len) == 0) { //从remote_userinfo_list中获取该用户名对应的密码
	//if (!get_secret(0, cs->name, rname, secret, &secret_len, 0)) {
        strcpy(secret, pif->chap_passwd);
    	secret_len = strlen(pif->chap_passwd);
    	
		if(secret_len == 0)	/* assume null secret if can't find one */
		    warn("No CHAP secret found for authenticating us to %q", rname);
	}

    //printf("yang test recv chanege, cs->name:%s, rname:%s, secret:%s\n", cs->name, rname, secret);
	p = response;
	MAKEHEADER(p, PPP_CHAP);
	p += CHAP_HDRLEN;

	cs->digest->make_response(p, id, cs->name, pkt,
				  secret, secret_len, cs->priv);  //把id(报文头中的id序号) secret(从remote_userinfo_list链表中获取到的第一个密码)和从主动发起挑战字 做md5运算并存到response内存空间，并且内存空间的第一个字节存放整个空间md5运算结果长度16
	memset(secret, 0, secret_len);

	clen = *p;
	nlen = strlen(cs->name);
	memcpy(p + clen + 1, cs->name, nlen);

	p = response + PPP_HDRLEN;
	len = CHAP_HDRLEN + clen + 1 + nlen;
	p[0] = CHAP_RESPONSE;
	p[1] = id;
	p[2] = len >> 8;
	p[3] = len;

	output(cs->unit, response, PPP_HDRLEN + len);
}

static void
chap_handle_status(struct chap_client_state *cs, int code, int id,
		   unsigned char *pkt, int len)
{
	const char *msg = NULL;

	if ((cs->flags & (AUTH_DONE|AUTH_STARTED|LOWERUP))
	    != (AUTH_STARTED|LOWERUP))
		return;
	cs->flags |= AUTH_DONE;

	if (code == CHAP_SUCCESS) {
		/* used for MS-CHAP v2 mutual auth, yuck */
		if (cs->digest->check_success != NULL) {
			if (!(*cs->digest->check_success)(pkt, len, cs->priv))
				code = CHAP_FAILURE;
		} else
			msg = "CHAP authentication succeeded";
	} else {
		if (cs->digest->handle_failure != NULL)
			(*cs->digest->handle_failure)(pkt, len);
		else
			msg = "CHAP authentication failed";
	}
	if (msg) {
		if (len > 0)
			info("%s: %.*v", msg, len, pkt);
		else
			info("%s", msg);
	}
	if (code == CHAP_SUCCESS) {
	    dbglog("unit:%u, client chap auth withpeer success", cs->unit);
		auth_withpeer_success(cs->unit, PPP_CHAP, cs->digest->code);
	} 
	else {
		cs->flags |= AUTH_FAILED;
		error("CHAP authentication failed");
		auth_withpeer_fail(cs->unit, PPP_CHAP);
	}
}
/*
第一步:主动发起挑战字的一段发送一个随机数  
第二步://把id(报文头中的id序号) secret(从remote_userinfo_list链表中获取到的第一个密码)和从主动发起挑战字 做md5运算并存到response
内存空间，并且内存空间的第一个字节存放整个空间md5运算结果长度16，然后发给主动挑战的一端
第三步:
*/
static void
chap_input(int unit, unsigned char *pkt, int pktlen)
{
	struct ppp_interface *pif = ppp_if[unit];
	struct chap_server_state *ss = &(pif->server);
	struct chap_client_state *cs = &(pif->client);
	unsigned char code, id;
	int len;

	if (pktlen < CHAP_HDRLEN)
		return;
	GETCHAR(code, pkt);
	GETCHAR(id, pkt);
	GETSHORT(len, pkt);
	if (len < CHAP_HDRLEN || len > pktlen)
		return;
	len -= CHAP_HDRLEN;

	switch (code) {
	case CHAP_CHALLENGE:
		chap_respond(cs, id, pkt, len);
		break;
	case CHAP_RESPONSE:
		chap_handle_response(ss, id, pkt, len);
		break;
	case CHAP_FAILURE:
	case CHAP_SUCCESS:
		chap_handle_status(cs, code, id, pkt, len);
		break;
	}
}

static void
chap_protrej(int unit)
{
	struct ppp_interface *pif = ppp_if[unit];
	struct chap_server_state *ss = &(pif->server);
	struct chap_client_state *cs = &(pif->client);
	
	if (ss->flags & TIMEOUT_PENDING) {
		ss->flags &= ~TIMEOUT_PENDING;
		UNTIMEOUT(chap_timeout, ss);
	}
	if (ss->flags & AUTH_STARTED) {
		ss->flags = 0;
		auth_peer_fail(unit, PPP_CHAP);
	}
	if ((cs->flags & (AUTH_STARTED|AUTH_DONE)) == AUTH_STARTED) {
		cs->flags &= ~AUTH_STARTED;
		error("CHAP authentication failed due to protocol-reject");
		auth_withpeer_fail(unit, PPP_CHAP);
	}
}

/*
 * chap_print_pkt - print the contents of a CHAP packet.
 */
static char *chap_code_names[] = {
	"Challenge", "Response", "Success", "Failure"
};

static int
chap_print_pkt(unsigned char *p, int plen,
	       void (*printer) __P((void *, char *, ...)), void *arg)
{
	int code, id, len;
	int clen, nlen;
	unsigned char x;

	if (plen < CHAP_HDRLEN)
		return 0;
	GETCHAR(code, p);
	GETCHAR(id, p);
	GETSHORT(len, p);
	if (len < CHAP_HDRLEN || len > plen)
		return 0;

	if (code >= 1 && code <= sizeof(chap_code_names) / sizeof(char *))
		printer(arg, " %s", chap_code_names[code-1]);
	else
		printer(arg, " code=0x%x", code);
	printer(arg, " id=0x%x", id);
	len -= CHAP_HDRLEN;
	switch (code) {
	case CHAP_CHALLENGE:
	case CHAP_RESPONSE:
		if (len < 1)
			break;
		clen = p[0];
		if (len < clen + 1)
			break;
		++p;
		nlen = len - clen - 1;
		printer(arg, " <");
		for (; clen > 0; --clen) {
			GETCHAR(x, p);
			printer(arg, "%.2x", x);
		}
		printer(arg, ">, name = ");
		print_string((char *)p, nlen, printer, arg);
		break;
	case CHAP_FAILURE:
	case CHAP_SUCCESS:
		printer(arg, " ");
		print_string((char *)p, len, printer, arg);
		break;
	default:
		for (clen = len; clen > 0; --clen) {
			GETCHAR(x, p);
			printer(arg, " %.2x", x);
		}
	}

	return len + CHAP_HDRLEN;
}

//chap认证过程可以参考 <<CHAP验证过程及单双向验证>>
struct protent chap_protent = {
	PPP_CHAP,
	chap_init,
	chap_input,
	chap_protrej,
	chap_lowerup,
	chap_lowerdown,
	NULL,		/* open */
	NULL,		/* close */
	chap_print_pkt,
	NULL,		/* datainput */
	1,		/* enabled_flag */
	"CHAP",		/* name */
	NULL,		/* data_name */
	chap_option_list,
	NULL,		/* check_options */
};
