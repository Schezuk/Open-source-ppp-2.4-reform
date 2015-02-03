/*
 * fsm.c - {Link, IP} Control Protocol Finite State Machine.
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

#define RCSID	"$Id: fsm.c,v 1.23 2004/11/13 02:28:15 paulus Exp $"

/*
 * TODO:
 * Randomize fsm id on link/init.
 * Deal with variable outgoing MTU.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "pppd.h"
#include "fsm.h"
#include "pppd_debug.h"

static const char rcsid[] = RCSID;

void fsm_timeout __P((int, void *));
static void fsm_rconfreq __P((fsm *, int, u_char *, int));
static void fsm_rconfack __P((fsm *, int, u_char *, int));
static void fsm_rconfnakrej __P((fsm *, int, int, u_char *, int));
static void fsm_rtermreq __P((fsm *, int, u_char *, int));
static void fsm_rtermack __P((fsm *));
static void fsm_rcoderej __P((fsm *, u_char *, int));
static void fsm_sconfreq __P((fsm *, int));

#define PROTO_NAME(f)	((f)->callbacks->proto_name)
 
int peer_mru[NUM_PPP]; //PPP_MRU  等于客户端请求的mru  见lcp_up

/*
 * fsm_init - Initialize fsm.
 *
 * Initialize fsm state.
 */
void
fsm_init(fsm *f)
{
    struct ppp_interface *pif = ppp_if[f->unit];

    f->state = INITIAL;
    f->flags = 0;
    f->id = 0;				/* XXX Start with random id? */
    f->timeouttime = DEFTIMEOUT;
    f->config_timeout = pif->sconfreq_timeout; /* ppp_if_mem_malloc中已经初始化 */
	f->maxconfreqtransmits = pif->maxsconfreq_times; /* ppp_if_mem_malloc中已经初始化 */
    f->maxtermtransmits = DEFMAXTERMREQS;
    f->maxnakloops = DEFMAXNAKLOOPS;
    f->term_reason_len = 0;
    f->autonegtimeout = DEFAUTONEGTIMEOUT;
}

#define PPP_MAX_STATE_NUMBER 10
const char *PPP_STATE[PPP_MAX_STATE_NUMBER] = {
	"INITIAL", 
	"STARTING",
	"CLOSED",
	"STOPPED",
	"CLOSING",
	"STOPPING",
	"REQSENT",
	"ACKRCVD",
	"ACKSENT",
	"OPENED"
};

const char *DBG_STATE_NAME(int state)
{
	if(state < PPP_MAX_STATE_NUMBER && state >= 0)
		return PPP_STATE[state];
	else
		return "--";
}

#define PPP_MAX_PHASE_NUMBER 13
const char *PPP_PHASE[PPP_MAX_PHASE_NUMBER] = {
	"DEAD",
	"INITIALIZE", 
	"SERIALCONN",
	"DORMANT",
	"ESTABLISH",
	"AUTHENTICATE",
	"CALLBACK",
	"NETWORK",
	"RUNNING",
	"TERMINATE",
	"DISCONNECT",
	"HOLDOFF",
	"MASTER"
};

const char *DBG_PHASE_NAME(int phase)
{
	if(phase < PPP_MAX_PHASE_NUMBER && phase >= 0)
		return PPP_PHASE[phase];
	else
		return "--";
}

void fsm_change_state(fsm *f, int new_state)
{
	int old_state = f->state;
	struct ppp_interface *pif = ppp_if[f->unit];

    if(pif == NULL)
        return;
        
	f->state = new_state;

	if (NULL != ppp_if && 
	    (f->protocol == PPP_IPCP || f->protocol == PPP_LCP || f->protocol == PPP_CHAP || f->protocol == PPP_PAP)){
        if(PPP_CHECK_FLAG(pppd_debug_if, (1 << f->unit)))   
		    PPPD_DEBUG_NEGTIAT("if %d %s state: %s -> %s", f->unit, PROTO_NAME(f), DBG_STATE_NAME(old_state), DBG_STATE_NAME(new_state));
	}
}

static int fsm_auto_timer_check(fsm *f)
{
	struct ppp_interface *pif = ppp_if[f->unit];

    if(pif->enable == 0)
        return 0;
        
	//if (pif->multilink_flags == 1 && pif->is_master == 0 && f->protocol < 0xC000) 
	//	return 0;

    if(f->protocol < 0xC000) 
        return 0;
        
	return 1;
}

void fsm_auto_start(int unit, void *arg)
{
	struct ppp_interface *pif;
	fsm *f = (fsm *) arg;

    unit = f->unit;
	if (unit < 0 || unit >= NUM_PPP || ppp_if[unit] == NULL)
		return;

	pif = ppp_if[f->unit];
	if (NULL == pif)
		return;
	        
	if(pif->is_ipcp_up == 1)
	    return;
	    
	//if(f->callbacks != NULL)
	if(PPP_CHECK_FLAG(pppd_debug_if, (1 << unit)))   
        PPPD_DEBUG_NEGTIAT("channel:%u: Reset-Timer Expired, reset %s and negotiate again!", unit, 
        PROTO_NAME(f) != NULL ? PROTO_NAME(f):"NULL");
	//fsm_open(f);

	lcp_open(unit);
	new_phase(unit,PHASE_ESTABLISH); //PPPD状态机进入“链路建立”阶段
    lcp_lowerup(unit);//3. 发送LCP Configure Request报文，向对方请求建立LCP链路
}

//一般在重传次数达到上限或者close的时候执行finish，然后从其auto定时器
void fsm_auto_timer(fsm *f)
{
	struct ppp_interface *pif = ppp_if[f->unit];

	if (NULL == pif)
		return;

    if(PPP_CHECK_FLAG(pppd_debug_if, (1 << f->unit)))   
        PPPD_DEBUG_NEGTIAT("channel:%u: Reset-Timer Expired, reset %s and negotiate again, is_ipcp_up:%u enable:%u, protocol:0x%x!", f->unit, 
            PROTO_NAME(f) != NULL ? PROTO_NAME(f):"NULL", pif->is_ipcp_up, pif->enable, f->protocol);
        
	if (fsm_auto_timer_check(f)) 
		TIMEOUT(fsm_auto_start, f, f->autonegtimeout);
	else 
		UNTIMEOUT(fsm_auto_start, f);
}

/*
 * fsm_lowerup - The lower layer is up.
 */ //link_established中调用
void
fsm_lowerup(f)
    fsm *f;
{
    switch( f->state ){
        case INITIAL:
    	//f->state = CLOSED;
    	fsm_change_state(f, CLOSED);
    	break;

    case STARTING:
    	if( f->flags & OPT_SILENT )
    	    //f->state = STOPPED;
    	    fsm_change_state(f, STOPPED);
    	else {
    	    /* Send an initial configure-request */
    	    fsm_sconfreq(f, 0);
    	    //f->state = REQSENT;
    	    fsm_change_state(f, REQSENT);
    	}
	    break;

    default:
	    FSMDEBUG(("%s: Up event in state %d!", PROTO_NAME(f), f->state));
    }
}

/* start auto negotiation timer,
 * and del timer when fsm is disable
 */

/*
 * fsm_lowerdown - The lower layer is down.
 *
 * Cancel all timeouts and inform upper layers.
 */ /*
 unit:0: rcvd [LCP TermReq id=0xaf]
 LCP terminated by peer
 ipcp: down
 unit:0: sent [LCP TermAck id=0xaf]
 */
void
fsm_lowerdown(f)//如果是该协议协商成功的时候调用该函数，则会执行ipcp_down或者lcp_down，否则执行一些状态修改
    fsm *f;
{
    switch( f->state ){
    case CLOSED:
    	//f->state = INITIAL;
    	fsm_change_state(f, INITIAL);
    	break;

    case STOPPED:
    	//f->state = STARTING;
    	fsm_change_state(f, STARTING);
    	if( f->callbacks->starting )
    	    (*f->callbacks->starting)(f);
    	break;

    case CLOSING:
    	//f->state = INITIAL;
    	fsm_change_state(f, INITIAL);
    	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
    	break;

    case STOPPING:
    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
    	//f->state = STARTING;
    	fsm_change_state(f, STARTING);
    	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
    	break;

    case OPENED:
    	if( f->callbacks->down )
    	    (*f->callbacks->down)(f);  
    	//f->state = STARTING;
    	fsm_change_state(f, STARTING);
    	break;

    default:
	FSMDEBUG(("%s: Down event in state %d!", PROTO_NAME(f), f->state));
    }
}


/*
 * fsm_open - Link is allowed to come up.
 */ 
void
fsm_open(fsm *f)
{
    struct ppp_interface *pif = ppp_if[f->unit];

    f->config_timeout = pif->sconfreq_timeout;
	f->maxconfreqtransmits = pif->maxsconfreq_times;
    switch( f->state ){
    case INITIAL:
    	//f->state = STARTING;
    	fsm_change_state(f, STARTING);
    	if(f->callbacks == NULL)
    	    PPPD_DEBUG_NEGTIAT("error, f callbacks");
    	    
    	if(f->callbacks->starting)
    	    (*f->callbacks->starting)(f);//初始化时开始建立链路 初始化状态，实际调用lcp_starting()-> link_required()：
    	break;

    case CLOSED:
    	if( f->flags & OPT_SILENT )
    	   // f->state = STOPPED;
    	    fsm_change_state(f, STOPPED);
    	else {
    	    /* Send an initial configure-request */
    	    fsm_sconfreq(f, 0);
    	   // f->state = REQSENT;
    	    fsm_change_state(f, REQSENT);
    	}
    	break;

    case CLOSING:
    	//f->state = STOPPING;
    	fsm_change_state(f, STOPPING);
    	/* fall through */
    case STOPPED:
    case OPENED:
    	if( f->flags & OPT_RESTART ){
    	    fsm_lowerdown(f);
    	    fsm_lowerup(f);  
    	}
    	break;
    default:
        FSMDEBUG(("%s: fsm open, state: %d!", PROTO_NAME(f), f->state));
    }
}

/*
 * terminate_layer - Start process of shutting down the FSM
 *
 * Cancel any timeout running, notify upper layers we're done, and
 * send a terminate-request message as configured.
 */
//                                                                                                                 |-1.ipcp_lowerdown->ipcp_down
//lcp_close->fsm_close->terminate_layer->(发送term-req，如果这里lcp是协商成功的继续后面)lcp_down->link_down->upper_layers_down->                                      
//                                                                                                                 |-2.ipcp_close->fsm_close->terminate_layer(不在执行ipcp_down，因为前面的ipcp_lowerdown把状态该为closing)
//lcp_finished->link_terminated->fsm_lowerdown->lcp_down

static void
terminate_layer(f, nextstate)  //如果之前该层协议是协商成功的，需要置位各个状态，同时发送term-req
    fsm *f;
    int nextstate;
{ 
    int stat;
    
    if( f->state != OPENED ) //如果是从lcp_close走到这里，并且转到了ipcp，则这里可能为closing状态
	    UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
    else if( f->callbacks->down )
	    (*f->callbacks->down)(f);	/* Inform upper layers we're down */

    /* Init restart counter and send Terminate-Request */
    f->retransmits = f->maxtermtransmits;
    fsm_sdata(f, TERMREQ, f->reqid = ++f->id,
	      (u_char *) f->term_reason, f->term_reason_len);

    if (f->retransmits == 0) { //已经从传了max次       不会走到这里
    	/*
        	 * User asked for no terminate requests at all; just close it.
        	 * We've already fired off one Terminate-Request just to be nice
        	 * to the peer, but we're not going to wait for a reply.
        	 */
    	stat = nextstate == CLOSING ? CLOSED : STOPPED;
    	fsm_change_state(f, stat);
    	if( f->callbacks->finished )
    	    (*f->callbacks->finished)(f);
    	fsm_auto_timer(f);
    	return;
    }

    TIMEOUT(fsm_timeout, f, f->timeouttime); //重传terminate
    --f->retransmits;

    //f->state = nextstate;//这里会把状态置为CLOSING， 下次再进来的时候就不会执行上面的(*f->callbacks->down)(f);
    fsm_change_state(f, nextstate);
}

/*
 * fsm_close - Start closing connection.
 *
 * Cancel timeouts and either initiate close or possibly go directly to
 * the CLOSED state.
 */
//                                                                                                                 |-1.ipcp_lowerdown->ipcp_down
//lcp_close->fsm_close->terminate_layer->(发送term-req如果这里lcp是协商成功的继续后面)lcp_down->link_down->upper_layers_down->                                      
//                                                                                                                 |-2.ipcp_close->fsm_close->terminate_layer(不在执行ipcp_down，因为前面的ipcp_lowerdown把状态该为closing)                                                                                                             |-2.ipcp_close->fsm_close->terminate_layer(不在执行ipcp_down，因为前面的ipcp_lowerdown把状态该为closing)
//lcp_finished->link_terminated->fsm_lowerdown->lcp_down

void
fsm_close(f, reason) //发送terminate-req
    fsm *f;
    char *reason;
{
    f->term_reason = reason;
    f->term_reason_len = (reason == NULL? 0: strlen(reason));
    switch( f->state ){
        case STARTING:
        	//f->state = INITIAL;
        	fsm_change_state(f, INITIAL);
        	break;
        	
        case STOPPED:
        	//f->state = CLOSED;
        	fsm_change_state(f, CLOSED);
        	break;
    	
        case STOPPING:
        	//f->state = CLOSING;
        	fsm_change_state(f, CLOSING);
        	break;

        case REQSENT:
        case ACKRCVD:
        case ACKSENT:
        case OPENED:
    	    terminate_layer(f, CLOSING);
    	break;
    }
}

/*
 * fsm_timeout - Timeout expired.
 */
void
fsm_timeout(int unit, void *arg)
{
    int oldstat;

    fsm *f = (fsm *) arg;
    struct ppp_interface *pif = ppp_if[f->unit];

    unit = f->unit;
    if(pif->enable == 0)
        return;
        
    if(PPP_CHECK_FLAG(pppd_debug_if, (1 << unit)))   
        PPPD_DEBUG_NEGTIAT("fsm timeout, unit:%d enalbe:%u, proto:%s, f->retransmits:%u", f->unit, pif->enable, PROTO_NAME(f), f->retransmits);
    
    switch (f->state) {
    case CLOSING:
    case STOPPING:
	if( f->retransmits <= 0 ){  //retransmits在fsm_rtermreq中被清0
	    /*
	     * We've waited for an ack long enough.  Peer probably heard us.
	     */
	    //f->state = (f->state == CLOSING)? CLOSED: STOPPED;
	    oldstat = (f->state == CLOSING)? CLOSED: STOPPED;
	    fsm_change_state(f, oldstat);
	    if( f->callbacks->finished )
		    (*f->callbacks->finished)(f);
		fsm_auto_timer(f);
	} else { 
	    /* Send Terminate-Request */
	    fsm_sdata(f, TERMREQ, f->reqid = ++f->id,
		      (u_char *) f->term_reason, f->term_reason_len);
	    TIMEOUT(fsm_timeout, f, f->timeouttime);
	    --f->retransmits;
	}
	break;

    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
	if (f->retransmits <= 0) {//重传了最大次数都没收到应答，则直接finish
	    warn("%s: timeout sending Config-Requests\n", PROTO_NAME(f));
	    //f->state = STOPPED;
	    fsm_change_state(f, STOPPED);
	    if((f->flags & OPT_PASSIVE) == 0 && f->callbacks->finished)
		    (*f->callbacks->finished)(f);
        fsm_auto_timer(f);

        if(f->protocol == PPP_IPCP)
			mp_choice_other_master(unit); /* 选择该组的其他unit进行IPCP协商 */
	} else {/* 还没有超过从传次数，启动定时器继续从船 */
	    /* Retransmit the configure-request */
	    if (f->callbacks->retransmit) /* LCP IPCP都没有这个retransmit函数，所以这两句无效 */
		    (*f->callbacks->retransmit)(f);

	    fsm_sconfreq(f, 1);		/* Re-send Configure-Request */
	    if( f->state == ACKRCVD )
		    //f->state = REQSENT;
		    fsm_change_state(f, REQSENT);
	}
	break;

    default:
	FSMDEBUG(("%s: Timeout event in state %d!", PROTO_NAME(f), f->state));
    }
}

/*
 * fsm_input - Input packet.
 */  //code(CONFREQ) + id(直接把接收的返回) + len(后面的数据部分长度)
 //代码域+标志域+长度域+数据域
void
fsm_input(f, inpacket, l)
    fsm *f;
    u_char *inpacket;
    int l;
{
    u_char *inp;
    u_char code, id;
    int len;

    /*
     * Parse header (code, id and length).
     * If packet too short, drop it.
     */
    inp = inpacket;
    if (l < HEADERLEN) {
    	FSMDEBUG(("unit:%2u, fsm_input(%x): Rcvd short header.", f->unit, f->protocol));
    	return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    GETSHORT(len, inp);
    if (len < HEADERLEN) {
    	FSMDEBUG(("unit:%2u, fsm_input(%x): Rcvd illegal length.", f->unit, f->protocol));
    	return;
    }
    if (len > l) {
    	FSMDEBUG(("unit:%2u, fsm_input(%x): Rcvd short packet.", f->unit, f->protocol));
    	return;
    }
    
    len -= HEADERLEN;		/* subtract header length */

    if( f->state == INITIAL || f->state == STARTING ){
    	FSMDEBUG(("unit:%2u, fsm_input(%x): Rcvd packet in state %d.", f->unit, f->protocol, f->state));
    	return;
    }

    /*
     * Action depends on code.
     */
    switch (code) {
    case CONFREQ:
    	fsm_rconfreq(f, id, inp, len);
    	break;
    
    case CONFACK:
    	fsm_rconfack(f, id, inp, len);
    	break;
    
    case CONFNAK:
    case CONFREJ:
    	fsm_rconfnakrej(f, code, id, inp, len);
    	break;
    
    case TERMREQ:
    	fsm_rtermreq(f, id, inp, len);
    	break;
    
    case TERMACK:
    	fsm_rtermack(f);
    	break;
    
    case CODEREJ:
    	fsm_rcoderej(f, inp, len);
    	break;
    
    default: //无法识别code标识域的时候走这里     PAP IPCP都没有注册该协议，只有LCP协议有注册extcode，见lcp_extcode
    	if( !f->callbacks->extcode
    	   || !(*f->callbacks->extcode)(f, code, id, inp, len) ) //只有ECHO信息会走到这里  lcp_extcode
    	    fsm_sdata(f, CODEREJ, ++f->id, inpacket, len + HEADERLEN);
    	break;
    }
}


/*
 * fsm_rconfreq - Receive Configure-Request.
 */
static void
fsm_rconfreq(f, id, inp, len)
    fsm *f;
    u_char id;
    u_char *inp;
    int len;
{
    int code, reject_if_disagree;

    switch( f->state ){
    case CLOSED:
    	/* Go away, we're closed */
    	fsm_sdata(f, TERMACK, id, NULL, 0);
    	return;
    case CLOSING:
    case STOPPING:
	    return;

    case OPENED:
    	/* Go down and restart negotiation */
    	if( f->callbacks->down )
    	    (*f->callbacks->down)(f);	/* Inform upper layers */
    	fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
	break;

    case STOPPED:
	/* Negotiation started by our peer */
    	fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
    	break;
    }

    /*
     * Pass the requested configuration options
     * to protocol-specific code for checking.
     */
    if (f->callbacks->reqci){		/* Check CI */
    	reject_if_disagree = (f->nakloops >= f->maxnakloops); //已经多次拒绝了
    	code = (*f->callbacks->reqci)(f, inp, &len, reject_if_disagree); //多次NAK后，达到NAK上限，则发送CONFREJ
    } else if (len)
	    code = CONFREJ;			/* Reject all CI */
    else
	    code = CONFACK;

    /* send the Ack, Nak or Rej to the peer */
    fsm_sdata(f, code, id, inp, len);

    if (code == CONFACK) {
    	if (f->state == ACKRCVD) {
    	    UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
    	    //f->state = OPENED;
    	    fsm_change_state(f, OPENED);
    	    if (f->callbacks->up)
    		(*f->callbacks->up)(f);	/* Inform upper layers */ //lcp_up
    	} else
    	    //f->state = ACKSENT;
    	    fsm_change_state(f, ACKSENT);
    	f->nakloops = 0;

    } else {
	/* we sent CONFACK or CONFREJ */
	if (f->state != ACKRCVD)
	    //f->state = REQSENT;
	    fsm_change_state(f, REQSENT);
	if( code == CONFNAK )
	    ++f->nakloops;
    }
}


/*
 * fsm_rconfack - Receive Configure-Ack.
 */
static void
fsm_rconfack(f, id, inp, len)
    fsm *f;
    int id;
    u_char *inp;
    int len;
{
    if (id != f->reqid || f->seen_ack)		/* Expected id? */
	    return;					/* Nope, toss... */
    if( !(f->callbacks->ackci? (*f->callbacks->ackci)(f, inp, len):(len == 0))){//对收到的包进行检查  见lcp_ackci
    	/* Ack is bad - ignore it */
    	error("Received bad configure-ack: %P", inp, len);
    	return;
    }
    f->seen_ack = 1;
    f->rnakloops = 0;

    
    switch (f->state) {
    case CLOSED:
    case STOPPED:
    	fsm_sdata(f, TERMACK, id, NULL, 0);
    	break;

    case REQSENT:
    	//f->state = ACKRCVD;
    	fsm_change_state(f, ACKRCVD);
    	f->retransmits = f->maxconfreqtransmits;
    	break;

    case ACKRCVD://收到重复ack,则需要重新发送req
    	/* Huh? an extra valid Ack? oh well... */
    	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
    	fsm_sconfreq(f, 0);
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
    	break;

    case ACKSENT:
    	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
    	//f->state = OPENED;
    	fsm_change_state(f, OPENED);
    	f->retransmits = f->maxconfreqtransmits;
    	if (f->callbacks->up)//lcp_up
    	    (*f->callbacks->up)(f);	/* Inform upper layers */
    	break;

    case OPENED:
    	/* Go down and restart negotiation */
    	if (f->callbacks->down)
    	    (*f->callbacks->down)(f);	/* Inform upper layers */
    	fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
    	break;
    }
}


/*
 * fsm_rconfnakrej - Receive Configure-Nak or Configure-Reject.
 */
static void
fsm_rconfnakrej(f, code, id, inp, len)
    fsm *f;
    int code, id;
    u_char *inp;
    int len;
{
    int ret;
    int treat_as_reject;

    if (id != f->reqid || f->seen_ack)	/* Expected id? */
	    return;				/* Nope, toss... */

    if (code == CONFNAK) {
    	++f->rnakloops;
    	treat_as_reject = (f->rnakloops >= f->maxnakloops);
    	if (f->callbacks->nakci == NULL
    	    || !(ret = f->callbacks->nakci(f, inp, len, treat_as_reject))) {
    	    error("Received bad configure-nak: %P", inp, len);
    	    return;
    	}
    } else {//CONFREJ
    	f->rnakloops = 0;
    	if (f->callbacks->rejci == NULL
    	    || !(ret = f->callbacks->rejci(f, inp, len))) {
    	    error("Received bad configure-rej: %P", inp, len);
    	    return;
    	}
    }

    f->seen_ack = 1;

    switch (f->state) {
    case CLOSED:
    case STOPPED:
	fsm_sdata(f, TERMACK, id, NULL, 0);
	break;

    case REQSENT:
    case ACKSENT:
	/* They didn't agree to what we wanted - try another request */
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	if (ret < 0)
	    //f->state = STOPPED;		/* kludge for stopping CCP */
	    fsm_change_state(f, STOPPED);
	else
	    fsm_sconfreq(f, 0);		/* Send Configure-Request */
	break;

    case ACKRCVD:
    	/* Got a Nak/reject when we had already had an Ack?? oh well... */
    	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
    	fsm_sconfreq(f, 0);
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
    	break;

    case OPENED:
	    /* Go down and restart negotiation */
    	if (f->callbacks->down)
    	    (*f->callbacks->down)(f);	/* Inform upper layers */
    	fsm_sconfreq(f, 0);		/* Send initial Configure-Request */
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
    	break;
    }
}


/*
 * fsm_rtermreq - Receive Terminate-Req.
 */
static void
fsm_rtermreq(f, id, p, len)
    fsm *f;
    int id;
    u_char *p;
    int len;
{
    switch (f->state) {
    case ACKRCVD:
    case ACKSENT:
    	//f->state = REQSENT;		/* Start over but keep trying */
    	fsm_change_state(f, REQSENT);
    	break;

    case OPENED:
    	//if (len > 0) {
    	//    info("%s terminated by peer (%0.*v)", PROTO_NAME(f), len, p);
    	//} else
    	    info("%s terminated by peer", PROTO_NAME(f));
    	f->retransmits = 0;
    	//f->state = STOPPING;
    	fsm_change_state(f, STOPPING);
    	if (f->callbacks->down)
    	    (*f->callbacks->down)(f);	/* Inform upper layers */
        TIMEOUT(fsm_timeout, f, f->timeouttime); //接收到ter-req的时候，最终从这里的超时定时器中来超时，实现finish
    	break;
    }

    fsm_sdata(f, TERMACK, id, NULL, 0);
}


/*
 * fsm_rtermack - Receive Terminate-Ack.
 */
static void
fsm_rtermack(f)
    fsm *f;
{
    switch (f->state) {
    case CLOSING:
    	UNTIMEOUT(fsm_timeout, f);
    	//f->state = CLOSED;//发送出去term-req(进入CLOSING状态)后，收到term-ack(进入CLOSED状态)应答，则把CLOSING状态置为CLOSED状态,进一步在lcp_finished中进入INITIAL
        fsm_change_state(f, CLOSED);
    	if( f->callbacks->finished )
    	    (*f->callbacks->finished)(f);
    	fsm_auto_timer(f);
	    break;
	    
    case STOPPING:
    	UNTIMEOUT(fsm_timeout, f);
    	//f->state = STOPPED;
    	fsm_change_state(f, STOPPED);
    	if( f->callbacks->finished )
    	    (*f->callbacks->finished)(f);
    	fsm_auto_timer(f);
    	break;

    case ACKRCVD:
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
    	break;

    case OPENED:
    	if (f->callbacks->down)
    	    (*f->callbacks->down)(f);	/* Inform upper layers */
    	fsm_sconfreq(f, 0);
    	//f->state = REQSENT;
    	fsm_change_state(f, REQSENT);
    	break;
    }
}


/*
 * fsm_rcoderej - Receive an Code-Reject.
 */
static void
fsm_rcoderej(f, inp, len)
    fsm *f;
    u_char *inp;
    int len;
{
    u_char code, id;

    if (len < HEADERLEN) {
	FSMDEBUG(("fsm_rcoderej: Rcvd short Code-Reject packet!"));
	return;
    }
    GETCHAR(code, inp);
    GETCHAR(id, inp);
    warn("%s: Rcvd Code-Reject for code %d, id %d", PROTO_NAME(f), code, id);

    if( f->state == ACKRCVD )
	    //f->state = REQSENT;
	    fsm_change_state(f, REQSENT);
}


/*
 * fsm_protreject - Peer doesn't speak this protocol.
 *
 * Treat this as a catastrophic error (RXJ-).
 */
void
fsm_protreject(f) /* 可以不管 */
    fsm *f;
{
    switch( f->state ){
    case CLOSING:
	UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	/* fall through */
    case CLOSED:
    	//f->state = CLOSED;
    	fsm_change_state(f, CLOSED);
    	if( f->callbacks->finished )
    	    (*f->callbacks->finished)(f);
    	fsm_auto_timer(f);
	break;

    case STOPPING:
    case REQSENT:
    case ACKRCVD:
    case ACKSENT:
	    UNTIMEOUT(fsm_timeout, f);	/* Cancel timeout */
	/* fall through */
    case STOPPED:
    	//f->state = STOPPED;
    	fsm_change_state(f, STOPPED);
    	if( f->callbacks->finished )
    	    (*f->callbacks->finished)(f);
    	fsm_auto_timer(f);
	break;

    case OPENED:
    	terminate_layer(f, STOPPING);
    	break;

    default:
	    FSMDEBUG(("%s: Protocol-reject event in state %d!",
		  PROTO_NAME(f), f->state));
    }
}


/*
 * fsm_sconfreq - Send a Configure-Request.
 */ //发送req
static void
fsm_sconfreq(f, retransmit)
    fsm *f;
    int retransmit;
{
    u_char *outp;
    int cilen;
    struct ppp_interface *pif = ppp_if[f->unit];

    if( f->state != REQSENT && f->state != ACKRCVD && f->state != ACKSENT ){
    	/* Not currently negotiating - reset options */
    	if( f->callbacks->resetci )
    	    (*f->callbacks->resetci)(f);//lcp_resetci  ipcp_reset
    	f->nakloops = 0;
    	f->rnakloops = 0;
    }

    if( !retransmit ){
    	/* New request - reset retransmission counter, use new ID */
    	f->retransmits = f->maxconfreqtransmits;
    	f->reqid = ++f->id;
    }

    f->seen_ack = 0;

    /*
     * Make up the request packet
     */
    outp = pif->out_buf + PPP_HDRLEN + HEADERLEN;
    //printf("yang test .........fsm unit:%u, addr:%p\n", f->unit, pif->out_buf);
    if( f->callbacks->cilen && f->callbacks->addci ){
    	cilen = (*f->callbacks->cilen)(f); //获取发送的数据部分长度 ipcp_cilen  lcp_cilen
    	if( cilen > peer_mru[f->unit] - HEADERLEN )
    	    cilen = peer_mru[f->unit] - HEADERLEN;
    	if (f->callbacks->addci)
    	    (*f->callbacks->addci)(f, outp, &cilen);
    } else
	    cilen = 0;

    /* send the request to our peer */
    fsm_sdata(f, CONFREQ, f->reqid, outp, cilen);

    /* start the retransmit timer */
    --f->retransmits;
    TIMEOUT(fsm_timeout, f, f->config_timeout);
}


/*
 * fsm_sdata - Send some data.
 *
 * Used for all packets sent to our peer by this module.
 */
void
fsm_sdata(f, code, id, data, datalen)
    fsm *f;
    u_char code, id;
    u_char *data;
    int datalen;
{
    u_char *outp;
    int outlen;
    struct ppp_interface *pif = ppp_if[f->unit];

    /* Adjust length to be smaller than MTU */
    outp = pif->out_buf;
    if (datalen > peer_mru[f->unit] - HEADERLEN)
	    datalen = peer_mru[f->unit] - HEADERLEN;

    if (datalen && data != outp + PPP_HDRLEN + HEADERLEN)
	    BCOPY(data, outp + PPP_HDRLEN + HEADERLEN, datalen);

    outlen = datalen + HEADERLEN;
    MAKEHEADER(outp, f->protocol);//地址域(1字节)+控制域(1字节)+协议域(2字节)
    PUTCHAR(code, outp);
    PUTCHAR(id, outp);
    PUTSHORT(outlen, outp);
    output(f->unit, pif->out_buf, outlen + PPP_HDRLEN);
}

