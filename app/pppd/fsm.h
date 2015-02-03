/*
 * fsm.h - {Link, IP} Control Protocol Finite State Machine definitions.
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
 * $Id: fsm.h,v 1.10 2004/11/13 02:28:15 paulus Exp $
 */
#ifndef __FSM_H__
#define __FSM_H__

/*
 * Packet header = Code, id, length.
 */
#define HEADERLEN	4 //code(1字节)+id(1字节)+length(2字节)


/*
 *  CP (LCP, IPCP, etc.) codes.
 *///code代码域ECHOREQ PROTREJ这几个会走到这里  他们和CONFREQ这里面的几个code代码不一样，单独处理。见fsm_input
#define CONFREQ		1	/* Configuration Request */
#define CONFACK		2	/* Configuration Ack */
#define CONFNAK		3	/* Configuration Nak */
#define CONFREJ		4	/* Configuration Reject */
#define TERMREQ		5	/* Termination Request */
#define TERMACK		6	/* Termination Ack */
#define CODEREJ		7	/* Code Reject */


/*
 * Each FSM is described by an fsm structure and fsm callbacks.
 */ //只有LCP和IPCP有状态机fsm
typedef struct fsm {
    int unit;			/* Interface unit number */
    int protocol;		/* Data Link Layer Protocol field value */
    int state;			/* State */
    int flags;			/* Contains option bits */
    u_char id;			/* Current id */
    u_char reqid;		/* Current request id */ //req和ack的id值必须一致
    u_char seen_ack;		/* Have received valid Ack/Nak/Rej to Req */ //标识已经收到了ACK，如果再次收到此ACK表示有问题，从夫了
    int timeouttime;		/* Timeout time in milliseconds 发送REQ等待对方应答超时时间，超时在定时器中从新启动定时器用该值，但第一次发送req的时候用config_timeout */
    
    int config_timeout;		/* Send Configure-Request timeout time in seconds 但第一次发送req的时候用config_timeout, 超时后在定时器中从新启动定时器用上面的timeouttime */
    int maxconfreqtransmits;	/* Maximum Configure-Request transmissions  默认DEFMAXCONFREQS*/ //这个是最大从船次数，和下面的retransmits配合使用
    int retransmits;		/* Number of retransmissions left */ //默认最大DEFMAXCONFREQS，发一次减一次  赋值的地方在fsm_sconfreq 如果这个减为0了还没收到对方应答,则直接finish，见fsm_timeout
    
    int maxtermtransmits;	/* Maximum Terminate-Request transmissions */

    //reject_if_disagree = (f->nakloops >= f->maxnakloops); //已经多次拒绝了，见fsm_rconfreq
    int nakloops;		/* Number of nak loops since last ack */ //每应答一次nak ack，则该值加1
    int rnakloops;		/* Number of naks received */ //每recv一次nak，则加1 重复接收NAK的次数，多次收到NAK，也是和maxnakloops做比较
    int maxnakloops;		/* Maximum number of nak loops tolerated */
    
    struct fsm_callbacks *callbacks;	/* Callback routines */  // lcp_callbacks  ipcp_callbacks  pap和chap没有callbacks回调函数
    char *term_reason;		/* Reason for closing protocol */
    int term_reason_len;	/* Length of term_reason */
    
    int autonegtimeout; /* maxconfreqtransmits次从传后都没有收到应答，则下一次lcp自动协商的时间就用这个autonegtimeout */
} fsm;

//该结构是fsm->fsm_callbacks状态机中的成员  只有LCP和IPCP协议有callbacks
typedef struct fsm_callbacks {
    void (*resetci)		/* Reset our Configuration Information */  //fsm_sconfreq中调用，也就是在发送req的时候调用 lcp_resetci 
		__P((fsm *));
    int  (*cilen)		/* Length of our Configuration Information */ //在fsm_sconfreq调用，可以不理
		__P((fsm *));

	//本端发送req出去的时候，第一次发送req需要根据配置信息来获取需要发送哪些内容，就需要用到该函数
    void (*addci) 		/* Add our Configuration Information */
		__P((fsm *, u_char *, int *)); //见fsm_sconfreq  发送req的时候用  LCP_addci  ipcp_addci

    //下面这三个，是本段发送req的时候，收到对方的应答。(可能情况:ack  nak  rej)
    int  (*ackci)	/* ACK our Configuration Information */ //Receive Configure-Ack   fsm_rconfack调用。然后在函数lcp_ackci ipcp_ackci中来解析收到的ACK报文内容
		__P((fsm *, u_char *, int));
    int  (*nakci)	/* NAK our Configuration Information */ //Receive Configure-Nak or Configure-Reject.  fsm_rconfnakrej调用.然后在函数lcp_nakci ipcp_nakci中来解析收到的ACK报文内容
		__P((fsm *, u_char *, int, int));
    int  (*rejci)	/* Reject our Configuration Information */ //Receive Configure-Nak or Configure-Reject. fsm_rconfnakrej调用。然后在函数lcp_rejci ipcp_rejci中来解析收到的ACK报文内容
		__P((fsm *, u_char *, int));

    //收到对方发送过来的req，给对方应答中会调用，应答NAK ACK REJ都在该函数中，见fsm_rconfreq。收到req，通过lcp_reqci ipcp_reqci解析req里面的信息，然后根据req里面的内容来决定是会送NAK还是ACK还是REJ
    int  (*reqci)		/* Request peer's Configuration Information */ 
    	__P((fsm *, u_char *, int *, int));

    	
    void (*up)			/* Called when fsm reaches OPENED state */
		__P((fsm *)); //调用的地方在fsm_rconfreq和fsm_rconfack  在LCP协商完成或者IPCP协商完成后调用这个，最终执行lcp_up ipcp_up

    void (*down)		/* Called when fsm leaves OPENED state */ //当LCP协商成功后，LCP状态机会进入OPEND状态。在OPEND状态如果有收到LCP-ACK REQ NAK等包或者收到term的时候，执行down。见fsm_input
		__P((fsm *));//状态错误，例如LCP认证成功后又收到了req，或者terminate_layer，或者fsm_lowerdown。这三种情况下调用。发送req重新协商该协议，例如在IPCP协商成功了，突然又收到个req，则发送IPCP-REQ从新协商IPCP
    void (*starting)		/* Called when we want the lower layer */ //未用，可以不管
		__P((fsm *)); //finish一般在closed或者重传次数达到上限的时候调用
    void (*finished)		/* Called when we don't want the lower layer */ //terminate相关的时候都会调用这个 fsm_rtermack terminate_layer
		__P((fsm *));
    void (*protreject)		/* Called when Protocol-Reject received */ //未用，可以不管
		__P((int));
    void (*retransmit)		/* Retransmission is necessary */ //发送出去的包在规定时间内没有应答的时候，执行。见fsm_timeout
		__P((fsm *));
    int  (*extcode)		/* Called when unknown code received *///lcp_extcode收到echo信息
		__P((fsm *, int, int, u_char *, int));
    char *proto_name;		/* String name for protocol (for messages) */
} fsm_callbacks;


/*
 * Link states.  当前状态
 *///PHASE_DEAD中的相关几个宏表示处于LCP 认证 或者IPCP中的哪一个阶段， INITIAL相关的几个宏表示的LCP AUTH IPCP(每种协议都有一个fsm，)每个状态中的fsm状态机中的stat状态
#define INITIAL		0	/* Down, hasn't been opened */
#define STARTING	1	/* Down, been opened */  //lcp在lcp_open中从INITIAL进入starting阶段
#define CLOSED		2	/* Up, hasn't been opened */ //认证发起前为该状态，见fsm_lowerup。//在terminate_layer中发送term-req的时候的时候状态机为CLOSING状态，当收到term-ack的时候变为CLOSED状态,并在进一步在lcp_finished中进入INITIAL
#define STOPPED		3	/* Open, waiting for down event */
#define CLOSING		4	/* Terminating the connection, not open */ //在terminate_layer中发送term-req的时候的时候状态机为CLOSING状态，当收到term-ack的时候变为CLOSED状态,进一步在lcp_finished中进入INITIAL
#define STOPPING	5	/* Terminating, but open */ //接收到term-req的时候，stat为该状态，从而进一步在
#define REQSENT		6	/* We've sent a Config Request */
#define ACKRCVD		7	/* We've received a Config Ack */
#define ACKSENT		8	/* We've sent a Config Ack */
#define OPENED		9	/* Connection available */ //协商成功后的最终状态为该状态。一层都要经历几个阶段，直到本层达到OPENED状态时才可进入下一阶段来实现下一阶段的协议。(*f->callbacks->up)(f)


//lcp_close  lcp状态变化(CLOSING(发送term-req)->CLOSED(接收到term-ack)->INITIAL(收到term-ack继续后续处理，在lcp_finished中把lcp置为初始状态)) 
//            IPCP状态(发送term-req) : STARTING(ipcp_lowerdown)-> INITIAL(ipcp_close)   接收到ter-ack后，还是维持INITIAL状态

//接收term-req过程      LCP: STOPPING(fsm_rtermreq)->(STOPPED)fsm_rtermack->(STARTING)fsm_lowerdown
//                      IPCP状态(发送term-req) : STARTING(ipcp_lowerdown)-> INITIAL(ipcp_close)   接收到ter-ack后，还是维持INITIAL状态
/*
 * Flags - indicate options controlling FSM operation
 */
 //下面这几个一直都没有置位，不管他
#define OPT_PASSIVE	1	/* Don't die if we don't get a response */ //在passive中配置
#define OPT_RESTART	2	/* Treat 2nd OPEN as DOWN, UP */
#define OPT_SILENT	4	/* Wait for peer to speak first */  //在配置silent中如果配置了在其他的对端先发起连接，则置位该位 OPT_SILENT


/*
 * Timeouts.
 */
#define DEFTIMEOUT	5	/* Timeout time in seconds */
#define DEFMAXTERMREQS	2	/* Maximum Terminate-Request transmissions */
#define DEFMAXCONFREQS	10	/* Maximum Configure-Request transmissions */
#define DEFMAXNAKLOOPS	5	/* Maximum number of nak loops */
#define DEFMAXUNACK	3	/* Maximum number of unack for echo-request */
#define DEFAUTONEGTIMEOUT	5	/* Auto negotiate timeout time in seconds */


/*
 * Prototypes
 */    
void fsm_auto_timer(fsm *f);
void fsm_change_state(fsm *f, int new_state);
void fsm_init __P((fsm *));
void fsm_lowerup __P((fsm *));
void fsm_lowerdown __P((fsm *));
void fsm_open __P((fsm *));
void fsm_close __P((fsm *, char *));
void fsm_input __P((fsm *, u_char *, int));
void fsm_protreject __P((fsm *));
void fsm_sdata __P((fsm *, int, int, u_char *, int));
void fsm_timeout(int unit, void *arg);
void fsm_auto_start(int unit, void *arg);

/*
 * Variables
 */
extern int peer_mru[];		/* currently negotiated peer MRU (per unit) */

#endif

