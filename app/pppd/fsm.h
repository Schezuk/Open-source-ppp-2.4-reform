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
#define HEADERLEN	4 //code(1�ֽ�)+id(1�ֽ�)+length(2�ֽ�)


/*
 *  CP (LCP, IPCP, etc.) codes.
 *///code������ECHOREQ PROTREJ�⼸�����ߵ�����  ���Ǻ�CONFREQ������ļ���code���벻һ��������������fsm_input
#define CONFREQ		1	/* Configuration Request */
#define CONFACK		2	/* Configuration Ack */
#define CONFNAK		3	/* Configuration Nak */
#define CONFREJ		4	/* Configuration Reject */
#define TERMREQ		5	/* Termination Request */
#define TERMACK		6	/* Termination Ack */
#define CODEREJ		7	/* Code Reject */


/*
 * Each FSM is described by an fsm structure and fsm callbacks.
 */ //ֻ��LCP��IPCP��״̬��fsm
typedef struct fsm {
    int unit;			/* Interface unit number */
    int protocol;		/* Data Link Layer Protocol field value */
    int state;			/* State */
    int flags;			/* Contains option bits */
    u_char id;			/* Current id */
    u_char reqid;		/* Current request id */ //req��ack��idֵ����һ��
    u_char seen_ack;		/* Have received valid Ack/Nak/Rej to Req */ //��ʶ�Ѿ��յ���ACK������ٴ��յ���ACK��ʾ�����⣬�ӷ���
    int timeouttime;		/* Timeout time in milliseconds ����REQ�ȴ��Է�Ӧ��ʱʱ�䣬��ʱ�ڶ�ʱ���д���������ʱ���ø�ֵ������һ�η���req��ʱ����config_timeout */
    
    int config_timeout;		/* Send Configure-Request timeout time in seconds ����һ�η���req��ʱ����config_timeout, ��ʱ���ڶ�ʱ���д���������ʱ���������timeouttime */
    int maxconfreqtransmits;	/* Maximum Configure-Request transmissions  Ĭ��DEFMAXCONFREQS*/ //��������Ӵ��������������retransmits���ʹ��
    int retransmits;		/* Number of retransmissions left */ //Ĭ�����DEFMAXCONFREQS����һ�μ�һ��  ��ֵ�ĵط���fsm_sconfreq ��������Ϊ0�˻�û�յ��Է�Ӧ��,��ֱ��finish����fsm_timeout
    
    int maxtermtransmits;	/* Maximum Terminate-Request transmissions */

    //reject_if_disagree = (f->nakloops >= f->maxnakloops); //�Ѿ���ξܾ��ˣ���fsm_rconfreq
    int nakloops;		/* Number of nak loops since last ack */ //ÿӦ��һ��nak ack�����ֵ��1
    int rnakloops;		/* Number of naks received */ //ÿrecvһ��nak�����1 �ظ�����NAK�Ĵ���������յ�NAK��Ҳ�Ǻ�maxnakloops���Ƚ�
    int maxnakloops;		/* Maximum number of nak loops tolerated */
    
    struct fsm_callbacks *callbacks;	/* Callback routines */  // lcp_callbacks  ipcp_callbacks  pap��chapû��callbacks�ص�����
    char *term_reason;		/* Reason for closing protocol */
    int term_reason_len;	/* Length of term_reason */
    
    int autonegtimeout; /* maxconfreqtransmits�δӴ���û���յ�Ӧ������һ��lcp�Զ�Э�̵�ʱ��������autonegtimeout */
} fsm;

//�ýṹ��fsm->fsm_callbacks״̬���еĳ�Ա  ֻ��LCP��IPCPЭ����callbacks
typedef struct fsm_callbacks {
    void (*resetci)		/* Reset our Configuration Information */  //fsm_sconfreq�е��ã�Ҳ�����ڷ���req��ʱ����� lcp_resetci 
		__P((fsm *));
    int  (*cilen)		/* Length of our Configuration Information */ //��fsm_sconfreq���ã����Բ���
		__P((fsm *));

	//���˷���req��ȥ��ʱ�򣬵�һ�η���req��Ҫ����������Ϣ����ȡ��Ҫ������Щ���ݣ�����Ҫ�õ��ú���
    void (*addci) 		/* Add our Configuration Information */
		__P((fsm *, u_char *, int *)); //��fsm_sconfreq  ����req��ʱ����  LCP_addci  ipcp_addci

    //�������������Ǳ��η���req��ʱ���յ��Է���Ӧ��(�������:ack  nak  rej)
    int  (*ackci)	/* ACK our Configuration Information */ //Receive Configure-Ack   fsm_rconfack���á�Ȼ���ں���lcp_ackci ipcp_ackci���������յ���ACK��������
		__P((fsm *, u_char *, int));
    int  (*nakci)	/* NAK our Configuration Information */ //Receive Configure-Nak or Configure-Reject.  fsm_rconfnakrej����.Ȼ���ں���lcp_nakci ipcp_nakci���������յ���ACK��������
		__P((fsm *, u_char *, int, int));
    int  (*rejci)	/* Reject our Configuration Information */ //Receive Configure-Nak or Configure-Reject. fsm_rconfnakrej���á�Ȼ���ں���lcp_rejci ipcp_rejci���������յ���ACK��������
		__P((fsm *, u_char *, int));

    //�յ��Է����͹�����req�����Է�Ӧ���л���ã�Ӧ��NAK ACK REJ���ڸú����У���fsm_rconfreq���յ�req��ͨ��lcp_reqci ipcp_reqci����req�������Ϣ��Ȼ�����req����������������ǻ���NAK����ACK����REJ
    int  (*reqci)		/* Request peer's Configuration Information */ 
    	__P((fsm *, u_char *, int *, int));

    	
    void (*up)			/* Called when fsm reaches OPENED state */
		__P((fsm *)); //���õĵط���fsm_rconfreq��fsm_rconfack  ��LCPЭ����ɻ���IPCPЭ����ɺ�������������ִ��lcp_up ipcp_up

    void (*down)		/* Called when fsm leaves OPENED state */ //��LCPЭ�̳ɹ���LCP״̬�������OPEND״̬����OPEND״̬������յ�LCP-ACK REQ NAK�Ȱ������յ�term��ʱ��ִ��down����fsm_input
		__P((fsm *));//״̬��������LCP��֤�ɹ������յ���req������terminate_layer������fsm_lowerdown������������µ��á�����req����Э�̸�Э�飬������IPCPЭ�̳ɹ��ˣ�ͻȻ���յ���req������IPCP-REQ����Э��IPCP
    void (*starting)		/* Called when we want the lower layer */ //δ�ã����Բ���
		__P((fsm *)); //finishһ����closed�����ش������ﵽ���޵�ʱ�����
    void (*finished)		/* Called when we don't want the lower layer */ //terminate��ص�ʱ�򶼻������� fsm_rtermack terminate_layer
		__P((fsm *));
    void (*protreject)		/* Called when Protocol-Reject received */ //δ�ã����Բ���
		__P((int));
    void (*retransmit)		/* Retransmission is necessary */ //���ͳ�ȥ�İ��ڹ涨ʱ����û��Ӧ���ʱ��ִ�С���fsm_timeout
		__P((fsm *));
    int  (*extcode)		/* Called when unknown code received *///lcp_extcode�յ�echo��Ϣ
		__P((fsm *, int, int, u_char *, int));
    char *proto_name;		/* String name for protocol (for messages) */
} fsm_callbacks;


/*
 * Link states.  ��ǰ״̬
 *///PHASE_DEAD�е���ؼ������ʾ����LCP ��֤ ����IPCP�е���һ���׶Σ� INITIAL��صļ������ʾ��LCP AUTH IPCP(ÿ��Э�鶼��һ��fsm��)ÿ��״̬�е�fsm״̬���е�stat״̬
#define INITIAL		0	/* Down, hasn't been opened */
#define STARTING	1	/* Down, been opened */  //lcp��lcp_open�д�INITIAL����starting�׶�
#define CLOSED		2	/* Up, hasn't been opened */ //��֤����ǰΪ��״̬����fsm_lowerup��//��terminate_layer�з���term-req��ʱ���ʱ��״̬��ΪCLOSING״̬�����յ�term-ack��ʱ���ΪCLOSED״̬,���ڽ�һ����lcp_finished�н���INITIAL
#define STOPPED		3	/* Open, waiting for down event */
#define CLOSING		4	/* Terminating the connection, not open */ //��terminate_layer�з���term-req��ʱ���ʱ��״̬��ΪCLOSING״̬�����յ�term-ack��ʱ���ΪCLOSED״̬,��һ����lcp_finished�н���INITIAL
#define STOPPING	5	/* Terminating, but open */ //���յ�term-req��ʱ��statΪ��״̬���Ӷ���һ����
#define REQSENT		6	/* We've sent a Config Request */
#define ACKRCVD		7	/* We've received a Config Ack */
#define ACKSENT		8	/* We've sent a Config Ack */
#define OPENED		9	/* Connection available */ //Э�̳ɹ��������״̬Ϊ��״̬��һ�㶼Ҫ���������׶Σ�ֱ������ﵽOPENED״̬ʱ�ſɽ�����һ�׶���ʵ����һ�׶ε�Э�顣(*f->callbacks->up)(f)


//lcp_close  lcp״̬�仯(CLOSING(����term-req)->CLOSED(���յ�term-ack)->INITIAL(�յ�term-ack��������������lcp_finished�а�lcp��Ϊ��ʼ״̬)) 
//            IPCP״̬(����term-req) : STARTING(ipcp_lowerdown)-> INITIAL(ipcp_close)   ���յ�ter-ack�󣬻���ά��INITIAL״̬

//����term-req����      LCP: STOPPING(fsm_rtermreq)->(STOPPED)fsm_rtermack->(STARTING)fsm_lowerdown
//                      IPCP״̬(����term-req) : STARTING(ipcp_lowerdown)-> INITIAL(ipcp_close)   ���յ�ter-ack�󣬻���ά��INITIAL״̬
/*
 * Flags - indicate options controlling FSM operation
 */
 //�����⼸��һֱ��û����λ��������
#define OPT_PASSIVE	1	/* Don't die if we don't get a response */ //��passive������
#define OPT_RESTART	2	/* Treat 2nd OPEN as DOWN, UP */
#define OPT_SILENT	4	/* Wait for peer to speak first */  //������silent������������������ĶԶ��ȷ������ӣ�����λ��λ OPT_SILENT


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

