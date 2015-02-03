/*
 * Generic PPP layer for Linux.
 *
 * Copyright 1999-2002 Paul Mackerras.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 * The generic PPP layer handles the PPP network interfaces, the
 * /dev/ppp device, packet and VJ compression, and multilink.
 * It talks to PPP `channels' via the interface defined in
 * include/linux/ppp_channel.h.  Channels provide the basic means for
 * sending and receiving PPP frames on some kind of communications
 * channel.
 *
 * Part of the code in this driver was inspired by the old async-only
 * PPP driver, written by Michael Callahan and Al Longyear, and
 * subsequently hacked by Paul Mackerras.
 *
 * ==FILEVERSION 20041108==
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/idr.h>
#include <linux/netdevice.h>
#include <linux/poll.h>
#include <linux/ppp_defs.h>
#include <linux/filter.h>
#include <linux/if_ppp.h>
#include <linux/ppp_channel.h>
#include <linux/ppp-comp.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/stddef.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <net/slhc_vj.h>
#include <asm/atomic.h>

#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
//#include <linux/netdevice.h>
//#include <linux/etherdevice.h>
extern __be16		eth_type_trans(struct sk_buff *skb, struct net_device *dev);

#define PPP_VERSION	"2.4.4"

#define REFORMreform_DEBUG 1

/*
 * Network protocols we support.
 */
#define NP_IP	0		/* Internet Protocol V4 */
#define NP_IPV6	1		/* Internet Protocol V6 */
#define NP_IPX	2		/* IPX protocol */
#define NP_AT	3		/* Appletalk protocol */
#define NP_MPLS_UC 4		/* MPLS unicast */
#define NP_MPLS_MC 5		/* MPLS multicast */
#define NUM_NP	6		/* Number of NPs. */

#define MPHDRLEN	6	/* multilink protocol header length */
#define MPHDRLEN_SSN	4	/* ditto with short sequence numbers */
#define MIN_FRAG_SIZE	64

/*
 * An instance of /dev/ppp can be associated with either a ppp
 * interface unit or a ppp channel.  In both cases, file->private_data
 * points to one of these.
 */
struct ppp_file {
	enum {
		INTERFACE=1, CHANNEL
	}		kind;
	struct sk_buff_head xq;		/* pppd transmit queue */
	struct sk_buff_head rq;		/* receive queue for pppd */
	wait_queue_head_t rwait;	/* for poll on reading /dev/ppp */
	atomic_t	refcnt;		/* # refs (incl /dev/ppp attached) 多少个channel在这上面*/
	int		hdrlen;		/* space to leave for headers */
	int		index;		/* interface unit / channel number */
	int		dead;		/* unit/channel has been shut down */
};

#define PF_TO_X(pf, X)		container_of(pf, X, file)

#define PF_TO_PPP(pf)		PF_TO_X(pf, struct ppp)
#define PF_TO_CHANNEL(pf)	PF_TO_X(pf, struct channel)

/*
 * Data structure describing one ppp unit.
 * A ppp unit corresponds to a ppp network interface device
 * and represents a multilink bundle.
 * It can have 0 or more ppp channels connected to it.
 */
struct ppp {
	struct ppp_file	file;		/* stuff for read/write/poll 0 */
	struct file	*owner;		/* file that owns this unit 48 */
	struct list_head channels;	/* list of attached channels 4c */
	int		n_channels;	/* how many channels are attached 54 */
	spinlock_t	rlock;		/* lock for receive side 58 */
	spinlock_t	wlock;		/* lock for transmit side 5c */
	int		mru;		/* max receive unit 60 */
	unsigned int	flags;		/* control bits 64 */
	unsigned int	xstate;		/* transmit state bits 68 */
	unsigned int	rstate;		/* receive state bits 6c */
	int		debug;		/* debug flags 70 */
	struct slcompress *vj;		/* state for VJ header compression */
	enum NPmode	npmode[NUM_NP];	/* what to do with each net proto 78 */
	struct sk_buff	*xmit_pending;	/* a packet ready to go out 88 */
	struct compressor *xcomp;	/* transmit packet compressor 8c */
	void		*xc_state;	/* its internal state 90 */
	struct compressor *rcomp;	/* receive decompressor 94 */
	void		*rc_state;	/* its internal state 98 */
	unsigned long	last_xmit;	/* jiffies when last pkt sent 9c */
	unsigned long	last_recv;	/* jiffies when last pkt rcvd a0 */
	struct net_device *dev;		/* network interface device a4 */
	int		closing;	/* is device closing down? a8 */
	struct reform_ppp *reform_ppp;
#ifdef CONFIG_PPP_MULTILINK
//标识下次再来一个multilink包的时候，将从nxchan发送数据。例如0 1 2 通道捆在一起，ppp_mp_explode发送一个2000的包，在发送的时候会从通道0和1发送，
//通道0发送1500字节，通道1发送500字节,下次再来multilink包通过ppp_mp_explode的时候，将从通道2开始循环发送
	int		nxchan;		/* next channel to send something on */ 
	u32		nxseq;		/* next sequence number to send */
	int		mrru;		/* MP: max reconst. receive unit */
	u32		nextseq;	/* MP: seq no of next packet */ //每当收到一个包的时候，ppp->nextseq = seq + 1;
	u32		minseq;		/* MP: min of most recent seqnos */ //默认-1，见ppp_create_interface
	struct sk_buff_head mrq;	/* MP: receive reconstruction queue */ //multlink接收队列，用于重组multilink多链路包
#endif /* CONFIG_PPP_MULTILINK */
#ifdef CONFIG_PPP_FILTER
	struct sock_filter *pass_filter;	/* filter for packets to pass */
	struct sock_filter *active_filter;/* filter for pkts to reset idle */
	unsigned pass_len, active_len;
#endif /* CONFIG_PPP_FILTER */
	struct net	*ppp_net;	/* the net we belong to */
};

/*
 * Bits in flags: SC_NO_TCP_CCID, SC_CCP_OPEN, SC_CCP_UP, SC_LOOP_TRAFFIC,
 * SC_MULTILINK, SC_MP_SHORTSEQ, SC_MP_XSHORTSEQ, SC_COMP_TCP, SC_REJ_COMP_TCP,
 * SC_MUST_COMP
 * Bits in rstate: SC_DECOMP_RUN, SC_DC_ERROR, SC_DC_FERROR.
 * Bits in xstate: SC_COMP_RUN
 */
#define SC_FLAG_BITS	(SC_NO_TCP_CCID|SC_CCP_OPEN|SC_CCP_UP|SC_LOOP_TRAFFIC \
			 |SC_MULTILINK|SC_MP_SHORTSEQ|SC_MP_XSHORTSEQ \
			 |SC_COMP_TCP|SC_REJ_COMP_TCP|SC_MUST_COMP)

/*
 * Private data structure for each channel.
 * This includes the data structure used for multilink.
 */
struct channel {
	struct ppp_file	file;		/* stuff for read/write/poll */
	struct list_head list;		/* link in all/new_channels list */
	struct ppp_channel *chan;	/* public channel data structure */
	struct rw_semaphore chan_sem;	/* protects `chan' during chan ioctl */
	spinlock_t	downl;		/* protects `chan', file.xq dequeue */
	struct ppp	*ppp;		/* ppp unit we're connected to */
	struct net	*chan_net;	/* the net channel belongs to */
	struct list_head clist;		/* link in list of channels per unit */
	rwlock_t	upl;		/* protects `ppp' */
#ifdef CONFIG_PPP_MULTILINK
    //标识该通道是否有效，如果有效并且该通道队列没有数据(pch->file.xq)则值为2，有数据为1，该通道无效值为0
	u8		avail;		/* flag used in multilink stuff */ 
	u8		had_frag;	/* >= 1 fragments have been sent */ //标识有包在该channel上面发送
	u32		lastseq;	/* MP: last sequence # received */ //表示最后接收到的skb的seq序号
	int     speed;		/* speed of the corresponding ppp channel*/
#endif /* CONFIG_PPP_MULTILINK */
};

/*
 * SMP locking issues:
 * Both the ppp.rlock and ppp.wlock locks protect the ppp.channels
 * list and the ppp.n_channels field, you need to take both locks
 * before you modify them.
 * The lock ordering is: channel.upl -> ppp.wlock -> ppp.rlock ->
 * channel.downl.
 */

static atomic_t ppp_unit_count = ATOMIC_INIT(0);
static atomic_t channel_count = ATOMIC_INIT(0);

/* per-net private data for this module */
static int ppp_net_id;
struct ppp_net {
	/* units to ppp mapping */
	struct idr units_idr;

	/*
	 * all_ppp_mutex protects the units_idr mapping.
	 * It also ensures that finding a ppp unit in the units_idr
	 * map and updating its file.refcnt field is atomic.
	 */
	struct mutex all_ppp_mutex;

	/* channels */
	struct list_head all_channels;
	struct list_head new_channels;
	int last_channel_index;

	/*
	 * all_channels_lock protects all_channels and
	 * last_channel_index, and the atomicity of find
	 * a channel and updating its file.refcnt field.
	 */
	spinlock_t all_channels_lock;
};

/* Get the PPP protocol number from a skb */
#define PPP_PROTO(skb)	(((skb)->data[0] << 8) + (skb)->data[1])

/* We limit the length of ppp->file.rq to this (arbitrary) value */
#define PPP_MAX_RQLEN	32

/*
 * Maximum number of multilink fragments queued up.
 * This has to be large enough to cope with the maximum latency of
 * the slowest channel relative to the others.  Strictly it should
 * depend on the number of channels and their characteristics.
 */
#define PPP_MP_MAX_QLEN	128

/* Multilink header bits. */
#define B	0x80		/* this fragment begins a packet */ //Begin  一个multilink包开始
#define E	0x40		/* this fragment ends a packet */  //end     一个multilink包结束

/* Compare multilink sequence numbers (assumed to be 32 bits wide) */
#define seq_before(a, b)	((s32)((a) - (b)) < 0)
#define seq_after(a, b)		((s32)((a) - (b)) > 0)

/* Prototypes. */
static int ppp_unattached_ioctl(struct net *net, struct ppp_file *pf,
			struct file *file, unsigned int cmd, unsigned long arg);
static void ppp_xmit_process(struct ppp *ppp);
static void ppp_send_frame(struct ppp *ppp, struct sk_buff *skb);
static void ppp_push(struct ppp *ppp);
static void ppp_channel_push(struct channel *pch);
static void ppp_receive_frame(struct ppp *ppp, struct sk_buff *skb,
			      struct channel *pch);
static void ppp_receive_error(struct ppp *ppp);
static void ppp_receive_nonmp_frame(struct ppp *ppp, struct sk_buff *skb);
static struct sk_buff *ppp_decompress_frame(struct ppp *ppp,
					    struct sk_buff *skb);
#ifdef CONFIG_PPP_MULTILINK
static void ppp_receive_mp_frame(struct ppp *ppp, struct sk_buff *skb,
				struct channel *pch);
static void ppp_mp_insert(struct ppp *ppp, struct sk_buff *skb);
static struct sk_buff *ppp_mp_reconstruct(struct ppp *ppp);
static int ppp_mp_explode(struct ppp *ppp, struct sk_buff *skb);
#endif /* CONFIG_PPP_MULTILINK */
static int ppp_set_compress(struct ppp *ppp, unsigned long arg);
static void ppp_ccp_peek(struct ppp *ppp, struct sk_buff *skb, int inbound);
static void ppp_ccp_closed(struct ppp *ppp);
static struct compressor *find_compressor(int type);
static void ppp_get_stats(struct ppp *ppp, struct ppp_stats *st);
static struct ppp *ppp_create_interface(struct net *net, int unit, int *retp);
static void init_ppp_file(struct ppp_file *pf, int kind);
static void ppp_shutdown_interface(struct ppp *ppp);
static void ppp_destroy_interface(struct ppp *ppp);
static struct ppp *ppp_find_unit(struct ppp_net *pn, int unit);
static struct channel *ppp_find_channel(struct ppp_net *pn, int unit);
static int ppp_connect_channel(struct channel *pch, int unit);
static int ppp_disconnect_channel(struct channel *pch);
static void ppp_destroy_channel(struct channel *pch);
static int unit_get(struct idr *p, void *ptr);
static int unit_set(struct idr *p, void *ptr, int n);
static void unit_put(struct idr *p, int n);
static void *unit_find(struct idr *p, int n);

static struct class *ppp_class;

/* per net-namespace data */
static inline struct ppp_net *ppp_pernet(struct net *net)
{
	BUG_ON(!net);

	return net_generic(net, ppp_net_id);
}

/* Translates a PPP protocol number to a NP index (NP == network protocol) */
static inline int proto_to_npindex(int proto)
{
	switch (proto) {
	case PPP_IP:
		return NP_IP;
	case PPP_IPV6:
		return NP_IPV6;
	case PPP_IPX:
		return NP_IPX;
	case PPP_AT:
		return NP_AT;
	case PPP_MPLS_UC:
		return NP_MPLS_UC;
	case PPP_MPLS_MC:
		return NP_MPLS_MC;
	}
	return -EINVAL;
}

/* Translates an NP index into a PPP protocol number */
static const int npindex_to_proto[NUM_NP] = {
	PPP_IP,
	PPP_IPV6,
	PPP_IPX,
	PPP_AT,
	PPP_MPLS_UC,
	PPP_MPLS_MC,
};

/* Translates an ethertype into an NP index */
static inline int ethertype_to_npindex(int ethertype)
{
	switch (ethertype) {
	case ETH_P_IP:
		return NP_IP;
	case ETH_P_IPV6:
		return NP_IPV6;
	case ETH_P_IPX:
		return NP_IPX;
	case ETH_P_PPPTALK:
	case ETH_P_ATALK:
		return NP_AT;
	case ETH_P_MPLS_UC:
		return NP_MPLS_UC;
	case ETH_P_MPLS_MC:
		return NP_MPLS_MC;
	}
	return -1;
}

/* Translates an NP index into an ethertype */
static const int npindex_to_ethertype[NUM_NP] = {
	ETH_P_IP,
	ETH_P_IPV6,
	ETH_P_IPX,
	ETH_P_PPPTALK,
	ETH_P_MPLS_UC,
	ETH_P_MPLS_MC,
};

/*
 * Locking shorthand.
 */
#define ppp_xmit_lock(ppp)	spin_lock_bh(&(ppp)->wlock)
#define ppp_xmit_unlock(ppp)	spin_unlock_bh(&(ppp)->wlock)
#define ppp_recv_lock(ppp)	spin_lock_bh(&(ppp)->rlock)
#define ppp_recv_unlock(ppp)	spin_unlock_bh(&(ppp)->rlock)
#define ppp_lock(ppp)		do { ppp_xmit_lock(ppp); \
				     ppp_recv_lock(ppp); } while (0)
#define ppp_unlock(ppp)		do { ppp_recv_unlock(ppp); \
				     ppp_xmit_unlock(ppp); } while (0)



static int g_del_chan_formultilink = 0; //如果链路是为了加入multilink组，则不应该释放reforme2_ppp结构
#define REFORM_reform_PPP 0xCDE0

typedef struct reform_reform_expand_hdr {
	unsigned char dmac[6];
	unsigned char smac[6];
	unsigned short proto;		/*上行报文定义为0xCDE0*/
	unsigned char paddata_len;
	unsigned char channo;
	unsigned char testxx;
} __attribute__((packed)) reform_reform_expand_hdr_t;

struct reform_ppp {
	struct net_device *dev;
	unsigned int	flags;//地址控制字段，协议字段压缩相关，待完善，yang add todo xxxxxxxxxxx
	struct reform_ppp  *reform_ppp;	/* descriptor */
	spinlock_t xmit_lock;
	spinlock_t recv_lock;
    unsigned long   xmit_flags;
    struct sk_buff  *tpkt;

	int		mru;
	struct sk_buff_head rqueue;
	struct tasklet_struct tsk;
	atomic_t	refcnt;
	struct ppp_channel chan;	/* interface to generic ppp layer */
};

char reform_dmac[] = {0xff,0x5f,0x4f,0x3f,0x2f,0xff};
char reform_smac[] = {0x12,0x12,0x12,0x12,0x0e,0x01};

#define REFORM_reform_DATA_HDR_SIZE sizeof(struct reform_reform_expand_hdr)

/* Bit numbers in xmit_flags */
#define XMIT_WAKEUP	0
#define XMIT_FULL	1

/* Bits in rbits */
#define SC_RCV_BITS	(SC_RCV_B7_1|SC_RCV_B7_0|SC_RCV_ODDP|SC_RCV_EVNP)

/*
 * Utility procedures to print a buffer in hex/ascii
 */
static void
ppp_print_hex (register __u8 * out, const __u8 * in, int count)
{
	register __u8 next_ch;
	static const char hex[] = "0123456789ABCDEF";

	while (count-- > 0) {
		next_ch = *in++;
		*out++ = hex[(next_ch >> 4) & 0x0F];
		*out++ = hex[next_ch & 0x0F];
		++out;
	}
}

static void
ppp_print_char (register __u8 * out, const __u8 * in, int count)
{
	register __u8 next_ch;

	while (count-- > 0) {
		next_ch = *in++;

		if (next_ch < 0x20 || next_ch > 0x7e)
			*out++ = '.';
		else {
			*out++ = next_ch;
			if (next_ch == '%')   /* printk/syslogd has a bug !! */
				*out++ = '%';
		}
	}
	*out = '\0';
}


static void reform_print_buffer (const char *name, const __u8 *buf, int count)
{
	__u8 line[44];
       // return;
	if (name != NULL)
		printk("ppp_vnd: %s, count = %d\n", name, count);
	while (count > 8) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, 8);
		ppp_print_char (&line[8 * 3], buf, 8);
		printk("%s\n", line);
		count -= 8;
		buf += 8;
	}

	if (count > 0) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, count);
		ppp_print_char (&line[8 * 3], buf, count);
		printk("%s\n", line);
	}
}

static int ppp_reform_input(struct sk_buff *skb)
{
	struct ppp *ppp;
	struct reform_ppp *vp;
	struct net_device *dev;
	unsigned char *pbuf;

	if(!skb)
		return NET_RX_SUCCESS;

   	if(skb->protocol != htons(REFORM_reform_PPP))
		return NET_RX_SUCCESS;
	dev = skb->dev;
	ppp = netdev_priv(dev);
	vp = ppp->reform_ppp;
	
	//#ifdef REFORMreform_DEBUG
	//	reform_print_buffer ("receive buffer", skb->data, skb->len);
   // #endif
    
	/*if(skb->len > vp->mru + PPP_HDRLEN + 2){
	    printk("ppp reform input len:%u, vp->mru:%u, large length,err\n", skb->len, vp->mru);
        ++ppp->dev->stats.rx_length_errors;
		goto err;
	}*/

	/* strip address/control field if present */
	pbuf = skb->data;
	if (pbuf[0] == PPP_ALLSTATIONS && pbuf[1] == PPP_UI) {
		/* chop off address/control */
		if (skb->len < 3)
			goto err;
		pbuf = skb_pull(skb, 2);
	}

	/* decompress protocol field if compressed */
	if (pbuf[0] & 1) {
		/* protocol is compressed */
		skb_push(skb, 1)[0] = 0;
	} else if (skb->len < 2)
		goto err;
	ppp_input(&vp->chan, skb);

	return NET_RX_SUCCESS;

err:
	kfree_skb(skb);
	++ppp->dev->stats.rx_errors;
	return NET_RX_DROP;
}

int reform_reform_data_skb_recv(struct sk_buff *skb, struct net_device *dev,
		  struct packet_type *ptype, struct net_device *orig_dev)
{
	int channo;
	int pkt_size;//包括封装头部在内的总长度
	int paddata_len;
	struct net_device *reform_dev;
	struct reform_reform_expand_hdr *reform_expand_hdr;
	struct channel *chan;
	struct reform_ppp* reform_ppp;
	struct ppp_net *pn;
	struct net *net;

	pkt_size = skb->len + ETH_HLEN;
	if (pkt_size <= REFORM_reform_DATA_HDR_SIZE){
		goto no_dev;
	}

    skb_push(skb, ETH_HLEN);

#if 0
        //printk("\nsend channo:%u  ", channo);
    		reform_print_buffer ("recv buffer", skb->data, skb->len);
#endif
    skb_pull(skb, ETH_HLEN);
    

	reform_expand_hdr = (struct reform_reform_expand_hdr *)skb_mac_header(skb);
	channo = (reform_expand_hdr->channo);

	pn = ppp_pernet(dev_net(dev));
	spin_lock_bh(&pn->all_channels_lock); 
	chan = ppp_find_channel(pn, channo);
	if(chan == NULL){
	    printk("channo can not find,reform_reform_data_skb_recv err, channo:%u\n", channo);
	    spin_unlock_bh(&pn->all_channels_lock);
		goto no_dev;
	}
    spin_unlock_bh(&pn->all_channels_lock);
    
    reform_ppp = (struct reform_ppp*)chan->chan->private;
    reform_dev = reform_ppp->dev;
	paddata_len = (reform_expand_hdr->paddata_len);
	
	/* 去掉尾部的0填充 */
	skb_trim(skb, skb->len - paddata_len);
	
	skb_pull(skb, REFORM_reform_DATA_HDR_SIZE - ETH_HLEN);
	skb->dev = reform_dev;
	switch (reform_dev->type){
		case ARPHRD_ETHER: //如果是PPP，则赋值为在中ppp_setup ARPHRD_PPP
			skb->protocol = eth_type_trans(skb, reform_dev);
			reform_dev->stats.rx_packets++;
			reform_dev->stats.rx_bytes += pkt_size; 
			break;
	}
	skb->pkt_type = PACKET_HOST;
	ppp_reform_input(skb);

	return NET_RX_SUCCESS;

drop_skb:
	reform_dev->stats.rx_dropped++;
	reform_dev->stats.rx_errors++;
no_dev:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static struct packet_type reform_data_pkt_type __read_mostly = {
	.type = cpu_to_be16(REFORM_reform_PPP),
	.func = reform_reform_data_skb_recv,  
};

static struct sk_buff*
ppp_reform_txmunge(struct reform_ppp *vp, struct sk_buff *skb)
{
	int proto;
	unsigned char *data;
	int islcp;

	data  = skb->data;
	proto = (data[0] << 8) + data[1];

	/* LCP packets with codes between 1 (configure-request)
	 * and 7 (code-reject) must be sent as though no options
	 * have been negotiated.
	 */
	islcp = proto == PPP_LCP && 1 <= data[2] && data[2] <= 7;

	/* compress protocol field if option enabled */
	if (data[0] == 0 && (vp->flags & SC_COMP_PROT) && !islcp)
		skb_pull(skb,1);

#if 1 
	/* prepend address/control fields if necessary */
	//if ((vp->flags & SC_COMP_AC) == 0 || islcp) {
		if (skb_headroom(skb) < 2) {
			struct sk_buff *npkt = dev_alloc_skb(skb->len + 2);
			if (npkt == NULL) {
				kfree_skb(skb);
				return NULL;
			}
			skb_reserve(npkt,2);
			skb_copy_from_linear_data(skb, skb_put(npkt, skb->len), skb->len);
			kfree_skb(skb);
			skb = npkt;
		}
		skb_push(skb,2);
		skb->data[0] = PPP_ALLSTATIONS;
		skb->data[1] = PPP_UI;
	//}
#endif

	return skb;
}

static int 
vnd_reform_raw_header(struct sk_buff *skb,struct net_device *vnd_dev, struct net_device *tx_dev, int channo,
    struct sk_buff **new_skb)
{
	struct reform_reform_expand_hdr *reform_exphdr;

	if (skb_cow_head(skb, REFORM_reform_DATA_HDR_SIZE))
		return -1;

	reform_exphdr = (struct reform_reform_expand_hdr *)skb_push(skb, REFORM_reform_DATA_HDR_SIZE);
	reform_exphdr->proto = htons(REFORM_reform_PPP);
	memcpy(reform_exphdr->dmac, reform_dmac, ETH_ALEN);
	memcpy(reform_exphdr->smac, reform_smac, ETH_ALEN);
	reform_exphdr->channo = (channo);
	reform_exphdr->paddata_len = 0;

#if 0
     if(skb->len < 60)
     {
         *new_skb = skb_copy_expand(skb, skb_headroom(skb), 100, GFP_ATOMIC);
         if(*new_skb == NULL) {
             printk("<%s, %u>, skb copy expand err\n", __FUNCTION__, __LINE__);
             return -1;
         }
         
            
         reform_exphdr->paddata_len = 60 - skb->len;
    	 memset((*new_skb)->data+(*new_skb)->len,0 , reform_exphdr->paddata_len);
    	 skb_put((*new_skb) , reform_exphdr->paddata_len);
    	 dev_kfree_skb(skb);
     }   
     
	skb_reset_network_header((*new_skb));
#else
    if(skb->len < 60)
     {
         reform_exphdr->paddata_len = 60 - skb->len;
     }   
     
	skb_reset_network_header(skb);
#endif

	return REFORM_reform_DATA_HDR_SIZE;
}

int ppp_xmit_reform_data_frame(struct sk_buff *skb, struct net_device *dev, int channo)
{
	int ret = -ENETDOWN;
	struct net_device *tx_dev;
	unsigned long ffllaaggss = 0;
	struct iphdr  *iph = NULL;
	u_int16_t frag_offset;
	u_int8_t mf;  

	struct sk_buff *new_skb = NULL;

	/*iph = ip_hdr(skb);
	frag_offset = ntohs(iph->frag_off);
	mf = (u_int8_t)((frag_offset & 0x2000) >> 13);
	frag_offset &= 0x1FFF;
	if(frag_offset || mf)
	{
        printk(" \n");
	}*/

	dev->trans_start = jiffies;
	
	tx_dev = dev_get_by_name(dev_net(dev), "eth3");
	if(tx_dev != NULL){
		/* 目前支持raw报文头 */
		ret = vnd_reform_raw_header(skb, dev, tx_dev, channo, &new_skb);
		
		if (ret < 0){
			dev_put(tx_dev);
			printk(KERN_WARNING"xmit reform header error, drop!\n");
			ret = -ENETDOWN;
			goto out_kfree;
		}

       // printk(KERN_WARNING"No such reform e1 eth3, err !!!!!!!!!!!\n");
        printk(" \n");
        //reform_print_buffer ("send buffer", skb->data, skb->len);

		skb->dev = tx_dev;
		ret = dev_queue_xmit(skb);
		//raise_softirq(NET_TX_SOFTIRQ);
		dev_put(tx_dev);

		return ret;
	}
	
	printk(KERN_WARNING"No such reform e1 eth3, err !!!!!!!!!!!\n");

out_kfree:
	kfree_skb(skb);
	return ret;
}

int ppp_send_reform_data(struct sk_buff *skb, struct net_device *dev, int channo)
{
	int ret = -ENETDOWN;
	int len = skb->len;

	ret = ppp_xmit_reform_data_frame(skb, dev, channo);
	if (likely(ret == NET_XMIT_SUCCESS)) {
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += len;
	}
	else {
		dev->stats.tx_dropped++;
	}

	return len;
}

/*
 * Transmit-side routines.
 */
/*
 * Push as much data as possible out to the tty.
 */
static int
ppp_reform_push(struct reform_ppp *vp)
{
	int sent, done = 0;
    struct channel *pch;
    pch = (struct channel *)vp->chan.ppp;
	if (!spin_trylock_bh(&vp->xmit_lock))
		return 0;
	for (;;) {
		test_and_clear_bit(XMIT_WAKEUP, &vp->xmit_flags);
		
		if (vp->tpkt) {
			sent = ppp_send_reform_data(vp->tpkt,vp->dev, pch->file.index);
			if (sent < 0)
				goto flush;	/* error, e.g. loss of CD */

			vp->tpkt = NULL;
			clear_bit(XMIT_FULL, &vp->xmit_flags);
			done = 1;
			continue;
		}
		/* haven't made any progress */
		spin_unlock_bh(&vp->xmit_lock);
		if (!(test_bit(XMIT_WAKEUP, &vp->xmit_flags)
		      || (vp->tpkt)))
			break;
		if (!spin_trylock_bh(&vp->xmit_lock))
			break;
	}
	return done;

flush:
	if (vp->tpkt) {
		kfree_skb(vp->tpkt);
		vp->tpkt = NULL;
		clear_bit(XMIT_FULL, &vp->xmit_flags);
		done = 1;
	}
	spin_unlock_bh(&vp->xmit_lock);
	return done;
}

static int
ppp_reform_send(struct ppp_channel *chan, struct sk_buff *skb)
{
	struct reform_ppp *vp = chan->private;

	ppp_reform_push(vp);

	if (test_and_set_bit(XMIT_FULL, &vp->xmit_flags))
		return 0;	/* already full */
	skb = ppp_reform_txmunge(vp, skb);
	if (skb != NULL)
		vp->tpkt = skb;
	else
		clear_bit(XMIT_FULL, &vp->xmit_flags);

	ppp_reform_push(vp);
	
	return 1;
}

static void ppp_reform_process(unsigned long arg)
{
	struct reform_ppp *vp = (struct reform_ppp *) arg;
	struct sk_buff *skb;

	/* process received packets */
	while ((skb = skb_dequeue(&vp->rqueue)) != NULL) {
		if (skb->len == 0) {
			/* zero length buffers indicate error */
			ppp_input_error(&vp->chan, 0);
			kfree_skb(skb);
		}
		else
			ppp_input(&vp->chan, skb);
	}

	/* try to push more stuff out */
	if (test_bit(XMIT_WAKEUP, &vp->xmit_flags) && ppp_reform_push(vp))
		ppp_output_wakeup(&vp->chan);
}

static int ppp_disconnect_channel_for_multilink(struct channel *pch)
{
	struct ppp *ppp;
	int err = -EINVAL;
    
	write_lock_bh(&pch->upl);
	ppp = pch->ppp;
	pch->ppp = NULL;
	write_unlock_bh(&pch->upl);
	if (ppp) {
		/* remove it from the ppp unit's list */
		ppp_lock(ppp);
		list_del(&pch->clist);
		if (--ppp->n_channels == 0)
			wake_up_interruptible(&ppp->file.rwait);
		ppp_unlock(ppp);
		//if (atomic_dec_and_test(&ppp->file.refcnt)) 如果是multilink，则这里
		//	ppp_destroy_interface(ppp);
		err = 0;
	}
	return err;
}

#define	PPPIOCHANTOUNIT _IOW('t', 100, int)	 

static int ppp_reform_ioctl(struct ppp_channel *chan, unsigned int cmd, unsigned long arg)
{
	struct reform_ppp *vp = chan->private;
	struct channel *ch = vp->chan.ppp;
	struct ppp *ppp = netdev_priv(vp->dev);
	int unit;
	int err;
	
    void __user *argp = (void __user *)arg;

    printk("ppp_reform_ioctl ....ppp reform ioctl\n");
	if (cmd == PPPIOCHANTOUNIT) {
		if (get_user(unit, (int __user *) argp))
			return -EFAULT;
		g_del_chan_formultilink = 1;
		printk("delet channo:%u,then add to unit:%u,for multilink\n", ch->file.index, unit);
		ppp_disconnect_channel(ch);
		ppp_connect_channel(ch, unit);
		err = 0;
	}

	return 0;
}

static struct ppp_channel_ops reform_ppp_ops = {
	.start_xmit = ppp_reform_send,
	.ioctl   = ppp_reform_ioctl,
};
//在ppp_create_interface->register_netdev->register_netdevice->ppp_reform_chan_open中执行 所以创建unit的时候同时创建了channel,但没有让channel添加到unit链表上
static int ppp_reform_chan_open(struct net_device *dev)
{
	struct ppp *ppp = netdev_priv(dev);
	struct reform_ppp *vp;
	struct channel *pch;
	int		hdrlen;
	int err;

	vp = kzalloc(sizeof(struct reform_ppp), GFP_KERNEL);
	err = -ENOMEM;
	if (!vp)
		goto out;

	/* initialize the vndppp structure */
	ppp->reform_ppp = vp;
	vp->dev = dev;
    vp->mru = PPP_MRU;
	spin_lock_init(&vp->xmit_lock);
	spin_lock_init(&vp->recv_lock);

	skb_queue_head_init(&vp->rqueue);
	tasklet_init(&vp->tsk, ppp_reform_process, (unsigned long)vp);

	atomic_set(&vp->refcnt, 1);

	vp->chan.private = vp;
	vp->chan.ops = &reform_ppp_ops;
	vp->chan.mtu = PPP_MRU;
	vp->chan.hdrlen = 2;	/* for A/C bytes */
	vp->chan.speed = 2048000;//2M

	//dev->rx_hook = ppp_vnd_input;
	
	err = ppp_register_channel(&vp->chan);
	if (err)
		goto out_free;

	//ppp_connect_channel(vp->chan.ppp, ppp->file.index);

	pch = vp->chan.ppp;

	err = -EINVAL;
	if (pch->ppp)
		goto out_free;

	return 0;

 out_free:
	kfree(vp);
 out:
	return err;
}

static void ppp_reform_chan_close(struct net_device *dev)
{
	struct ppp *ppp = netdev_priv(dev);
	struct reform_ppp *vp = ppp->reform_ppp;

    if(g_del_chan_formultilink == 1) {
        g_del_chan_formultilink = 0;
        return;
    }
    
	if (!vp)
		return;

	/*
	 * We have now ensured that nobody can start using ap from now
	 * on, but we have to wait for all existing users to finish.
	 * Note that ppp_unregister_channel ensures that no calls to
	 * our channel ops (i.e. ppp_sync_send/ioctl) are in progress
	 * by the time it returns.
	 */
	tasklet_kill(&vp->tsk);

	ppp_unregister_channel(&vp->chan);
	skb_queue_purge(&vp->rqueue);
	kfree_skb(vp->tpkt);
	kfree(vp);
}


/*
 * /dev/ppp device routines.
 * The /dev/ppp device is used by pppd to control the ppp unit.
 * It supports the read, write, ioctl and poll functions.
 * Open instances of /dev/ppp can be in one of three states:
 * unattached, attached to a ppp unit, or attached to a ppp channel.
 */
static int ppp_open(struct inode *inode, struct file *file)
{
	cycle_kernel_lock();
	/*
	 * This could (should?) be enforced by the permissions on /dev/ppp.
	 */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	return 0;
}

static int ppp_release(struct inode *unused, struct file *file)
{
	struct ppp_file *pf = file->private_data;
	struct ppp *ppp;

	if (pf) {
		file->private_data = NULL;
		if (pf->kind == INTERFACE) {
			ppp = PF_TO_PPP(pf);
			if (file == ppp->owner)
				ppp_shutdown_interface(ppp);
		}
		if (atomic_dec_and_test(&pf->refcnt)) {
			switch (pf->kind) {
			case INTERFACE:
				ppp_destroy_interface(PF_TO_PPP(pf));
				break;
			case CHANNEL:
				ppp_destroy_channel(PF_TO_CHANNEL(pf));
				break;
			}
		}
	}
	return 0;
}

static ssize_t ppp_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct ppp_file *pf = file->private_data;
	DECLARE_WAITQUEUE(wait, current);
	ssize_t ret;
	struct sk_buff *skb = NULL;

	ret = count;

	if (!pf) {
		return -ENXIO;
    }
	add_wait_queue(&pf->rwait, &wait);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		skb = skb_dequeue(&pf->rq); //接收的IPCP,见ppp_receive_nonmp_frame
		if (skb)
			break;
		ret = 0;//队列上没有数据直接返回0
		if (pf->dead) {
			break;
		}
		if (pf->kind == INTERFACE) {
			/*
			 * Return 0 (EOF) on an interface that has no
			 * channels connected, unless it is looping
			 * network traffic (demand mode).
			 */
			struct ppp *ppp = PF_TO_PPP(pf);
			if (ppp->n_channels == 0
			    && (ppp->flags & SC_LOOP_TRAFFIC) == 0)
				break;
		}
		ret = -EAGAIN;
		if (file->f_flags & O_NONBLOCK)
			break;
		ret = -ERESTARTSYS;
		if (signal_pending(current))
			break;
		schedule();
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&pf->rwait, &wait);

	if (!skb) {
		goto out;
    }
	ret = -EOVERFLOW;
	if (skb->len > count) {
		goto outf;
	}
	ret = -EFAULT;
	if (copy_to_user(buf, skb->data, skb->len)) {
		goto outf;
	}
	ret = skb->len;

 outf:
	kfree_skb(skb);
 out:
	return ret;
}

static ssize_t ppp_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	struct ppp_file *pf = file->private_data;
	struct sk_buff *skb;
	ssize_t ret;

	if (!pf)
		return -ENXIO;
	ret = -ENOMEM;
	skb = alloc_skb(count + pf->hdrlen, GFP_KERNEL);
	if (!skb)
		goto out;
	skb_reserve(skb, pf->hdrlen);
	ret = -EFAULT;
	if (copy_from_user(skb_put(skb, count), buf, count)) {
		kfree_skb(skb);
		goto out;
	}

	skb_queue_tail(&pf->xq, skb);

/*
如果吃channel则直接调用pch->chan->ops->start_xmit走以太口出去
如果是unit则分两种情况，如果是master(也就是设置了SC_MULTILINK)，则走ppp_mp_explode，把数据平方到unit的channel上面，如果是这种情况一定要确保unit上面至少有一个channel
然后调用各自channel的chan->ops->start_xmit。如果是slave(也就是没有设置SC_MULTILINK)则直接走chan->ops->start_xmit。见ppp_push
*/
	switch (pf->kind) {
	case INTERFACE:
		ppp_xmit_process(PF_TO_PPP(pf));
		break;
	case CHANNEL:
		ppp_channel_push(PF_TO_CHANNEL(pf));
		break;
	}

	ret = count;

 out:
	return ret;
}

/* No kernel lock - fine */
static unsigned int ppp_poll(struct file *file, poll_table *wait)
{
	struct ppp_file *pf = file->private_data;
	unsigned int mask;

	if (!pf)
		return 0;
	poll_wait(file, &pf->rwait, wait);
	mask = POLLOUT | POLLWRNORM;
	if (skb_peek(&pf->rq))
		mask |= POLLIN | POLLRDNORM;
	if (pf->dead)
		mask |= POLLHUP;
	else if (pf->kind == INTERFACE) {
		/* see comment in ppp_read */
		struct ppp *ppp = PF_TO_PPP(pf);
		if (ppp->n_channels == 0
		    && (ppp->flags & SC_LOOP_TRAFFIC) == 0)
			mask |= POLLIN | POLLRDNORM;
	}

	return mask;
}

#ifdef CONFIG_PPP_FILTER
static int get_filter(void __user *arg, struct sock_filter **p)
{
	struct sock_fprog uprog;
	struct sock_filter *code = NULL;
	int len, err;

	if (copy_from_user(&uprog, arg, sizeof(uprog)))
		return -EFAULT;

	if (!uprog.len) {
		*p = NULL;
		return 0;
	}

	len = uprog.len * sizeof(struct sock_filter);
	code = kmalloc(len, GFP_KERNEL);
	if (code == NULL)
		return -ENOMEM;

	if (copy_from_user(code, uprog.filter, len)) {
		kfree(code);
		return -EFAULT;
	}

	err = sk_chk_filter(code, uprog.len);
	if (err) {
		kfree(code);
		return err;
	}

	*p = code;
	return uprog.len;
}
#endif /* CONFIG_PPP_FILTER */

static long ppp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ppp_file *pf = file->private_data;
	struct ppp *ppp;
	int err = -EFAULT, val, val2, i;
	struct ppp_idle idle;
	struct npioctl npi;
	int unit, cflags;
	struct slcompress *vj;
	void __user *argp = (void __user *)arg;
	int __user *p = argp;

    g_del_chan_formultilink = 0;
    
	if (!pf) //fd和unit或者channel没有关联的时候走这里面
		return ppp_unattached_ioctl(current->nsproxy->net_ns,
					pf, file, cmd, arg);
					
    
	if (cmd == PPPIOCDETACH) {//使得fd和unit或者channel的管理关系取消
		/*
		 * We have to be careful here... if the file descriptor
		 * has been dup'd, we could have another process in the
		 * middle of a poll using the same file *, so we had
		 * better not free the interface data structures -
		 * instead we fail the ioctl.  Even in this case, we
		 * shut down the interface if we are the owner of it.
		 * Actually, we should get rid of PPPIOCDETACH, userland
		 * (i.e. pppd) could achieve the same effect by closing
		 * this fd and reopening /dev/ppp.
		 */
		printk("ppp ioctl, detach from ppp unit/chan\n");
		err = -EINVAL;
		lock_kernel();
		if (pf->kind == INTERFACE) {
			ppp = PF_TO_PPP(pf);
			if (file == ppp->owner)
				ppp_shutdown_interface(ppp);
		}
		if (atomic_long_read(&file->f_count) <= 2) {
			ppp_release(NULL, file);
			err = 0;
		} else
			printk(KERN_DEBUG "PPPIOCDETACH file->f_count=%ld\n",
			       atomic_long_read(&file->f_count));
		unlock_kernel();
		return err;
	}
   
	if (pf->kind == CHANNEL) {
		struct channel *pch;
		struct ppp_channel *chan;

		lock_kernel();
		pch = PF_TO_CHANNEL(pf);

		switch (cmd) {
		case PPPIOCCONNECT: //把channel添加到unit上
			if (get_user(unit, p))
				break;
		     printk("ppp ioctl, connect channel to unit:%u\n", unit);
			err = ppp_connect_channel(pch, unit);
			break;

		case PPPIOCDISCONN://把channel从unit上面删除
		    get_user(unit, p);
		    printk("ppp ioctl, disconnect channe:%u\n", unit);
			err = ppp_disconnect_channel(pch);
			break;

		default:
			down_read(&pch->chan_sem);
			chan = pch->chan;
			err = -ENOTTY;
			printk("ppp_ioctl.......goto reform ioctl\n");
			if (chan && chan->ops->ioctl)
				err = chan->ops->ioctl(chan, cmd, arg);
		    atomic_inc(&ppp->file.refcnt);
			file->private_data = &ppp->file;
			err = 0;
			up_read(&pch->chan_sem);
		}
		unlock_kernel();
		return err;
	}

	if (pf->kind != INTERFACE) {
		/* can't happen */
		printk(KERN_ERR "PPP: not interface or channel??\n");
		return -EINVAL;
	}

	lock_kernel();
	ppp = PF_TO_PPP(pf);
	switch (cmd) {
	case PPPIOCSMRU:
		if (get_user(val, p))
			break;
		ppp->mru = val;
		err = 0;
		break;

	case PPPIOCSFLAGS:
		if (get_user(val, p))
			break;
		ppp_lock(ppp);
		cflags = ppp->flags & ~val;
		ppp->flags = val & SC_FLAG_BITS;
		ppp_unlock(ppp);
		if (cflags & SC_CCP_OPEN)
			ppp_ccp_closed(ppp);
		err = 0;
		break;

	case PPPIOCGFLAGS:
		val = ppp->flags | ppp->xstate | ppp->rstate;
		if (put_user(val, p))
			break;
		err = 0;
		break;

	case PPPIOCSCOMPRESS:
		err = ppp_set_compress(ppp, arg);
		break;

	case PPPIOCGUNIT:
		if (put_user(ppp->file.index, p))
			break;
		err = 0;
		break;

	case PPPIOCSDEBUG:
		if (get_user(val, p))
			break;
		ppp->debug = val;
		err = 0;
		break;

	case PPPIOCGDEBUG:
		if (put_user(ppp->debug, p))
			break;
		err = 0;
		break;

	case PPPIOCGIDLE:
		idle.xmit_idle = (jiffies - ppp->last_xmit) / HZ;
		idle.recv_idle = (jiffies - ppp->last_recv) / HZ;
		if (copy_to_user(argp, &idle, sizeof(idle)))
			break;
		err = 0;
		break;

	case PPPIOCSMAXCID:
		if (get_user(val, p))
			break;
		val2 = 15;
		if ((val >> 16) != 0) {
			val2 = val >> 16;
			val &= 0xffff;
		}
		vj = slhc_init(val2+1, val+1);
		if (!vj) {
			printk(KERN_ERR "PPP: no memory (VJ compressor)\n");
			err = -ENOMEM;
			break;
		}
		ppp_lock(ppp);
		if (ppp->vj)
			slhc_free(ppp->vj);
		ppp->vj = vj;
		ppp_unlock(ppp);
		err = 0;
		break;

	case PPPIOCGNPMODE:
	case PPPIOCSNPMODE:
		if (copy_from_user(&npi, argp, sizeof(npi)))
			break;
		err = proto_to_npindex(npi.protocol);
		if (err < 0)
			break;
		i = err;
		if (cmd == PPPIOCGNPMODE) {
			err = -EFAULT;
			npi.mode = ppp->npmode[i];
			if (copy_to_user(argp, &npi, sizeof(npi)))
				break;
		} else {
			ppp->npmode[i] = npi.mode;
			/* we may be able to transmit more packets now (??) */
			netif_wake_queue(ppp->dev);
		}
		err = 0;
		break;

#ifdef CONFIG_PPP_FILTER
	case PPPIOCSPASS:
	{
		struct sock_filter *code;
		err = get_filter(argp, &code);
		if (err >= 0) {
			ppp_lock(ppp);
			kfree(ppp->pass_filter);
			ppp->pass_filter = code;
			ppp->pass_len = err;
			ppp_unlock(ppp);
			err = 0;
		}
		break;
	}
	case PPPIOCSACTIVE:
	{
		struct sock_filter *code;
		err = get_filter(argp, &code);
		if (err >= 0) {
			ppp_lock(ppp);
			kfree(ppp->active_filter);
			ppp->active_filter = code;
			ppp->active_len = err;
			ppp_unlock(ppp);
			err = 0;
		}
		break;
	}
#endif /* CONFIG_PPP_FILTER */

#ifdef CONFIG_PPP_MULTILINK
	case PPPIOCSMRRU:
		if (get_user(val, p))
			break;
		ppp_recv_lock(ppp);
		ppp->mrru = val;
		ppp_recv_unlock(ppp);
		err = 0;
		break;
#endif /* CONFIG_PPP_MULTILINK */

	default:
		err = -ENOTTY;
	}
	unlock_kernel();
	return err;
}

static int ppp_unattached_ioctl(struct net *net, struct ppp_file *pf,
			struct file *file, unsigned int cmd, unsigned long arg)
{
	int unit, err = -EFAULT;
	struct ppp *ppp;
	struct channel *chan;
	struct ppp_net *pn;
	int __user *p = (int __user *)arg;

	lock_kernel();
	printk("ppp ioctl, ppp unattached ioctl, cmd:%u\n", cmd);
	switch (cmd) {
	case PPPIOCNEWUNIT: //创建unit，同时应用层对应的fd和该unit对应
		/* Create a new ppp unit */
		printk("ppp ioctl, ppp unattached ioctl, new unit\n");
		if (get_user(unit, p))
			break;
		ppp = ppp_create_interface(net, unit, &err);
		if (!ppp)
			break;
		file->private_data = &ppp->file;
		ppp->owner = file;
		err = -EFAULT;
		if (put_user(ppp->file.index, p))
			break;
		err = 0;
		break;

	case PPPIOCATTACH: //使fd与对应的内核unit联系起来
		/* Attach to an existing ppp unit */
		printk("ppp ioctl, ppp unattached ioctl, attach to ppp unit\n");
		if (get_user(unit, p))
			break;
		err = -ENXIO;
		pn = ppp_pernet(net);
		mutex_lock(&pn->all_ppp_mutex);
		ppp = ppp_find_unit(pn, unit);
		if (ppp) {
			atomic_inc(&ppp->file.refcnt);
			file->private_data = &ppp->file;
			err = 0;
		}
		mutex_unlock(&pn->all_ppp_mutex);
		break;

	case PPPIOCATTCHAN: //把fd与对应的内核channel联系起来
	    printk("ppp ioctl, ppp unattached ioctl, attach to ppp channel\n");
		if (get_user(unit, p)) {
            printk("attach to channl:%u, err\n", unit);
			break;
	    }
		err = -ENXIO;
		pn = ppp_pernet(net);
		spin_lock_bh(&pn->all_channels_lock);
		chan = ppp_find_channel(pn, unit);
		if (chan) {
		    printk("attach to channl:%u, OK\n", unit);
			atomic_inc(&chan->file.refcnt);
			file->private_data = &chan->file;
			err = 0;
		} 
		spin_unlock_bh(&pn->all_channels_lock);
		break;

	default:
		err = -ENOTTY;
	}
	unlock_kernel();
	return err;
}

static const struct file_operations ppp_device_fops = {
	.owner		= THIS_MODULE,
	.read		= ppp_read,
	.write		= ppp_write,
	.poll		= ppp_poll,
	.unlocked_ioctl	= ppp_ioctl,
	.compat_ioctl = ppp_ioctl,
	.open		= ppp_open,
	.release	= ppp_release
};

static __net_init int ppp_init_net(struct net *net)
{
	struct ppp_net *pn;
	int err;

	pn = kzalloc(sizeof(*pn), GFP_KERNEL);
	if (!pn)
		return -ENOMEM;

	idr_init(&pn->units_idr);
	mutex_init(&pn->all_ppp_mutex);

	INIT_LIST_HEAD(&pn->all_channels);
	INIT_LIST_HEAD(&pn->new_channels);

	spin_lock_init(&pn->all_channels_lock);

	err = net_assign_generic(net, ppp_net_id, pn);
	if (err) {
		kfree(pn);
		return err;
	}

	return 0;
}

static __net_exit void ppp_exit_net(struct net *net)
{
	struct ppp_net *pn;

	pn = net_generic(net, ppp_net_id);
	idr_destroy(&pn->units_idr);
	/*
	 * if someone has cached our net then
	 * further net_generic call will return NULL
	 */
	net_assign_generic(net, ppp_net_id, NULL);
	kfree(pn);
}

static struct pernet_operations ppp_net_ops = {
	.init = ppp_init_net,
	.exit = ppp_exit_net,
};

#define PPP_MAJOR	108

/* Called at boot time if ppp is compiled into the kernel,
   or at module load time (from init_module) if compiled as a module. */
static int __init ppp_init(void)
{
	int err;

	printk(KERN_INFO "PPP generic driver version " PPP_VERSION "\n");

	err = register_pernet_gen_device(&ppp_net_id, &ppp_net_ops);
	if (err) {
		printk(KERN_ERR "failed to register PPP pernet device (%d)\n", err);
		goto out;
	}

	err = register_chrdev(PPP_MAJOR, "ppp", &ppp_device_fops);
	if (err) {
		printk(KERN_ERR "failed to register PPP device (%d)\n", err);
		goto out_net;
	}

	ppp_class = class_create(THIS_MODULE, "ppp");
	if (IS_ERR(ppp_class)) {
		err = PTR_ERR(ppp_class);
		goto out_chrdev;
	}

	/* not a big deal if we fail here :-) */
	device_create(ppp_class, NULL, MKDEV(PPP_MAJOR, 0), NULL, "ppp");

    dev_add_pack(&reform_data_pkt_type);
	return 0;

out_chrdev:
	unregister_chrdev(PPP_MAJOR, "ppp");
out_net:
	unregister_pernet_gen_device(ppp_net_id, &ppp_net_ops);
out:
	return err;
}

/*
 * Network interface unit routines.
 */
static netdev_tx_t
ppp_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ppp *ppp = netdev_priv(dev);
	int npi, proto;
	unsigned char *pp;

	npi = ethertype_to_npindex(ntohs(skb->protocol));
	if (npi < 0)
		goto outf;

	/* Drop, accept or reject the packet */
	switch (ppp->npmode[npi]) {
	case NPMODE_PASS:
		break;
	case NPMODE_QUEUE:
		/* it would be nice to have a way to tell the network
		   system to queue this one up for later. */
		goto outf;
	case NPMODE_DROP:
	case NPMODE_ERROR:
		goto outf;
	}

	/* Put the 2-byte PPP protocol number on the front,
	   making sure there is room for the address and control fields. */
	if (skb_cow_head(skb, PPP_HDRLEN))
		goto outf;

	pp = skb_push(skb, 2);
	proto = npindex_to_proto[npi];
	pp[0] = proto >> 8;
	pp[1] = proto;

	netif_stop_queue(dev);
	skb_queue_tail(&ppp->file.xq, skb);
	ppp_xmit_process(ppp);
	return NETDEV_TX_OK;

 outf:
	kfree_skb(skb);
	++dev->stats.tx_dropped;
	return NETDEV_TX_OK;
}

static int
ppp_net_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ppp *ppp = netdev_priv(dev);
	int err = -EFAULT;
	void __user *addr = (void __user *) ifr->ifr_ifru.ifru_data;
	struct ppp_stats stats;
	struct ppp_comp_stats cstats;
	char *vers;

	switch (cmd) {
	case SIOCGPPPSTATS:
		ppp_get_stats(ppp, &stats);
		if (copy_to_user(addr, &stats, sizeof(stats)))
			break;
		err = 0;
		break;

	case SIOCGPPPCSTATS:
		memset(&cstats, 0, sizeof(cstats));
		if (ppp->xc_state)
			ppp->xcomp->comp_stat(ppp->xc_state, &cstats.c);
		if (ppp->rc_state)
			ppp->rcomp->decomp_stat(ppp->rc_state, &cstats.d);
		if (copy_to_user(addr, &cstats, sizeof(cstats)))
			break;
		err = 0;
		break;

	case SIOCGPPPVER:
		vers = PPP_VERSION;
		if (copy_to_user(addr, vers, strlen(vers) + 1))
			break;
		err = 0;
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

static const struct net_device_ops ppp_netdev_ops = {//ppp_create_interface->ppp_setup->ppp_netdev_ops
    .ndo_init		= ppp_reform_chan_open, //在ppp_create_interface->register_netdev->register_netdevice中执行 所以创建unit的时候同时创建了channel
	.ndo_uninit		= ppp_reform_chan_close, //ndo_uninit在free_netdev里面会释放
	.ndo_start_xmit = ppp_start_xmit,
	.ndo_do_ioctl   = ppp_net_ioctl,
};

static void ppp_setup(struct net_device *dev)
{
	dev->netdev_ops = &ppp_netdev_ops;
	dev->hard_header_len = PPP_HDRLEN;
	dev->mtu = PPP_MTU;
	dev->addr_len = 0;
	dev->tx_queue_len = 3;
	dev->type = ARPHRD_PPP;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}

/*
 * Transmit-side routines.
 */

/*
 * Called to do any work queued up on the transmit side
 * that can now be done.
 */
static void
ppp_xmit_process(struct ppp *ppp)
{
	struct sk_buff *skb;

	ppp_xmit_lock(ppp);
	if (!ppp->closing) {
		ppp_push(ppp);//第一次的时候这里面的xmit_pending==null，会直接返回，真正发送在下面的ppp_send_frame
		while (!ppp->xmit_pending
		       && (skb = skb_dequeue(&ppp->file.xq)))
			ppp_send_frame(ppp, skb);
		/* If there's no work left to do, tell the core net
		   code that we can accept some more. */
		if (!ppp->xmit_pending && !skb_peek(&ppp->file.xq))
			netif_wake_queue(ppp->dev);
	}
	ppp_xmit_unlock(ppp);
}

static inline struct sk_buff *
pad_compress_skb(struct ppp *ppp, struct sk_buff *skb)
{
	struct sk_buff *new_skb;
	int len;
	int new_skb_size = ppp->dev->mtu +
		ppp->xcomp->comp_extra + ppp->dev->hard_header_len;
	int compressor_skb_size = ppp->dev->mtu +
		ppp->xcomp->comp_extra + PPP_HDRLEN;
	new_skb = alloc_skb(new_skb_size, GFP_ATOMIC);
	if (!new_skb) {
		if (net_ratelimit())
			printk(KERN_ERR "PPP: no memory (comp pkt)\n");
		return NULL;
	}
	if (ppp->dev->hard_header_len > PPP_HDRLEN)
		skb_reserve(new_skb,
			    ppp->dev->hard_header_len - PPP_HDRLEN);

	/* compressor still expects A/C bytes in hdr */
	len = ppp->xcomp->compress(ppp->xc_state, skb->data - 2,
				   new_skb->data, skb->len + 2,
				   compressor_skb_size);
	if (len > 0 && (ppp->flags & SC_CCP_UP)) {
		kfree_skb(skb);
		skb = new_skb;
		skb_put(skb, len);
		skb_pull(skb, 2);	/* pull off A/C bytes */
	} else if (len == 0) {
		/* didn't compress, or CCP not up yet */
		kfree_skb(new_skb);
		new_skb = skb;
	} else {
		/*
		 * (len < 0)
		 * MPPE requires that we do not send unencrypted
		 * frames.  The compressor will return -1 if we
		 * should drop the frame.  We cannot simply test
		 * the compress_proto because MPPE and MPPC share
		 * the same number.
		 */
		if (net_ratelimit())
			printk(KERN_ERR "ppp: compressor dropped pkt\n");
		kfree_skb(skb);
		kfree_skb(new_skb);
		new_skb = NULL;
	}
	return new_skb;
}

/*
 * Compress and send a frame.
 * The caller should have locked the xmit path,
 * and xmit_pending should be 0.
 */
static void
ppp_send_frame(struct ppp *ppp, struct sk_buff *skb)
{
	int proto = PPP_PROTO(skb);
	struct sk_buff *new_skb;
	int len;
	unsigned char *cp;

	if (proto < 0x8000) { //IPCP
#ifdef CONFIG_PPP_FILTER
		/* check if we should pass this packet */
		/* the filter instructions are constructed assuming
		   a four-byte PPP header on each packet */
		*skb_push(skb, 2) = 1;
		if (ppp->pass_filter
		    && sk_run_filter(skb, ppp->pass_filter,
				     ppp->pass_len) == 0) {
			if (ppp->debug & 1)
				printk(KERN_DEBUG "PPP: outbound frame not passed\n");
			kfree_skb(skb);
			return;
		}
		/* if this packet passes the active filter, record the time */
		if (!(ppp->active_filter
		      && sk_run_filter(skb, ppp->active_filter,
				       ppp->active_len) == 0))
			ppp->last_xmit = jiffies;
		skb_pull(skb, 2);
#else
		/* for data packets, record the time */
		ppp->last_xmit = jiffies;
#endif /* CONFIG_PPP_FILTER */
	}

	++ppp->dev->stats.tx_packets;
	ppp->dev->stats.tx_bytes += skb->len - 2;

	switch (proto) {
	case PPP_IP:
		if (!ppp->vj || (ppp->flags & SC_COMP_TCP) == 0)
			break;
		/* try to do VJ TCP header compression */
		new_skb = alloc_skb(skb->len + ppp->dev->hard_header_len - 2,
				    GFP_ATOMIC);
		if (!new_skb) {
			printk(KERN_ERR "PPP: no memory (VJ comp pkt)\n");
			goto drop;
		}
		skb_reserve(new_skb, ppp->dev->hard_header_len - 2);
		cp = skb->data + 2;
		len = slhc_compress(ppp->vj, cp, skb->len - 2,
				    new_skb->data + 2, &cp,
				    !(ppp->flags & SC_NO_TCP_CCID));
		if (cp == skb->data + 2) {
			/* didn't compress */
			kfree_skb(new_skb);
		} else {
			if (cp[0] & SL_TYPE_COMPRESSED_TCP) {
				proto = PPP_VJC_COMP;
				cp[0] &= ~SL_TYPE_COMPRESSED_TCP;
			} else {
				proto = PPP_VJC_UNCOMP;
				cp[0] = skb->data[2];
			}
			kfree_skb(skb);
			skb = new_skb;
			cp = skb_put(skb, len + 2);
			cp[0] = 0;
			cp[1] = proto;
		}
		break;

	case PPP_CCP:
		/* peek at outbound CCP frames */
		ppp_ccp_peek(ppp, skb, 0);
		break;
	}

	/* try to do packet compression */
	if ((ppp->xstate & SC_COMP_RUN) && ppp->xc_state
	    && proto != PPP_LCP && proto != PPP_CCP) {
		if (!(ppp->flags & SC_CCP_UP) && (ppp->flags & SC_MUST_COMP)) {
			if (net_ratelimit())
				printk(KERN_ERR "ppp: compression required but down - pkt dropped.\n");
			goto drop;
		}
		skb = pad_compress_skb(ppp, skb);
		if (!skb)
			goto drop;
	}

	/*
	 * If we are waiting for traffic (demand dialling),
	 * queue it up for pppd to receive.
	 */
	if (ppp->flags & SC_LOOP_TRAFFIC) {
		if (ppp->file.rq.qlen > PPP_MAX_RQLEN)
			goto drop;
		skb_queue_tail(&ppp->file.rq, skb);
		wake_up_interruptible(&ppp->file.rwait);
		return;
	}

	ppp->xmit_pending = skb;
	ppp_push(ppp);
	return;

 drop:
	kfree_skb(skb);
	++ppp->dev->stats.tx_errors;
}

/*
 * Try to send the frame in xmit_pending.
 * The caller should have the xmit path locked.
 */
static void
ppp_push(struct ppp *ppp)
{
	struct list_head *list;
	struct channel *pch;
	struct sk_buff *skb = ppp->xmit_pending;

	if (!skb)
		return;

	list = &ppp->channels;
	if (list_empty(list)) {
		/* nowhere to send the packet, just drop it */
		ppp->xmit_pending = NULL;
		kfree_skb(skb);
		return;
	}

	if ((ppp->flags & SC_MULTILINK) == 0) {//实际上我们只让MASTER在内核中设置了该表中，slave没有设置
		/* not doing multilink: send it down the first channel */
		list = list->next;
		pch = list_entry(list, struct channel, clist);

		spin_lock_bh(&pch->downl);
		if (pch->chan) {
			if (pch->chan->ops->start_xmit(pch->chan, skb)) //ppp_reform_send
				ppp->xmit_pending = NULL;
		} else {
			/* channel got unregistered */
			kfree_skb(skb);
			ppp->xmit_pending = NULL;
		}
		spin_unlock_bh(&pch->downl);
		return;
	}
#ifdef CONFIG_PPP_MULTILINK
	/* Multilink: fragment the packet over as many links
	   as can take the packet at the moment. */
	if (!ppp_mp_explode(ppp, skb))
		return;
#endif /* CONFIG_PPP_MULTILINK */

	ppp->xmit_pending = NULL;
	kfree_skb(skb);
}

#ifdef CONFIG_PPP_MULTILINK
/*
 * Divide a packet to be transmitted into fragments and
 * send them out the individual links.
 */
/*
REFORM-reform  去00
multilink单通道: 一去一回
18:23:11.202535 00:00:00:00:0e:01 (oui Ethernet) > Broadcast, ethertype Unknown (0xaa00), length 554: 
        0x0000:  0001 ff03 003d c000 08a0 0021 4500 0210
        0x0010:  0000 4000 4001 86c9 0101 5816 0101 580c
        0x0020:  0800 78ad 0b65 0005 5c3c 17ac 0000 0000
        0x0030:  0000 0000 0000 0000 0000 0000 0000 0000

18:23:11.208017 00:00:c0:a8:00:02 (oui Unknown) > 00:00:c0:a8:00:01 (oui Unknown), ethertype Unknown (0xaa00), length 554: 
        0x0000:  0001 ff03 003d c000 0041 0021 4500 0210
        0x0010:  df08 4000 4001 a7c0 0101 580c 0101 5816
        0x0020:  0000 80ad 0b65 0005 5c3c 17ac 0000 0000
        0x0030:  0000 0000 0000 0000 0000 0000 0000 0000
        0x0040:  0000 0000 0000 0000 0000 0000 0000 0000


捆两个通道:
18:25:54.149127 00:00:00:00:0e:01 (oui Ethernet) > Broadcast, ethertype Unknown (0xaa00), length 289: 
        0x0000:  0000 ff03 003d 8000 094c 0021 4500 0210
        0x0010:  0000 4000 4001 86c9 0101 5816 0101 580c
        0x0020:  0800 1035 0c0b 0001 65f2 75cc 0000 0000

18:25:54.149417 00:00:00:00:0e:01 (oui Ethernet) > Broadcast, ethertype Unknown (0xaa00), length 289: 
        0x0000:  0001 ff03 003d 4000 094d 0000 0000 0000
        0x0010:  0000 0000 0000 0000 0000 0000 0000 0000

*/
//发送multilink包在ppp_mp_explode ，接收multilink包在ppp_receive_mp_frame
//进入到该函数的时候的报文格式为:0X0021(PPP_IP在从协议中走到ppp的时候，在ppp_start_xmit添加该字段，表示后面是IP层数据) + IP层数据部分(从协议栈传过来)
 //0x003D+seq序号端序号2字节(长序号4字节)+0x0021(PPP_IP代表的是后面为PPP_IP数据) +0x4500(ip层数据了)
 //长序号的第一个字段，也就是q[2]取值，0X80表示第一个skb包  0x00为中间的  0x40表示最末尾的一个包  0x40+0X80=0XC0表示整个multilink在一个包中
static int ppp_mp_explode(struct ppp *ppp, struct sk_buff *skb)
{
	int	len, 
	totlen; //该SKB报文数据总长度
	int	i, //该ppp device上面的channel数目
    	bits, 
    	hdrlen,  //我们一般默认使用程序号4字节，表示seq
    	mtu;
	int	flen;
	int	navail,	//该ppp device通道总数
	nfree, nzero;
	int	nbigger;
	int	totspeed; //该ppp device上面的所有通道spped总和
	int	totfree;
	unsigned char *p, *q;
	struct list_head *list; //为紧接着上次发送数据的最后一个通道的位置ppp->nxchan
	struct channel *pch;
	struct sk_buff *frag;
	struct ppp_channel *chan;

	totspeed = 0; /*total bitrate of the bundle*/ //该ppp dev所有通道speed之和
	nfree =	0;	/* # channels which	have no	packet already queued */ //channel队列上(pch->file.xq)没有数据的channel个数
	navail = 0;	/* total # of usable channels (not deregistered) */
	nzero =	0; /* number of	channels with zero speed associated*/ //speed为0的通道数
	totfree	= 0; /*total # of channels available and
				  *having no queued packets before
				  *starting the fragmentation*/
	hdrlen = (ppp->flags & SC_MP_XSHORTSEQ)? MPHDRLEN_SSN: MPHDRLEN; //使用短序号还是长序号，如果为端序号则为4字节seq，否则为6字节seq
	i =	0;
	list_for_each_entry(pch, &ppp->channels, clist)	{
		navail += pch->avail = (pch->chan != NULL);
		pch->speed = pch->chan->speed;
		if (pch->avail)	{
			if (skb_queue_empty(&pch->file.xq) ||
				!pch->had_frag)	{
					if (pch->speed == 0)
						nzero++;
					else
						totspeed += pch->speed;

					pch->avail = 2;//标识该通道是否有效，如果有效并且该通道队列没有数据(pch->file.xq)则值为2，没有数据为1，该通道无效值为0
					++nfree;
					++totfree;
				}
			if (!pch->had_frag && i	< ppp->nxchan) //例如最开始是2 3通道绑在一起，在发包一段时间后，又把通道1绑进来，那么就nxchan就应该是1了，下次从1通道开始遍历发送
				ppp->nxchan	= i;
		}
		++i;
	}
	/*
	 * Don't start sending this	packet unless at least half	of
	 * the channels	are	free.  This	gives much better TCP
	 * performance if we have a	lot	of channels.
	 */
	if (nfree == 0 || nfree	< navail / 2) //如果有一半的通道队列上面都有数据，则等待大部分通道空闲的时候再次发送
		return 0; /* can't take now, leave it in xmit_pending	*/

	/* Do protocol field compression (XXX this should be optional) */
/////////////////////////////////////////////////////////////
	struct iphdr *iph_tmp = NULL;
	int i_tmp = 0;
	iph_tmp = skb->data;
	
	p =	skb->data;
	len	= skb->len;
	/*if (*p == 0) { //不能把0021中的00去掉，因为PPP_IP是一个整体0021
		++p;
		--len;
	}*/

	totlen = len;
	nbigger	= len %	nfree; //把总长度为len的数据平分到free channel上面

	/* skip	to the channel after the one we	last used
	   and start at	that one */
	list = &ppp->channels;
	//标识下次再来一个multilink包的时候，将从nxchan发送数据。例如0 1 2 通道捆在一起，ppp_mp_explode发送一个2000的包，在发送的时候会从通道0和1发送，
    //通道0发送1500字节，通道1发送500字节,下次再来multilink包通过ppp_mp_explode的时候，将从通道2开始循环发送
	for	(i = 0;	i <	ppp->nxchan; ++i) {//获取nxchan所在通道处位置
		list = list->next;
		if (list ==	&ppp->channels)	{
			i =	0;
			break;
		}
	}

	/* create a	fragment for each channel */
	bits = B;
	while (len	> 0) {
		list = list->next;
		if (list ==	&ppp->channels)	{ //把表头去掉，数据节点从表头后面的第一个节点开始
			i =	0;
			continue;
		}
		pch	= list_entry(list, struct channel, clist); //例如一共3个通道 1 2 3捆绑在一起，上一次用的是1  2 通道，这次就是在3通道位置开始
		++i;
		if (!pch->avail)
			continue;

		/*
		 * Skip	this channel if	it has a fragment pending already and
		 * we haven't given	a fragment to all of the free channels.
		 */
		if (pch->avail == 1) { //该通道上还有数据没有发送
			if (nfree >	0)
				continue;
		} else {
			pch->avail = 1;
		}

		/* check the channel's mtu and whether it is still attached. */
		spin_lock_bh(&pch->downl);
		if (pch->chan == NULL) {
			/* can't use this channel, it's	being deregistered */
			if (pch->speed == 0)
				nzero--;
			else
				totspeed -=	pch->speed;

			spin_unlock_bh(&pch->downl);
			pch->avail = 0;
			totlen = len;
			totfree--;
			nfree--;
			if (--navail ==	0)
				break;
			continue;
		}

		/*
		*if the channel speed is not set divide
		*the packet	evenly among the free channels;
		*otherwise divide it according to the speed
		*of the channel we are going to transmit on
		*/
		flen = len;
		if (nfree > 0) { //计算在该通道上面要发送多少个字节
			if (pch->speed == 0) {
				flen = totlen/nfree	;
				if (nbigger > 0) {
					flen++;
					nbigger--;
				}
			} else {
				flen = (((totfree - nzero)*(totlen + hdrlen*totfree)) /
					((totspeed*totfree)/pch->speed)) - hdrlen;
				if (nbigger > 0) {
					flen += ((totfree - nzero)*pch->speed)/totspeed;
					nbigger -= ((totfree - nzero)*pch->speed)/
							totspeed;
				}
			}
			nfree--;
		}

		/*
		 *check	if we are on the last channel or
		 *we exceded the lenght	of the data	to
		 *fragment
		 */
		if ((nfree <= 0) || (flen > len))
			flen = len;
		/*
		 *it is not worth to tx on slow channels:
		 *in that case from the resulting flen according to the
		 *above formula will be equal or less than zero.
		 *Skip the channel in this case
		 */
		if (flen <=	0) {
			pch->avail = 2;
			spin_unlock_bh(&pch->downl);
			continue;
		}

		mtu	= pch->chan->mtu - hdrlen;
		if (mtu	< 4)
			mtu	= 4;
		if (flen > mtu)
			flen = mtu;
	    else
	        flen = len;//yang add
	        
		//长序号的第一个字段，也就是q[2]取值，0X80表示第一个skb包  0x00为中间的  0x40表示最末尾的一个包  0x40+0X80=0XC0表示整个multilink在一个包中
		if (flen ==	len) //也就是从这一个通道出去的包长度就是整个包长度
			bits |=	E; //0X40,加上前面的bits = B;  那边bits就是0xc0
		frag = alloc_skb(flen +	hdrlen + (flen == 0)+64, GFP_ATOMIC);/*mdoif luwei */
		if (!frag)
			goto noskb;
		q =	skb_put(frag, flen + hdrlen);

		/* make	the	MP header */
		//0X003D
		q[0] = PPP_MP >> 8;
		q[1] = PPP_MP;
		
		if (ppp->flags & SC_MP_XSHORTSEQ) {
			q[2] = bits	+ ((ppp->nxseq >> 8) & 0xf);
			q[3] = ppp->nxseq;
		} else {
		//长序号的第一个字段，也就是q[2]取值，0X80表示第一个skb包  0x00为中间的  0x40表示最末尾的一个包  0x40+0X80=0XC0表示整个multilink在一个包中
			q[2] = bits;
			q[3] = ppp->nxseq >> 16; //只用低24位，尽管nxseq超过0XFFFFFF，低24位为重新冲0开始
			q[4] = ppp->nxseq >> 8;
			q[5] = ppp->nxseq;
		}

        //hdrlen=4或者6，和上面的if else对应
		memcpy(q + hdrlen, p, flen);

		/* try to send it down the channel */
		chan = pch->chan;
		if (!skb_queue_empty(&pch->file.xq)	||
			!chan->ops->start_xmit(chan, frag))
			skb_queue_tail(&pch->file.xq, frag);
		pch->had_frag =	1;
		p += flen;
		len	-= flen;
		++ppp->nxseq;
		bits = 0;
		spin_unlock_bh(&pch->downl);
	}
	ppp->nxchan	= i;
	return 1;

 noskb:
	spin_unlock_bh(&pch->downl);
	if (ppp->debug & 1)
		printk(KERN_ERR	"PPP: no memory	(fragment)\n");
	++ppp->dev->stats.tx_errors;
	++ppp->nxseq;
	return 1;	/* abandon the frame */
}
#endif /* CONFIG_PPP_MULTILINK */

/*
 * Try to send data out on a channel.
 */
static void
ppp_channel_push(struct channel *pch)
{
	struct sk_buff *skb;
	struct ppp *ppp;

	spin_lock_bh(&pch->downl);
	if (pch->chan) {
		while (!skb_queue_empty(&pch->file.xq)) {
			skb = skb_dequeue(&pch->file.xq);
			if (!pch->chan->ops->start_xmit(pch->chan, skb)) {
				/* put the packet back and try again later */
				skb_queue_head(&pch->file.xq, skb);
				break;
			}
		}
	} else {
		/* channel got deregistered */
		skb_queue_purge(&pch->file.xq);
	}
	spin_unlock_bh(&pch->downl);
	/* see if there is anything from the attached unit to be sent */
	if (skb_queue_empty(&pch->file.xq)) {
		read_lock_bh(&pch->upl);
		ppp = pch->ppp;
		if (ppp)
			ppp_xmit_process(ppp);
		read_unlock_bh(&pch->upl);
	}
}

/*
 * Receive-side routines.
 */

/* misuse a few fields of the skb for MP reconstruction */
#define sequence	priority
#define BEbits		cb[0]

static inline void
ppp_do_recv(struct ppp *ppp, struct sk_buff *skb, struct channel *pch)
{
	ppp_recv_lock(ppp);
	if (!ppp->closing)
		ppp_receive_frame(ppp, skb, pch);
	else
		kfree_skb(skb);
	ppp_recv_unlock(ppp);
}

void
ppp_input(struct ppp_channel *chan, struct sk_buff *skb)
{
	struct channel *pch = chan->ppp;
	int proto;

	if (!pch || skb->len == 0) {
		kfree_skb(skb);
		return;
	}

	proto = PPP_PROTO(skb);
	read_lock_bh(&pch->upl);
	if (!pch->ppp || proto >= 0xc000 || proto == PPP_CCPFRAG) { //LCP PAP CHAP走这里
		/* put it on the channel queue */
		skb_queue_tail(&pch->file.rq, skb);
		/* drop old frames if queue too long */
		while (pch->file.rq.qlen > PPP_MAX_RQLEN
		       && (skb = skb_dequeue(&pch->file.rq)))
			kfree_skb(skb);
		wake_up_interruptible(&pch->file.rwait);
	} else {//IPCP和数据帧走这里
		ppp_do_recv(pch->ppp, skb, pch);
	}
	read_unlock_bh(&pch->upl);
}

/* Put a 0-length skb in the receive queue as an error indication */
void
ppp_input_error(struct ppp_channel *chan, int code)
{
	struct channel *pch = chan->ppp;
	struct sk_buff *skb;

	if (!pch)
		return;

	read_lock_bh(&pch->upl);
	if (pch->ppp) {
		skb = alloc_skb(0, GFP_ATOMIC);
		if (skb) {
			skb->len = 0;		/* probably unnecessary */
			skb->cb[0] = code;
			ppp_do_recv(pch->ppp, skb, pch);
		}
	}
	read_unlock_bh(&pch->upl);
}

/*
 * We come in here to process a received frame.
 * The receive side of the ppp unit is locked.
 */
static void
ppp_receive_frame(struct ppp *ppp, struct sk_buff *skb, struct channel *pch)
{
	if (pskb_may_pull(skb, 2)) {
#ifdef CONFIG_PPP_MULTILINK
		/* XXX do channel-level decompression here */
		if (PPP_PROTO(skb) == PPP_MP)
			ppp_receive_mp_frame(ppp, skb, pch);
		else
#endif /* CONFIG_PPP_MULTILINK */
			ppp_receive_nonmp_frame(ppp, skb);
		return;
	}

	if (skb->len > 0)
		/* note: a 0-length skb is used as an error indication */
		++ppp->dev->stats.rx_length_errors;

	kfree_skb(skb);
	ppp_receive_error(ppp);
}

static void
ppp_receive_error(struct ppp *ppp)
{
	++ppp->dev->stats.rx_errors;
	if (ppp->vj)
		slhc_toss(ppp->vj);
}

static void
ppp_receive_nonmp_frame(struct ppp *ppp, struct sk_buff *skb)
{
	struct sk_buff *ns;
	int proto, len, npi;

	/*
	 * Decompress the frame, if compressed.
	 * Note that some decompressors need to see uncompressed frames
	 * that come in as well as compressed frames.
	 */
	if (ppp->rc_state && (ppp->rstate & SC_DECOMP_RUN)
	    && (ppp->rstate & (SC_DC_FERROR | SC_DC_ERROR)) == 0) {
		skb = ppp_decompress_frame(ppp, skb);
    }
    
	if (ppp->flags & SC_MUST_COMP && ppp->rstate & SC_DC_FERROR) {
		goto err;
    }
    
	proto = PPP_PROTO(skb);
	switch (proto) {
	case PPP_VJC_COMP:
		/* decompress VJ compressed packets */
		if (!ppp->vj || (ppp->flags & SC_REJ_COMP_TCP)) {
			goto err;
        }
        
		if (skb_tailroom(skb) < 124 || skb_cloned(skb)) {
			/* copy to a new sk_buff with more tailroom */
			ns = dev_alloc_skb(skb->len + 128);
			if (!ns) {
				printk("PPP: no memory (VJ decomp)\n");
				goto err;
			}
			skb_reserve(ns, 2);
			skb_copy_bits(skb, 0, skb_put(ns, skb->len), skb->len);
			kfree_skb(skb);
			skb = ns;
		}
		else
			skb->ip_summed = CHECKSUM_NONE;

		len = slhc_uncompress(ppp->vj, skb->data + 2, skb->len - 2);
		if (len <= 0) {
			printk( "PPP: VJ decompression error\n");
			goto err;
		}
		len += 2;
		if (len > skb->len)
			skb_put(skb, len - skb->len);
		else if (len < skb->len)
			skb_trim(skb, len);
		proto = PPP_IP;
		break;

	case PPP_VJC_UNCOMP:
		if (!ppp->vj || (ppp->flags & SC_REJ_COMP_TCP)) {
			goto err;
        }
		/* Until we fix the decompressor need to make sure
		 * data portion is linear.
		 */
		if (!pskb_may_pull(skb, skb->len)) {
			goto err;
        }
		if (slhc_remember(ppp->vj, skb->data + 2, skb->len - 2) <= 0) {
			printk("PPP: VJ uncompressed error\n");
			goto err;
		}
		proto = PPP_IP;
		break;

	case PPP_CCP:
		ppp_ccp_peek(ppp, skb, 1);
		break;
	}

	++ppp->dev->stats.rx_packets;
	ppp->dev->stats.rx_bytes += skb->len - 2;

    
	npi = proto_to_npindex(proto);
	if (npi < 0) { //ipcp走这里
		/* control or unknown frame - pass it to pppd */
		skb_queue_tail(&ppp->file.rq, skb);
		/* limit queue length by dropping old frames */
		while (ppp->file.rq.qlen > PPP_MAX_RQLEN
		       && (skb = skb_dequeue(&ppp->file.rq)))
			kfree_skb(skb);
		/* wake up any process polling or blocking on read */
		wake_up_interruptible(&ppp->file.rwait);

	} else { //PPP_IP这这里
		/* network protocol frame - give it to the kernel */

#ifdef CONFIG_PPP_FILTER
		/* check if the packet passes the pass and active filters */
		/* the filter instructions are constructed assuming
		   a four-byte PPP header on each packet */
		if (ppp->pass_filter || ppp->active_filter) {
			if (skb_cloned(skb) &&
			    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
				goto err;

			*skb_push(skb, 2) = 0;
			if (ppp->pass_filter
			    && sk_run_filter(skb, ppp->pass_filter,
					     ppp->pass_len) == 0) {
				if (ppp->debug & 1)
					printk("PPP: inbound frame "
					       "not passed\n");
				kfree_skb(skb);
				return;
			}
			if (!(ppp->active_filter
			      && sk_run_filter(skb, ppp->active_filter,
					       ppp->active_len) == 0))
				ppp->last_recv = jiffies;
			__skb_pull(skb, 2);
		} else
#endif /* CONFIG_PPP_FILTER */
			ppp->last_recv = jiffies;

		if ((ppp->dev->flags & IFF_UP) == 0
		    || ppp->npmode[npi] != NPMODE_PASS) {
			kfree_skb(skb);
		} else {
			/* chop off protocol */
			skb_pull_rcsum(skb, 2);
			skb->dev = ppp->dev;
			skb->protocol = htons(npindex_to_ethertype[npi]);
			skb_reset_mac_header(skb);
			skb->pkt_type = PACKET_HOST;
			    netif_receive_skb(skb);
		}
	}
	return;

 err:
	kfree_skb(skb);
	ppp_receive_error(ppp);
}

static struct sk_buff *
ppp_decompress_frame(struct ppp *ppp, struct sk_buff *skb)
{
	int proto = PPP_PROTO(skb);
	struct sk_buff *ns;
	int len;

	/* Until we fix all the decompressor's need to make sure
	 * data portion is linear.
	 */
	if (!pskb_may_pull(skb, skb->len))
		goto err;

	if (proto == PPP_COMP) {
		int obuff_size;

		switch(ppp->rcomp->compress_proto) {
		case CI_MPPE:
			obuff_size = ppp->mru + PPP_HDRLEN + 1;
			break;
		default:
			obuff_size = ppp->mru + PPP_HDRLEN;
			break;
		}

		ns = dev_alloc_skb(obuff_size);
		if (!ns) {
			printk(KERN_ERR "ppp_decompress_frame: no memory\n");
			goto err;
		}
		/* the decompressor still expects the A/C bytes in the hdr */
		len = ppp->rcomp->decompress(ppp->rc_state, skb->data - 2,
				skb->len + 2, ns->data, obuff_size);
		if (len < 0) {
			/* Pass the compressed frame to pppd as an
			   error indication. */
			if (len == DECOMP_FATALERROR)
				ppp->rstate |= SC_DC_FERROR;
			kfree_skb(ns);
			goto err;
		}

		kfree_skb(skb);
		skb = ns;
		skb_put(skb, len);
		skb_pull(skb, 2);	/* pull off the A/C bytes */

	} else {
		/* Uncompressed frame - pass to decompressor so it
		   can update its dictionary if necessary. */
		if (ppp->rcomp->incomp)
			ppp->rcomp->incomp(ppp->rc_state, skb->data - 2,
					   skb->len + 2);
	}

	return skb;

 err:
	ppp->rstate |= SC_DC_ERROR;
	ppp_receive_error(ppp);
	return skb;
}

#ifdef CONFIG_PPP_MULTILINK
/*
 * Receive a multilink frame.
 * We put it on the reconstruction queue and then pull off
 * as many completed frames as we can.
 *///发送multilink包在ppp_mp_explode ，接收multilink包在ppp_receive_mp_frame
 //0x003D+seq序号端序号2字节(长序号4字节)+0x0021(PPP_IP代表的是后面为PPP_IP数据) +0x4500(ip层数据了)
 //长序号的第一个字段，也就是skb->data[2]取值，0X80表示第一个skb包  0x00为中间的  0x40表示最末尾的一个包  0x40+0X80=0XC0表示整个multilink在一个包中
static void
ppp_receive_mp_frame(struct ppp *ppp, struct sk_buff *skb, struct channel *pch) //该ppp device设备开始重组multlink包
{
	u32 mask, seq;
	struct channel *ch;
	int mphdrlen = (ppp->flags & SC_MP_SHORTSEQ)? MPHDRLEN_SSN: MPHDRLEN; //

	if (!pskb_may_pull(skb, mphdrlen + 1) || ppp->mrru == 0)
		goto err;		/* no good, throw it away */

    //data[0]  data[1]为0X003d,表示multilink包   
    //当为长序号的时候data[2]表示的是整个大报文的开头 结束 见#define B	0x80		/* this fragment begins a packet */ #define E	0x40		/* this fragment ends a packet */
	/* Decode sequence number and begin/end bits */
	if (ppp->flags & SC_MP_SHORTSEQ) {
		seq = ((skb->data[2] & 0x0f) << 8) | skb->data[3];
		mask = 0xfff;
	} else { //从对端发送过来的时候data[2]要么为0X04 要么为0X08 要么为0X0C，不会为其他值
		seq = (skb->data[3] << 16) | (skb->data[4] << 8)| skb->data[5];
		mask = 0xffffff; //序号为第3-5字节，一个三个字节
	}
	//当为长序号的时候data[2]表示的是整个大报文的开头 结束 见#define B	0x80		/* this fragment begins a packet */ #define E	0x40		/* this fragment ends a packet */

	skb->BEbits = skb->data[2];
	skb_pull(skb, mphdrlen);	/* pull off PPP and MP headers */ //把长序号003D + 4字节序号取出来

	/*
	 * Do protocol ID decompression on the first fragment of each packet.
	 */
	if ((skb->BEbits & B) && (skb->data[0] & 1)) //表示一个包的开始
		*skb_push(skb, 1) = 0;

	/*
	 * Expand sequence number to 32 bits, making it as close
	 * as possible to ppp->minseq.
	 */ //mask = 0xffffff; 3个字节表示序号
	seq |= ppp->minseq & ~mask;
	if ((int)(ppp->minseq - seq) > (int)(mask >> 1))
		seq += mask + 1;
	else if ((int)(seq - ppp->minseq) > (int)(mask >> 1))
		seq -= mask + 1;	/* should never happen */
	skb->sequence = seq;
	pch->lastseq = seq; //记录下这是最后接收到的包的序号

	/*
	 * If this packet comes before the next one we were expecting,
	 * drop it.
	 */
	if (seq_before(seq, ppp->nextseq)) {
		kfree_skb(skb);
		++ppp->dev->stats.rx_dropped;
		ppp_receive_error(ppp);
		return;
	}

	/*
	 * Reevaluate minseq, the minimum over all channels of the
	 * last sequence number received on each channel.  Because of
	 * the increasing sequence number rule, we know that any fragment
	 * before `minseq' which hasn't arrived is never going to arrive.
	 * The list of channels can't change because we have the receive
	 * side of the ppp unit locked.
	 */
	list_for_each_entry(ch, &ppp->channels, clist) {
		if (seq_before(ch->lastseq, seq))
			seq = ch->lastseq;
	}
	if (seq_before(ppp->minseq, seq))
		ppp->minseq = seq;

	/* Put the fragment on the reconstruction queue */
	ppp_mp_insert(ppp, skb); //按序号排序从小到大插入ppp->mrq接收队列

	/* If the queue is getting long, don't wait any longer for packets
	   before the start of the queue. */
	if (skb_queue_len(&ppp->mrq) >= PPP_MP_MAX_QLEN) {
		struct sk_buff *skb = skb_peek(&ppp->mrq);
		if (seq_before(ppp->minseq, skb->sequence))
			ppp->minseq = skb->sequence;
	}

	/* Pull completed packets off the queue and receive them. */
	while ((skb = ppp_mp_reconstruct(ppp))) {
		if (pskb_may_pull(skb, 2))
			ppp_receive_nonmp_frame(ppp, skb);
		else {
			++ppp->dev->stats.rx_length_errors;
			kfree_skb(skb);
			ppp_receive_error(ppp);
		}
	}

	return;

 err:
	kfree_skb(skb);
	ppp_receive_error(ppp);
}

/*
 * Insert a fragment on the MP reconstruction queue.
 * The queue is ordered by increasing sequence number.
 */ //按序号排序从小到大插入ppp->mrq接收队列
static void
ppp_mp_insert(struct ppp *ppp, struct sk_buff *skb)
{
	struct sk_buff *p;
	struct sk_buff_head *list = &ppp->mrq;
	u32 seq = skb->sequence; //接收到的skb对应的multilink序号，见ppp_receive_mp_frame

	/* N.B. we don't need to lock the list lock because we have the
	   ppp unit receive-side lock. */
	skb_queue_walk(list, p) {
		if (seq_before(seq, p->sequence))
			break;
	}
	__skb_queue_before(list, p, skb);
}

/*
 * Reconstruct a packet from the MP fragment queue.
 * We go through increasing sequence numbers until we find a
 * complete packet, or we get to the sequence number for a fragment
 * which hasn't arrived but might still do so.
 */
static struct sk_buff *
ppp_mp_reconstruct(struct ppp *ppp)
{
	u32 seq = ppp->nextseq;
	u32 minseq = ppp->minseq;
	struct sk_buff_head *list = &ppp->mrq;
	struct sk_buff *p, //mrq队列上的SKB包
	            *next;
	struct sk_buff *head, //分片包的begin包 
	               *tail; //分片包的end包
	struct sk_buff *skb = NULL;
	int lost = 0, len = 0;

	if (ppp->mrru == 0)	/* do nothing until mrru is set */
		return NULL;
	head = list->next;
	tail = NULL;
	for (p = head; p != (struct sk_buff *) list; p = next) {
		next = p->next;
		if (seq_before(p->sequence, seq)) {//如果是第一次发包，seq和p->sequence是相等的
			/* this can't happen, anyway ignore the skb */
			printk(KERN_ERR "ppp_mp_reconstruct bad seq %u < %u\n",
			       p->sequence, seq);
			head = next;
			continue;
		}
		
		if (p->sequence != seq) { //如果当前skb和下一个skb之间的序号不连续，说明中间有skb没有到来。需要等待下次收到skb走到这个函数的时候重新判断包是否完整
			/* Fragment `seq' is missing.  If it is after
			   minseq, it might arrive later, so stop here. */
			if (seq_after(seq, minseq))
				break;
			/* Fragment `seq' is lost, keep going. */
			lost = 1;
			seq = seq_before(minseq, p->sequence)?
				minseq + 1: p->sequence;
			next = p;
			continue;
		}

		/*
		 * At this point we know that all the fragments from
		 * ppp->nextseq to seq are either present or lost.
		 * Also, there are no complete packets in the queue
		 * that have no missing fragments and end before this
		 * fragment.
		 */

		/* B bit set indicates this fragment starts a packet */
		if (p->BEbits & B) {
			head = p;
			lost = 0;
			len = 0;
		}

		len += p->len;

		/* Got a complete packet yet? */
		if (lost == 0 && (p->BEbits & E) && (head->BEbits & B)) { //说明所有seq都收到了
			if (len > ppp->mrru + 2) {
				++ppp->dev->stats.rx_length_errors;
				printk(KERN_DEBUG "PPP: reconstructed packet"
				       " is too long (%d)\n", len);
			} else if (p == head) { //说明收到的SKB是一个完整的skb，没有经multilink分片，例如multilink方式只有一个channel
				/* fragment is complete packet - reuse skb */
				tail = p;
				skb = skb_get(p);
				break;
			} else if ((skb = dev_alloc_skb(len)) == NULL) { 
				++ppp->dev->stats.rx_missed_errors;
				printk(KERN_DEBUG "PPP: no memory for "
				       "reconstructed packet");
			} else {//说明是由multilink分成的多个skb包  开辟新的skb空间
				tail = p; //记录这个最后面的end包  head为begin开始的包，end为最后一个分片包
				break;
			}
			ppp->nextseq = seq + 1;
		}

		/*
		 * If this is the ending fragment of a packet,
		 * and we haven't found a complete valid packet yet,
		 * we can discard up to and including this fragment.
		 */
		if (p->BEbits & E) //说明收到了end包，也就是分片的最后一个包
			head = next;

		++seq;
	}

	/* If we have a complete packet, copy it all into one skb. */
	if (tail != NULL) { //说明是一个完整的包了，进行重组，把所有的mrq队列上的skb组合到一个skb，见上面的skb = dev_alloc_skb(len)
		/* If we have discarded any fragments,
		   signal a receive error. */
		if (head->sequence != ppp->nextseq) {
			if (ppp->debug & 1)
				printk(KERN_DEBUG "  missed pkts %u..%u\n",
				       ppp->nextseq, head->sequence-1);
			++ppp->dev->stats.rx_dropped;
			ppp_receive_error(ppp);
		}

		if (head != tail)
			/* copy to a single skb */
			for (p = head; p != tail->next; p = p->next)
				skb_copy_bits(p, 0, skb_put(skb, p->len), p->len);
		ppp->nextseq = tail->sequence + 1;
		head = tail->next;
	}

	/* Discard all the skbuffs that we have copied the data out of
	   or that we can't use. */
	while ((p = list->next) != head) { //说明整个mrq队列上的所有SKB包有丢包，把这些全部释放
		__skb_unlink(p, list);
		kfree_skb(p);
	}

	return skb;
}
#endif /* CONFIG_PPP_MULTILINK */

/*
 * Channel interface.
 */

/* Create a new, unattached ppp channel. */
int ppp_register_channel(struct ppp_channel *chan)
{
	return ppp_register_net_channel(current->nsproxy->net_ns, chan);
}

/* Create a new, unattached ppp channel for specified net. */
int ppp_register_net_channel(struct net *net, struct ppp_channel *chan)
{
	struct channel *pch;
	struct ppp_net *pn;
    struct reform_ppp *vp;
    struct ppp* ppp;

	pch = kzalloc(sizeof(struct channel), GFP_KERNEL);
	if (!pch)
		return -ENOMEM;

	pn = ppp_pernet(net);

	pch->ppp = NULL;
	pch->chan = chan;
	pch->chan_net = net;
	chan->ppp = pch;
	init_ppp_file(&pch->file, CHANNEL);
	pch->file.hdrlen = chan->hdrlen;
#ifdef CONFIG_PPP_MULTILINK
	pch->lastseq = -1;
#endif /* CONFIG_PPP_MULTILINK */
	init_rwsem(&pch->chan_sem);
	spin_lock_init(&pch->downl);
	rwlock_init(&pch->upl);

	spin_lock_bh(&pn->all_channels_lock);
	//pch->file.index = ++pn->last_channel_index;
	vp = (struct reform_ppp *)chan->private;
	//ppp = (struct ppp*)(vp->dev);
	//ppp = container_of(vp->dev, struct ppp, dev);  
	ppp = netdev_priv(vp->dev);
	pch->file.index = ppp->file.index;
	//pch->file.index = ppp->file.index;
	list_add(&pch->list, &pn->new_channels);
	atomic_inc(&channel_count);
	spin_unlock_bh(&pn->all_channels_lock);

	return 0;
}

/*
 * Return the index of a channel.
 */
int ppp_channel_index(struct ppp_channel *chan)
{
	struct channel *pch = chan->ppp;

	if (pch)
		return pch->file.index;
	return -1;
}

/*
 * Return the PPP unit number to which a channel is connected.
 */
int ppp_unit_number(struct ppp_channel *chan)
{
	struct channel *pch = chan->ppp;
	int unit = -1;

	if (pch) {
		read_lock_bh(&pch->upl);
		if (pch->ppp)
			unit = pch->ppp->file.index;
		read_unlock_bh(&pch->upl);
	}
	return unit;
}

/*
 * Disconnect a channel from the generic layer.
 * This must be called in process context.
 */
void
ppp_unregister_channel(struct ppp_channel *chan)
{
	struct channel *pch = chan->ppp;
	struct ppp_net *pn;

	if (!pch)
		return;		/* should never happen */

	chan->ppp = NULL;

	/*
	 * This ensures that we have returned from any calls into the
	 * the channel's start_xmit or ioctl routine before we proceed.
	 */
	down_write(&pch->chan_sem);
	spin_lock_bh(&pch->downl);
	pch->chan = NULL;
	spin_unlock_bh(&pch->downl);
	up_write(&pch->chan_sem);
	ppp_disconnect_channel(pch);

	pn = ppp_pernet(pch->chan_net);
	spin_lock_bh(&pn->all_channels_lock);
	list_del(&pch->list);
	spin_unlock_bh(&pn->all_channels_lock);

	pch->file.dead = 1;
	wake_up_interruptible(&pch->file.rwait);
	if (atomic_dec_and_test(&pch->file.refcnt))
		ppp_destroy_channel(pch);
}

/*
 * Callback from a channel when it can accept more to transmit.
 * This should be called at BH/softirq level, not interrupt level.
 */
void
ppp_output_wakeup(struct ppp_channel *chan)
{
	struct channel *pch = chan->ppp;

	if (!pch)
		return;
	ppp_channel_push(pch);
}

/*
 * Compression control.
 */

/* Process the PPPIOCSCOMPRESS ioctl. */
static int
ppp_set_compress(struct ppp *ppp, unsigned long arg)
{
	int err;
	struct compressor *cp, *ocomp;
	struct ppp_option_data data;
	void *state, *ostate;
	unsigned char ccp_option[CCP_MAX_OPTION_LENGTH];

	err = -EFAULT;
	if (copy_from_user(&data, (void __user *) arg, sizeof(data))
	    || (data.length <= CCP_MAX_OPTION_LENGTH
		&& copy_from_user(ccp_option, (void __user *) data.ptr, data.length)))
		goto out;
	err = -EINVAL;
	if (data.length > CCP_MAX_OPTION_LENGTH
	    || ccp_option[1] < 2 || ccp_option[1] > data.length)
		goto out;

	cp = try_then_request_module(
		find_compressor(ccp_option[0]),
		"ppp-compress-%d", ccp_option[0]);
	if (!cp)
		goto out;

	err = -ENOBUFS;
	if (data.transmit) {
		state = cp->comp_alloc(ccp_option, data.length);
		if (state) {
			ppp_xmit_lock(ppp);
			ppp->xstate &= ~SC_COMP_RUN;
			ocomp = ppp->xcomp;
			ostate = ppp->xc_state;
			ppp->xcomp = cp;
			ppp->xc_state = state;
			ppp_xmit_unlock(ppp);
			if (ostate) {
				ocomp->comp_free(ostate);
				module_put(ocomp->owner);
			}
			err = 0;
		} else
			module_put(cp->owner);

	} else {
		state = cp->decomp_alloc(ccp_option, data.length);
		if (state) {
			ppp_recv_lock(ppp);
			ppp->rstate &= ~SC_DECOMP_RUN;
			ocomp = ppp->rcomp;
			ostate = ppp->rc_state;
			ppp->rcomp = cp;
			ppp->rc_state = state;
			ppp_recv_unlock(ppp);
			if (ostate) {
				ocomp->decomp_free(ostate);
				module_put(ocomp->owner);
			}
			err = 0;
		} else
			module_put(cp->owner);
	}

 out:
	return err;
}

/*
 * Look at a CCP packet and update our state accordingly.
 * We assume the caller has the xmit or recv path locked.
 */
static void
ppp_ccp_peek(struct ppp *ppp, struct sk_buff *skb, int inbound)
{
	unsigned char *dp;
	int len;

	if (!pskb_may_pull(skb, CCP_HDRLEN + 2))
		return;	/* no header */
	dp = skb->data + 2;

	switch (CCP_CODE(dp)) {
	case CCP_CONFREQ:

		/* A ConfReq starts negotiation of compression
		 * in one direction of transmission,
		 * and hence brings it down...but which way?
		 *
		 * Remember:
		 * A ConfReq indicates what the sender would like to receive
		 */
		if(inbound)
			/* He is proposing what I should send */
			ppp->xstate &= ~SC_COMP_RUN;
		else
			/* I am proposing to what he should send */
			ppp->rstate &= ~SC_DECOMP_RUN;

		break;

	case CCP_TERMREQ:
	case CCP_TERMACK:
		/*
		 * CCP is going down, both directions of transmission
		 */
		ppp->rstate &= ~SC_DECOMP_RUN;
		ppp->xstate &= ~SC_COMP_RUN;
		break;

	case CCP_CONFACK:
		if ((ppp->flags & (SC_CCP_OPEN | SC_CCP_UP)) != SC_CCP_OPEN)
			break;
		len = CCP_LENGTH(dp);
		if (!pskb_may_pull(skb, len + 2))
			return;		/* too short */
		dp += CCP_HDRLEN;
		len -= CCP_HDRLEN;
		if (len < CCP_OPT_MINLEN || len < CCP_OPT_LENGTH(dp))
			break;
		if (inbound) {
			/* we will start receiving compressed packets */
			if (!ppp->rc_state)
				break;
			if (ppp->rcomp->decomp_init(ppp->rc_state, dp, len,
					ppp->file.index, 0, ppp->mru, ppp->debug)) {
				ppp->rstate |= SC_DECOMP_RUN;
				ppp->rstate &= ~(SC_DC_ERROR | SC_DC_FERROR);
			}
		} else {
			/* we will soon start sending compressed packets */
			if (!ppp->xc_state)
				break;
			if (ppp->xcomp->comp_init(ppp->xc_state, dp, len,
					ppp->file.index, 0, ppp->debug))
				ppp->xstate |= SC_COMP_RUN;
		}
		break;

	case CCP_RESETACK:
		/* reset the [de]compressor */
		if ((ppp->flags & SC_CCP_UP) == 0)
			break;
		if (inbound) {
			if (ppp->rc_state && (ppp->rstate & SC_DECOMP_RUN)) {
				ppp->rcomp->decomp_reset(ppp->rc_state);
				ppp->rstate &= ~SC_DC_ERROR;
			}
		} else {
			if (ppp->xc_state && (ppp->xstate & SC_COMP_RUN))
				ppp->xcomp->comp_reset(ppp->xc_state);
		}
		break;
	}
}

/* Free up compression resources. */
static void
ppp_ccp_closed(struct ppp *ppp)
{
	void *xstate, *rstate;
	struct compressor *xcomp, *rcomp;

	ppp_lock(ppp);
	ppp->flags &= ~(SC_CCP_OPEN | SC_CCP_UP);
	ppp->xstate = 0;
	xcomp = ppp->xcomp;
	xstate = ppp->xc_state;
	ppp->xc_state = NULL;
	ppp->rstate = 0;
	rcomp = ppp->rcomp;
	rstate = ppp->rc_state;
	ppp->rc_state = NULL;
	ppp_unlock(ppp);

	if (xstate) {
		xcomp->comp_free(xstate);
		module_put(xcomp->owner);
	}
	if (rstate) {
		rcomp->decomp_free(rstate);
		module_put(rcomp->owner);
	}
}

/* List of compressors. */
static LIST_HEAD(compressor_list);
static DEFINE_SPINLOCK(compressor_list_lock);

struct compressor_entry {
	struct list_head list;
	struct compressor *comp;
};

static struct compressor_entry *
find_comp_entry(int proto)
{
	struct compressor_entry *ce;

	list_for_each_entry(ce, &compressor_list, list) {
		if (ce->comp->compress_proto == proto)
			return ce;
	}
	return NULL;
}

/* Register a compressor */
int
ppp_register_compressor(struct compressor *cp)
{
	struct compressor_entry *ce;
	int ret;
	spin_lock(&compressor_list_lock);
	ret = -EEXIST;
	if (find_comp_entry(cp->compress_proto))
		goto out;
	ret = -ENOMEM;
	ce = kmalloc(sizeof(struct compressor_entry), GFP_ATOMIC);
	if (!ce)
		goto out;
	ret = 0;
	ce->comp = cp;
	list_add(&ce->list, &compressor_list);
 out:
	spin_unlock(&compressor_list_lock);
	return ret;
}

/* Unregister a compressor */
void
ppp_unregister_compressor(struct compressor *cp)
{
	struct compressor_entry *ce;

	spin_lock(&compressor_list_lock);
	ce = find_comp_entry(cp->compress_proto);
	if (ce && ce->comp == cp) {
		list_del(&ce->list);
		kfree(ce);
	}
	spin_unlock(&compressor_list_lock);
}

/* Find a compressor. */
static struct compressor *
find_compressor(int type)
{
	struct compressor_entry *ce;
	struct compressor *cp = NULL;

	spin_lock(&compressor_list_lock);
	ce = find_comp_entry(type);
	if (ce) {
		cp = ce->comp;
		if (!try_module_get(cp->owner))
			cp = NULL;
	}
	spin_unlock(&compressor_list_lock);
	return cp;
}

/*
 * Miscelleneous stuff.
 */

static void
ppp_get_stats(struct ppp *ppp, struct ppp_stats *st)
{
	struct slcompress *vj = ppp->vj;

	memset(st, 0, sizeof(*st));
	st->p.ppp_ipackets = ppp->dev->stats.rx_packets;
	st->p.ppp_ierrors = ppp->dev->stats.rx_errors;
	st->p.ppp_ibytes = ppp->dev->stats.rx_bytes;
	st->p.ppp_opackets = ppp->dev->stats.tx_packets;
	st->p.ppp_oerrors = ppp->dev->stats.tx_errors;
	st->p.ppp_obytes = ppp->dev->stats.tx_bytes;
	if (!vj)
		return;
	st->vj.vjs_packets = vj->sls_o_compressed + vj->sls_o_uncompressed;
	st->vj.vjs_compressed = vj->sls_o_compressed;
	st->vj.vjs_searches = vj->sls_o_searches;
	st->vj.vjs_misses = vj->sls_o_misses;
	st->vj.vjs_errorin = vj->sls_i_error;
	st->vj.vjs_tossed = vj->sls_i_tossed;
	st->vj.vjs_uncompressedin = vj->sls_i_uncompressed;
	st->vj.vjs_compressedin = vj->sls_i_compressed;
}

/*
 * Stuff for handling the lists of ppp units and channels
 * and for initialization.
 */

/*
 * Create a new ppp interface unit.  Fails if it can't allocate memory
 * or if there is already a unit with the requested number.
 * unit == -1 means allocate a new number.
 *///在ppp_create_interface->register_netdev->register_netdevice->ppp_reform_chan_open中执行 所以创建unit的时候同时创建了channel,但没有让channel添加到unit链表上
static struct ppp *
ppp_create_interface(struct net *net, int unit, int *retp)
{
	struct ppp *ppp;
	struct ppp_net *pn;
	struct net_device *dev = NULL;
	int ret = -ENOMEM;
	int i;

	dev = alloc_netdev(sizeof(struct ppp), "", ppp_setup);
	if (!dev)
		goto out1;

	pn = ppp_pernet(net);

	ppp = netdev_priv(dev);
	ppp->dev = dev;
	ppp->mru = PPP_MRU;
	init_ppp_file(&ppp->file, INTERFACE);
	ppp->file.hdrlen = PPP_HDRLEN - 2;	/* don't count proto bytes */
	for (i = 0; i < NUM_NP; ++i)
		ppp->npmode[i] = NPMODE_PASS;
	INIT_LIST_HEAD(&ppp->channels);
	spin_lock_init(&ppp->rlock);
	spin_lock_init(&ppp->wlock);
#ifdef CONFIG_PPP_MULTILINK
	ppp->minseq = -1;
	skb_queue_head_init(&ppp->mrq);
#endif /* CONFIG_PPP_MULTILINK */

	/*
	 * drum roll: don't forget to set
	 * the net device is belong to
	 */
	dev_net_set(dev, net);

	ret = -EEXIST;
	mutex_lock(&pn->all_ppp_mutex);

	if (unit < 0) {
		unit = unit_get(&pn->units_idr, ppp);
		if (unit < 0) {
			*retp = unit;
			goto out2;
		}
	} else {
		if (unit_find(&pn->units_idr, unit))
			goto out2; /* unit already exists */
		/*
		 * if caller need a specified unit number
		 * lets try to satisfy him, otherwise --
		 * he should better ask us for new unit number
		 *
		 * NOTE: yes I know that returning EEXIST it's not
		 * fair but at least pppd will ask us to allocate
		 * new unit in this case so user is happy :)
		 */
		unit = unit_set(&pn->units_idr, ppp, unit);
		if (unit < 0)
			goto out2;
	}

	/* Initialize the new ppp unit */
	ppp->file.index = unit;
	sprintf(dev->name, "ppp%d", unit);

	ret = register_netdev(dev);
	if (ret != 0) {
		unit_put(&pn->units_idr, unit);
		printk(KERN_ERR "PPP: couldn't register device %s (%d)\n",
		       dev->name, ret);
		goto out2;
	}

	ppp->ppp_net = net;

	atomic_inc(&ppp_unit_count);
	mutex_unlock(&pn->all_ppp_mutex);

	*retp = 0;
	return ppp;

out2:
	mutex_unlock(&pn->all_ppp_mutex);
	free_netdev(dev);
out1:
	*retp = ret;
	return NULL;
}

/*
 * Initialize a ppp_file structure.
 */
static void
init_ppp_file(struct ppp_file *pf, int kind)
{
	pf->kind = kind;
	skb_queue_head_init(&pf->xq);
	skb_queue_head_init(&pf->rq);
	atomic_set(&pf->refcnt, 1);
	init_waitqueue_head(&pf->rwait);
}

/*
 * Take down a ppp interface unit - called when the owning file
 * (the one that created the unit) is closed or detached.
 */
static void ppp_shutdown_interface(struct ppp *ppp)
{
	struct ppp_net *pn;

	pn = ppp_pernet(ppp->ppp_net);
	mutex_lock(&pn->all_ppp_mutex);

	/* This will call dev_close() for us. */
	ppp_lock(ppp);
	if (!ppp->closing) {
		ppp->closing = 1;
		ppp_unlock(ppp);
		unregister_netdev(ppp->dev);
	} else
		ppp_unlock(ppp);

	unit_put(&pn->units_idr, ppp->file.index);
	ppp->file.dead = 1;
	ppp->owner = NULL;
	wake_up_interruptible(&ppp->file.rwait);

	mutex_unlock(&pn->all_ppp_mutex);
}

/*
 * Free the memory used by a ppp unit.  This is only called once
 * there are no channels connected to the unit and no file structs
 * that reference the unit.
 */
static void ppp_destroy_interface(struct ppp *ppp)
{
	atomic_dec(&ppp_unit_count);

	if (!ppp->file.dead || ppp->n_channels) {
		/* "can't happen" */
		printk(KERN_ERR "ppp: destroying ppp struct %p but dead=%d "
		       "n_channels=%d !\n", ppp, ppp->file.dead,
		       ppp->n_channels);
		return;
	}

	ppp_ccp_closed(ppp);
	if (ppp->vj) {
		slhc_free(ppp->vj);
		ppp->vj = NULL;
	}
	skb_queue_purge(&ppp->file.xq);
	skb_queue_purge(&ppp->file.rq);
#ifdef CONFIG_PPP_MULTILINK
	skb_queue_purge(&ppp->mrq);
#endif /* CONFIG_PPP_MULTILINK */
#ifdef CONFIG_PPP_FILTER
	kfree(ppp->pass_filter);
	ppp->pass_filter = NULL;
	kfree(ppp->active_filter);
	ppp->active_filter = NULL;
#endif /* CONFIG_PPP_FILTER */

	kfree_skb(ppp->xmit_pending);

	free_netdev(ppp->dev);
}

/*
 * Locate an existing ppp unit.
 * The caller should have locked the all_ppp_mutex.
 */
static struct ppp *
ppp_find_unit(struct ppp_net *pn, int unit)
{
	return unit_find(&pn->units_idr, unit);
}

/*
 * Locate an existing ppp channel.
 * The caller should have locked the all_channels_lock.
 * First we look in the new_channels list, then in the
 * all_channels list.  If found in the new_channels list,
 * we move it to the all_channels list.  This is for speed
 * when we have a lot of channels in use.
 */
static struct channel *
ppp_find_channel(struct ppp_net *pn, int unit)
{
	struct channel *pch;

	list_for_each_entry(pch, &pn->new_channels, list) {
		if (pch->file.index == unit) {
			list_move(&pch->list, &pn->all_channels);
			return pch;
		}
	}

	list_for_each_entry(pch, &pn->all_channels, list) {
		if (pch->file.index == unit)
			return pch;
	}

	return NULL;
}

/*
 * Connect a PPP channel to a PPP interface unit.
 */
static int
ppp_connect_channel(struct channel *pch, int unit)
{
	struct ppp *ppp;
	struct ppp_net *pn;
	int ret = -ENXIO;
	int hdrlen;

	pn = ppp_pernet(pch->chan_net);

	mutex_lock(&pn->all_ppp_mutex);
	ppp = ppp_find_unit(pn, unit);
	if (!ppp) {
        printk("ppp connect channel error, can not find unit:%u", unit);
		goto out;
	}
	write_lock_bh(&pch->upl);
	ret = -EINVAL;
	if (pch->ppp) {
        printk("ppp connect channel error, pch->ppp exist");
        goto outl;
    }
	ppp_lock(ppp);
	if (pch->file.hdrlen > ppp->file.hdrlen)
		ppp->file.hdrlen = pch->file.hdrlen;
	hdrlen = pch->file.hdrlen + 2;	/* for protocol bytes */
	if (hdrlen > ppp->dev->hard_header_len)
		ppp->dev->hard_header_len = hdrlen;
	list_add_tail(&pch->clist, &ppp->channels);
	++ppp->n_channels;
	pch->ppp = ppp;
	atomic_inc(&ppp->file.refcnt);
	ppp_unlock(ppp);
	ret = 0;

 outl:
	write_unlock_bh(&pch->upl);
 out:
	mutex_unlock(&pn->all_ppp_mutex);
	return ret;
}

/*
 * Disconnect a channel from its ppp unit.
 */
static int
ppp_disconnect_channel(struct channel *pch)
{
	struct ppp *ppp;
	int err = -EINVAL;
    
	write_lock_bh(&pch->upl);
	ppp = pch->ppp;
	pch->ppp = NULL;
	write_unlock_bh(&pch->upl);
	if (ppp) {
		/* remove it from the ppp unit's list */
		ppp_lock(ppp);
		list_del(&pch->clist);
		if (--ppp->n_channels == 0)
			wake_up_interruptible(&ppp->file.rwait);
		ppp_unlock(ppp);
		//if (atomic_dec_and_test(&ppp->file.refcnt))
		//	ppp_destroy_interface(ppp);
		err = 0;
	}
	return err;
}

/*
 * Free up the resources used by a ppp channel.
 */
static void ppp_destroy_channel(struct channel *pch)
{
	atomic_dec(&channel_count);

	if (!pch->file.dead) {
		/* "can't happen" */
		printk(KERN_ERR "ppp: destroying undead channel %p !\n",
		       pch);
		return;
	}
	skb_queue_purge(&pch->file.xq);
	skb_queue_purge(&pch->file.rq);
	kfree(pch);
}

static void __exit ppp_cleanup(void)
{
	/* should never happen */
	if (atomic_read(&ppp_unit_count) || atomic_read(&channel_count))
		printk(KERN_ERR "PPP: removing module but units remain!\n");
	unregister_chrdev(PPP_MAJOR, "ppp");
	device_destroy(ppp_class, MKDEV(PPP_MAJOR, 0));
	class_destroy(ppp_class);
	
	dev_remove_pack(&reform_data_pkt_type);
	unregister_pernet_gen_device(ppp_net_id, &ppp_net_ops);
	
	printk("ppp cleanup end \n");
}

/*
 * Units handling. Caller must protect concurrent access
 * by holding all_ppp_mutex
 */

/* associate pointer with specified number */
static int unit_set(struct idr *p, void *ptr, int n)
{
	int unit, err;

again:
	if (!idr_pre_get(p, GFP_KERNEL)) {
		printk(KERN_ERR "PPP: No free memory for idr\n");
		return -ENOMEM;
	}

	err = idr_get_new_above(p, ptr, n, &unit);
	if (err == -EAGAIN)
		goto again;

	if (unit != n) {
		idr_remove(p, unit);
		return -EINVAL;
	}

	return unit;
}

/* get new free unit number and associate pointer with it */
static int unit_get(struct idr *p, void *ptr)
{
	int unit, err;

again:
	if (!idr_pre_get(p, GFP_KERNEL)) {
		printk(KERN_ERR "PPP: No free memory for idr\n");
		return -ENOMEM;
	}

	err = idr_get_new_above(p, ptr, 0, &unit);
	if (err == -EAGAIN)
		goto again;

	return unit;
}

/* put unit number back to a pool */
static void unit_put(struct idr *p, int n)
{
	idr_remove(p, n);
}

/* get pointer associated with the number */
static void *unit_find(struct idr *p, int n)
{
	return idr_find(p, n);
}

/* Module/initialization stuff */

module_init(ppp_init);
module_exit(ppp_cleanup);

EXPORT_SYMBOL(ppp_register_net_channel);
EXPORT_SYMBOL(ppp_register_channel);
EXPORT_SYMBOL(ppp_unregister_channel);
EXPORT_SYMBOL(ppp_channel_index);
EXPORT_SYMBOL(ppp_unit_number);
EXPORT_SYMBOL(ppp_input);
EXPORT_SYMBOL(ppp_input_error);
EXPORT_SYMBOL(ppp_output_wakeup);
EXPORT_SYMBOL(ppp_register_compressor);
EXPORT_SYMBOL(ppp_unregister_compressor);
MODULE_LICENSE("GPL");
MODULE_ALIAS_CHARDEV_MAJOR(PPP_MAJOR);
MODULE_ALIAS("/dev/ppp");

