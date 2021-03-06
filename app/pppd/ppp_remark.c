/***********************************************************************
*
* plugin.c
*
* pppd plugin for kernel-mode PPPoreform on Linux
*
***********************************************************************/

#include "config.h"
#include "zebra.h"
#include "sockunion.h"

#include "sockopt.h"
#include "pathnames.h"
#include "ppp_remark.h"
#include "linklist.h"
#include "log.h"
#include "stream.h"
#include "pppd_tmp.h"
#include "sockunion.h"
#include "memory.h"
#include "command.h"
#include "pppd_debug.h"

struct remark_ipinfo g_ipinfo;
struct remark_bundle g_bundleinfo;
unsigned int pppd_debug_flags = DEBUG_NEG_FLAG;;     //调试标志位开关  默认指打开NEG
unsigned int pppd_debug_if = 0XFFFFFFFF;;     //通道调试标志位开关  默认全部打开

struct ppp_mcp_sock {
    int fd;
    union sockunion su;
    unsigned short port; 
    struct thread *t_connect_admin;
    struct thread *t_read;
	struct thread *t_write;
	struct thread *t_holdtime;
	struct thread *t_keepalive;
	struct thread *t_check;
	struct thread *t_wait_ipinfo_ack;
	struct thread *t_wait_bundle_ack;
    int connect_status;

    int packet_size;
    int control_cmd;
    struct stream *ibuf;
    //struct stream *obuf;
    struct stream_fifo *obuf;
    char hostname[30];	
};

extern int ppp_remark_establish_ppp(int fd);
extern void ppp_remark_disestablish_ppp(int dev_fd);
extern int new_style_driver;

#define _PATH_PPPOreformOPT         _ROOT_PATH "/ppp/options.remark"
#define PPPOreform_VERSION          "1.0"

char pppd_version[] = VERSION;

struct list* multilink_if_list;
struct list* remote_userinfo_list;
struct ppp_mcp_sock* g_ppp_mcp_sock;

static struct multilink_if_info* ppp_multi_info_malloc(void)
{
    struct multilink_if_info *p = malloc(sizeof(struct multilink_if_info));

    memset(p, 0, sizeof(struct multilink_if_info));

    return p;
}

static void ppp_multi_info_free(struct multilink_if_info* p)
{
    if(p == NULL)
        return;

    free(p);
}

static struct remote_userinfo* ppp_remote_info_malloc(void)
{
    struct remote_userinfo *p = malloc(sizeof(struct remote_userinfo));

    memset(p, 0, sizeof(struct remote_userinfo));

    return p;
}

static void ppp_remote_info_free(struct remote_userinfo* p)
{
    if(p == NULL)
        return;

    free(p);
}

void ppp_mcp_sock_init(struct ppp_mcp_sock *peer)
{
    int ret;
    union sockunion su;

    memset(peer->hostname, 0, sizeof(peer->hostname));
    strcpy(peer->hostname, MCP_PPPD_TCP_ADDR);

    ret = str2sockunion(MCP_PPPD_TCP_ADDR, &su);
	if (ret < 0) {
		PPPD_DEBUG_TCP("Malformed address: %s error", MCP_PPPD_TCP_ADDR);
		return;
	}

    peer->su = su;
	peer->port = MCP_PPPD_TCP_PORT;
    peer->fd = -1;

	return;
}

static int ppp_remark_mem_malloc(void)
{
//    int i = 0, j = 0;//, k = 0;

    multilink_if_list = list_new();
    multilink_if_list->del = (void (*)(void *))ppp_multi_info_free;

    remote_userinfo_list = list_new();
    if(remote_userinfo_list == NULL)
        goto err2;
    remote_userinfo_list->del = (void (*)(void *))ppp_remote_info_free;

    g_ppp_mcp_sock = malloc(sizeof(struct ppp_mcp_sock));
    if(g_ppp_mcp_sock == NULL)
        goto err3;
    memset(g_ppp_mcp_sock, 0, sizeof(struct ppp_mcp_sock));

    g_ppp_mcp_sock->ibuf = stream_new(10240);
    g_ppp_mcp_sock->obuf = stream_fifo_new ();
    ppp_mcp_sock_init(g_ppp_mcp_sock);

    ppp_if_mem_malloc();
    
    return 0;

err3:
    list_free(remote_userinfo_list);
    
err2:
    list_free(multilink_if_list);
    
    return -1;
}

void ppp_remark_mem_free(void)
{
 //   int i = 0;

    ppp_if_mem_free();
    
    if(multilink_if_list != NULL) {
        list_delete(multilink_if_list);
        multilink_if_list = NULL;
    }

    if(remote_userinfo_list != NULL) {
        list_delete(remote_userinfo_list);
        remote_userinfo_list = NULL;
    }

    if(g_ppp_mcp_sock->ibuf != NULL)
        stream_free(g_ppp_mcp_sock->ibuf);

    if(g_ppp_mcp_sock->obuf != NULL)
        stream_fifo_free(g_ppp_mcp_sock->obuf);

    if(g_ppp_mcp_sock->fd > 0)
        close(g_ppp_mcp_sock->fd);
        
    if(g_ppp_mcp_sock != NULL)
        free(g_ppp_mcp_sock);
        
    return;
}

struct remote_userinfo* ppp_remark_lookup_remote_userinfo(char *remote_name)
{
    struct remote_userinfo* p;
    struct listnode *nn, *mm;
    struct list* list = remote_userinfo_list;

    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
        if(strcmp(p->remote_name, remote_name) == 0)    
            return p;    
    }

    return NULL;
}

void ppp_remark_add_remote_userinfo(struct remote_userinfo* userinfo)
{
    struct remote_userinfo* p;

    p = ppp_remark_lookup_remote_userinfo(userinfo->remote_name);
    if(p != NULL) {
        memset(p->remote_name, 0, sizeof(p->remote_name));
        memset(p->remote_pwd, 0, sizeof(p->remote_pwd));
        strcpy(p->remote_name, userinfo->remote_name);
        strcpy(p->remote_pwd, userinfo->remote_pwd);
        return;
    }

    p = ppp_remote_info_malloc();
    strcpy(p->remote_name, userinfo->remote_name);
    strcpy(p->remote_pwd, userinfo->remote_pwd);

    listnode_add(remote_userinfo_list, p);

    return;
}

int ppp_remark_check_remote_userinfo(char* remote_name, char* remote_pwd)
{
    struct remote_userinfo* p;
    struct listnode *nn, *mm;
    struct list* list = remote_userinfo_list;

    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
        if(strcmp(p->remote_name, remote_name) == 0 && strcmp(p->remote_pwd, remote_pwd) == 0)    
            return 0;    
    }

    return -1;
}

int ppp_get_user_passwd(char *username, char *passwd, int *pass_len)
{
	struct remote_userinfo* p;
    struct listnode *nn, *mm;
    struct list* list = remote_userinfo_list;
    
    if(username == NULL)
        return 0;
        
    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
    	if (p && p->remote_pwd && strcmp(username, p->remote_name) == 0) {
    		strcpy(passwd, p->remote_pwd);
    		*pass_len = strlen(p->remote_pwd);
    		return 1;
    	}
    }
	return 0;
}

void ppp_remark_del_remote_userinfo(struct remote_userinfo* userinfo)
{
    struct remote_userinfo* p;
   // struct listnode *nn, *mm;
    struct list* list = remote_userinfo_list;

    p = ppp_remark_lookup_remote_userinfo(userinfo->remote_name);
    if(p != NULL) {
        listnode_delete(list, p);
    }

    return;
}

struct multilink_if_info* ppp_remark_lookup_multilink_interface(unsigned int multi_num)
{
    struct multilink_if_info* p;
    struct listnode *nn, *mm;
    struct list* list = multilink_if_list;

    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
        if(p->multi_num == multi_num)
            return p;
    }

    return NULL;
}

void ppp_remark_add_multilink_interface(struct multilink_if_info* info)
{
    struct multilink_if_info* p;

    p = ppp_remark_lookup_multilink_interface(info->multi_num);
    if(p != NULL) {
        if(p->multi_ip != info->multi_ip) {/* 修改了组IP，接口IP需要跟着变 */
            mcp_pppd_update_allinterface_addto_group(p->multi_ip, info->multi_ip);
            p->multi_ip = info->multi_ip;
            
            mcp_pppd_disable_allinterface_addto_group(p);
        }
        
        p->multi_num = info->multi_num;
        return;
    }

    p = ppp_multi_info_malloc();
    p->multi_ip = info->multi_ip;
    p->multi_num = info->multi_num;
    p->interface_bit = info->interface_bit;

    listnode_add(multilink_if_list, p);

    return;
}

void ppp_remark_del_multilink_interface(unsigned int multi_num)
{
    struct multilink_if_info* p;
    struct listnode *nn, *mm;
    struct list* list = multilink_if_list;

    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
        if(p->multi_num != multi_num)
            continue;
            
        listnode_delete(list, p);
        return;    
    }

    return;
}

/* 绑定成功后才加入该组 */
void ppp_remark_interface_addto_multilink(int inter, int multi_num)
{
    struct multilink_if_info* p;
    struct listnode *nn, *mm;
    struct list* list = multilink_if_list;

    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
        if(p->multi_num != multi_num)
            continue;

        PPP_SET_MULTI_BIT(p->interface_bit, inter);
        return;    
    }

    return;
}

void ppp_remark_interface_del_from_multilink(int inter, int multi_num)
{
    struct multilink_if_info* p;
    struct listnode *nn, *mm;
    struct list* list = multilink_if_list;

    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
        if(p->multi_num != multi_num)
            continue;

        PPP_CLEAR_MULTI_BIT(p->interface_bit, inter);
        return;    
    }

    return;
}

#define MCP_PPPD_UDP_PORT 9211
#define MCP_PPPD_ADDR ("127.0.0.1")
#define SO_REUSEPORT 15

int remark_socket = -1;
const char *safe_strerror(int errnum)
{
  const char *s = strerror(errnum);
  
  return (s != NULL) ? s : "Unknown error";
}

#define MAX_ADDR_BUFFER     10
static int current_buffer = 0;
#define INET_ADDRSTRLEN 16

static char addr_buffer[MAX_ADDR_BUFFER][INET_ADDRSTRLEN];

const char *remark_ip2str (u_int32_t addr)
{
    char *buffer = addr_buffer[current_buffer];
    addr = htonl (addr);
    inet_ntop (AF_INET, (char *) &addr, buffer, INET_ADDRSTRLEN);
    current_buffer++;
    if (current_buffer >= MAX_ADDR_BUFFER)
        current_buffer = 0;

    return buffer;
}

const unsigned int remark_str2ip(const char *ip_str)
{
    if(NULL == ip_str)
        return 0;	

    struct sockaddr_in sock_addr;

    if(inet_pton(AF_INET, ip_str, &sock_addr.sin_addr.s_addr) <= 0)
    {        
        PPPD_DEBUG_TCP("Error, mcp_xml_str2ip (%s)", ip_str);
        return 0;
    }
    
    return ntohl(sock_addr.sin_addr.s_addr);
}

#define MAX_ZLOG_LINELEN 512
void ZLOG_EXT_BASE(const char* filename, int lineno, const char* fmt, ...)
{
   // return;
    
    va_list var;
    va_start(var, fmt);
    char szbuf[MAX_ZLOG_LINELEN];
    vsnprintf(szbuf, MAX_ZLOG_LINELEN, fmt, var);
    zlog_debug("%15s, %04d : %s", filename, lineno, szbuf);
    va_end(var);
}

static void ppp_connect_mcp_error_deal(struct ppp_mcp_sock *peer)
{
    PPPD_DEBUG_TCP("ppp mcp connect error deal, close fd");
    MCP_READ_OFF (peer->t_read);
    MCP_WRITE_OFF (peer->t_write);
    MCP_TIMER_OFF (peer->t_holdtime);
    MCP_TIMER_OFF (peer->t_keepalive);
    MCP_WRITE_OFF (peer->t_check);

    if (peer->fd > 0) {
        close (peer->fd);
        peer->fd = -1;
    }

    if (peer->ibuf)
        stream_reset (peer->ibuf);
    
    if (peer->obuf)
		stream_fifo_clean (peer->obuf);

    peer->connect_status = 0;
    return;
}


static void ppp_put_control_to_stream(struct stream* s, unsigned int control)
{
    stream_putl(s, control);

    return;
}

static int ppp_tcp_client_holdtime_timer (struct thread *thread)
{
    struct ppp_mcp_sock *peer;

    peer = THREAD_ARG (thread);
    peer->t_holdtime = NULL;

    PPPD_DEBUG_TCP("[TCP CLIENT FSM] Timer (holdtime timer expire), peer:%s", peer->hostname);
	ppp_connect_mcp_error_deal(peer);

    return 0;
}

static int ppp_tcp_client_keepalive_timer (struct thread *thread)
{
	struct ppp_mcp_sock *peer;
    struct stream* s_new;
    
	peer = THREAD_ARG (thread);
	peer->t_keepalive = NULL;
	
	PPPD_DEBUG_TCP("Timer (keepalive timer expire), peer:%s", peer->hostname);
	s_new = stream_new(1024);
	stream_putl(s_new, 4);
    ppp_put_control_to_stream(s_new, REMARK_KEEPALIVE_CMD);
    stream_fifo_push (peer->obuf, s_new);
    MCP_WRITE_ON (peer->t_write, ppp_tcp_write, peer, peer->fd);
	MCP_TIMER_ON (peer->t_keepalive, ppp_tcp_client_keepalive_timer, peer, CLIENT_CONNECT_KEEPALIVE_TIMER);
	return 0;
}

int ppp_tcp_client_established (struct ppp_mcp_sock *peer)
{
    PPPD_DEBUG_TCP("client connect server mcp OK");
	MCP_READ_ON (peer->t_read, ppp_tcp_read, peer, peer->fd);

	MCP_TIMER_ON (peer->t_holdtime, ppp_tcp_client_holdtime_timer, peer, CLIENT_HOLD_TIME_EXPIRE);

	MCP_TIMER_ON (peer->t_keepalive, ppp_tcp_client_keepalive_timer, peer, 0);//只要有发送报文，则该定时器OFF，然后重新ON
	
    remark_all_ipinfo_notify_mcp();
    peer->connect_status = CLIENT_CONNECT_SERVER_OK;
    
	//MCP_TIMER_OFF (peer->t_connect_admin);
	
	return 0;
}
static void pppd_postpone_keepalive_timer(struct ppp_mcp_sock *peer)
{
	if(CLIENT_CONNECT_SERVER_OK != peer->connect_status)
	    return;
	    
	MCP_TIMER_OFF(peer->t_keepalive);
	MCP_TIMER_ON(peer->t_keepalive, ppp_tcp_client_keepalive_timer, peer, CLIENT_CONNECT_KEEPALIVE_TIMER);
}

static void pppd_postpone_holdtime_timer(struct ppp_mcp_sock *peer)
{
	if(CLIENT_CONNECT_SERVER_OK != peer->connect_status)
	    return;
	    
	MCP_TIMER_OFF(peer->t_holdtime);
	MCP_TIMER_ON(peer->t_holdtime, ppp_tcp_client_holdtime_timer, peer, CLIENT_HOLD_TIME_EXPIRE);
}


int ppp_tcp_write (struct thread *thread)
{
	struct ppp_mcp_sock *peer;
	struct stream *stream;
	int num;
	int write_errno;
	int val, writenum;

	/* Yes first of all get peer pointer. */
	peer = THREAD_ARG (thread);
	peer->t_write = NULL;

	if (peer->fd < 0)
	{
		PPPD_DEBUG_TCP("write: peer's fd is negative value %d", peer->fd);
		return -1;
	}

	if(peer->connect_status != CLIENT_CONNECT_SERVER_OK)
	    return -1;
	
	while (1)
	{
		stream = stream_fifo_head(peer->obuf);
		if (stream == NULL)
			return 0;

		val = fcntl (peer->fd, F_GETFL, 0);
		fcntl (peer->fd, F_SETFL, val | O_NONBLOCK);

		/* Number of bytes to be sent.  */
		writenum = stream_get_endp (stream) - stream_get_getp (stream);

		/* Call write() system call.  */
		num = write (peer->fd, STREAM_PNT (stream), writenum);
		write_errno = errno;
		fcntl (peer->fd, F_SETFL, val);
		if (num < 0)
		{
			if (write_errno == EWOULDBLOCK || write_errno == EAGAIN || write_errno == EINTR)
				break;

            PPPD_DEBUG_TCP("erro,write packet to peer:%s, fd:%u", peer->hostname, peer->fd);
			ppp_connect_mcp_error_deal(peer);
			
			return 0;
		}

		/*发送了数据之后，推迟保活定时器*/
		if(num > 0)
			pppd_postpone_keepalive_timer(peer);

		if (num != writenum) {
			stream_forward_getp(stream, num);
			break;
		} else
		    stream_free(stream_fifo_pop (peer->obuf));
        
		break;
	}

	if(stream_fifo_head (peer->obuf))
		MCP_WRITE_ON (peer->t_write, ppp_tcp_write, peer, peer->fd);

	return 0;
}

struct pppd_remote_userinfo* mcp_remote_userinfo_malloc_new(void)
{
    struct pppd_remote_userinfo* p = malloc(sizeof(struct pppd_remote_userinfo));

    memset(p, 0, sizeof(struct pppd_remote_userinfo));

    return p;
}

void mcp_ppp_config_info_free(void* p)
{
    if(p == NULL)
        return;

    free(p);
}

static struct list* mcp_ppp_remote_userinfo_parse(struct stream *data_s)
{
	int type;
	int len;
	struct list* digt_list;
	struct pppd_remote_userinfo* info = NULL;

    digt_list = list_new();
    digt_list->del = (void (*) (void *))mcp_ppp_config_info_free;
	
	while(STREAM_READABLE(data_s) >= 4)
	{
		type = stream_getw(data_s);
		len = stream_getw(data_s);
		//zlog_debug("<%s,%d> type:%d len:%d", __FUNCTION__, __LINE__, type, len);
		if(STREAM_READABLE(data_s) < 2) {
			zlog_err("mcp<%s:%d> stream readable bytes %d less %d",__FUNCTION__,__LINE__,((data_s)->endp-(data_s)->getp),len);
			return NULL;
		}

		switch(type)
		{
		    case ppp_REMOTEINFO_SEQ: 
		        info = mcp_remote_userinfo_malloc_new();
				info->seq = stream_getl(data_s);
				//zlog_err("yang test ...seq:%u", (info->seq));
				break;
				
			case ppp_REMOTEINFO_GWID: 
				info->gwid= stream_getl(data_s);
				//zlog_err("yang test ...gwid:%s", remark_ip2str(info->gwid));
				break;

			case ppp_REMOTEINFO_DEV_TYPE: 
				info->dev_type = stream_getl(data_s);
				//zlog_err("yang test devtype:%u", info->dev_type);
				break;
				
            case ppp_REMOTEINFO_USERNAME:
                memset(info->username, 0, sizeof(info->username));
                stream_get(info->username, data_s, len);
				//zlog_err("yang test username:%s", info->username);
				break;

			case ppp_REMOTEINFO_PASSWD:
			    memset(info->passwd, 0, sizeof(info->passwd));
			    stream_get(info->passwd, data_s,len);
				//zlog_err("yang test passwd:%s", info->passwd);
				break;
				
			case ppp_REMOTEINFO_TIME: 
			    memset(info->create_time, 0, sizeof(info->create_time));
				stream_get(info->create_time, data_s, len);
				//zlog_err("yang test create_time:%s", info->create_time);
				break;

			case ppp_REMOTEINFO_REMARK: 
			    memset(info->remark, 0, sizeof(info->remark));
				stream_get(info->remark, data_s, len);
				//zlog_err("yang test remark:%s", (info->remark));
				break;

			case ppp_REMOTEINFO_ACTION: 
			    info->action = stream_getl(data_s);
				//zlog_err("yang test action:%u", info->action);
				listnode_add(digt_list, info);
				break;
			    
			default:
			    list_delete(digt_list);
				zlog_err("mcp<%s:%d> wrong type:%u",__FUNCTION__,__LINE__,type);
				goto error;
		}		
	}

	return digt_list;

error:
	return NULL;	
}

static int mcp_ppp_remote_userinfo_update_local(struct pppd_remote_userinfo *info)
{
    struct remote_userinfo userinfo;

    strcpy(userinfo.remote_name, info->username);
    strcpy(userinfo.remote_pwd, info->passwd);

    if(info->action == PPP_OP_ADD)
        ppp_remark_add_remote_userinfo(&userinfo);
    else if(info->action == ppp_OP_DEL)
        ppp_remark_del_remote_userinfo(&userinfo);
        
    return 0;
}

static void mcp_printf_ppp_remote_userinfo(struct pppd_remote_userinfo *multi_info)
{
    PPPD_DEBUG_TCP("ppp remote userinfo update local, op:%u, gwid:%s, dev_type:%u, username:%s, pwd:%s",
        multi_info->action, remark_ip2str(multi_info->gwid), multi_info->dev_type, multi_info->username, multi_info->passwd);
}

int mcp_recv_pppd_remote_userinfo_ack(struct stream *data_s)
{
    struct pppd_remote_userinfo *multi_info;
    struct listnode *mm;
    struct list* multi_list;

    ZLOG_INFO("recv pppd remote userinfo ");
    multi_list = mcp_ppp_remote_userinfo_parse(data_s);
    if(multi_list == NULL) {
        PPPD_DEBUG_TCP("mcp ppp remote userinfo parse error");
        return -1;
    } 

    PPPD_DEBUG_TCP("mcp recv pppd remote userinfo config, info count:%u", multi_list->count);
    for(ALL_LIST_ELEMENTS_RO(multi_list, mm, multi_info)) {
        mcp_printf_ppp_remote_userinfo(multi_info);
        mcp_ppp_remote_userinfo_update_local(multi_info);
	}

    list_delete(multi_list);
    return 0;
}

struct pppd_multilink_info* mcp_pppd_multilink_malloc_new(void)
{
    struct pppd_multilink_info* p = malloc(sizeof(struct pppd_multilink_info));

    memset(p, 0, sizeof(struct pppd_multilink_info));

    return p;
}

static struct list* mcp_ppp_multilink_info_parse(struct stream *data_s)
{
	int type;
	int len;
	struct list* digt_list;
	struct pppd_multilink_info* info = NULL;

    digt_list = list_new();
    digt_list->del = (void (*) (void *))mcp_ppp_config_info_free;
	
	while(STREAM_READABLE(data_s) >= 4)
	{
		type = stream_getw(data_s);
		len = stream_getw(data_s);
		//zlog_debug("<%s,%d> type:%d len:%d", __FUNCTION__, __LINE__, type, len);
		if(STREAM_READABLE(data_s) < 2) {
			zlog_err("mcp<%s:%d> stream readable bytes %d less %d",__FUNCTION__,__LINE__,((data_s)->endp-(data_s)->getp),len);
			return NULL;
		}

		switch(type)
		{
		    case PPP_MULTILINK_INFO_SEQ: 
		        info = mcp_pppd_multilink_malloc_new();
				info->seq = stream_getl(data_s);
				//zlog_err("yang test ...seq:%u", (info->seq));
				break;
				
			case PPP_MULTILINK_INFO_GWID: 
				info->gwid= stream_getl(data_s);
				//zlog_err("yang test ...gwid:%s", remark_ip2str(info->gwid));
				break;

			case PPP_MULTILINK_INFO_MULTIIP: 
			    memset(info->multi_ip, 0, sizeof(info->multi_ip));
				stream_get(info->multi_ip, data_s, len);
				//zlog_err("yang test multi_ip:%s", info->multi_ip);
				break;
				
            case PPP_MULTILINK_INFO_TIME:
                memset(info->create_time, 0, sizeof(info->create_time));
                stream_get(info->create_time, data_s, len);
				//zlog_err("yang test create_time:%s", info->create_time);
				break;
				
			case PPP_MULTILINK_INFO_REMARK: 
			    memset(info->remark, 0, sizeof(info->remark));
				stream_get(info->remark, data_s, len);
				//zlog_err("yang test remark:%s", info->remark);
				break;

			case PPP_MULTILINK_INFO_ACTION:
			    info->action = stream_getl(data_s);
			    listnode_add(digt_list, info);
				//zlog_err("yang test ...action:%u", (info->action));
				break;
			    
			default:
			    list_delete(digt_list);
				zlog_err("mcp<%s:%d> wrong type:%u",__FUNCTION__,__LINE__,type);
				goto error;
		}		
	}

	return digt_list;

error:
	return NULL;	
}

static int mcp_ppp_multlink_info_update_local(struct pppd_multilink_info *info)
{
    struct multilink_if_info multi_info;

    multi_info.multi_num = info->seq;

    if(strlen(info->multi_ip) > 0)
        multi_info.multi_ip = remark_str2ip(info->multi_ip);

    if(info->action == ppp_OP_DEL)
        ppp_remark_del_multilink_interface(multi_info.multi_num);
    else
        ppp_remark_add_multilink_interface(&multi_info);
        
    return 0;
}

static void mcp_printf_ppp_multiinfo(struct pppd_multilink_info *multi_info)
{
    PPPD_DEBUG_TCP("ppp multilink info update local, op:%u, seq:%u, gwid:%s, multi_ip:%s",
        multi_info->action, (multi_info->seq), remark_ip2str(multi_info->gwid), multi_info->multi_ip);
}

int mcp_recv_pppd_multilink_info_ack(struct stream *data_s)
{
    struct pppd_multilink_info *multi_info;
    struct listnode *mm;
    struct list* multi_list;
    
    ZLOG_INFO("recv pppd multilink info ");
    multi_list = mcp_ppp_multilink_info_parse(data_s);
    if(multi_list == NULL) {
        PPPD_DEBUG_TCP("mcp ppp multilink info parse error");
        return -1;
    } 

    PPPD_DEBUG_TCP("mcp recv pppd remote MULTILINK config, info count:%u", multi_list->count);
    for(ALL_LIST_ELEMENTS_RO(multi_list, mm, multi_info)) {
        mcp_printf_ppp_multiinfo(multi_info);
        mcp_ppp_multlink_info_update_local(multi_info);
	}

    list_delete(multi_list);
    return 0;
}

struct pppd_interface_info* mcp_pppd_interface_new(void)
{
    struct pppd_interface_info* p = malloc(sizeof(struct pppd_interface_info));

    memset(p, 0, sizeof(struct pppd_interface_info));

    return p;
}

static struct list* mcp_pppd_interface_parse(struct stream *data_s)
{
	int type;
	int len;
	struct list* digt_list;
	struct pppd_interface_info* info = NULL;

    digt_list = list_new();
    digt_list->del = (void (*) (void *))mcp_ppp_config_info_free;
	
	while(STREAM_READABLE(data_s) >= 4)
	{
		type = stream_getw(data_s);
		len = stream_getw(data_s);
		//zlog_debug("<%s,%d> type:%d len:%d", __FUNCTION__, __LINE__, type, len);
		if(STREAM_READABLE(data_s) < 2) {
			zlog_err("mcp<%s:%d> stream readable bytes %d less %d",__FUNCTION__,__LINE__,((data_s)->endp-(data_s)->getp),len);
			return NULL;
		}

		switch(type)
		{
		    case PPP_INTERFACE_SEQ: 
		        info = mcp_pppd_interface_new();
				info->seq = stream_getl(data_s);
				//zlog_err("yang test ...seq:%u", (info->seq));
				break;
				
			case PPP_INTERFACE_GWID: 
				info->gwid= stream_getl(data_s);
				//zlog_err("yang test ...gwid:%s", remark_ip2str(info->gwid));
				break;

			case PPP_INTERFACE_SEVTYPE: 
			    info->dev_type = stream_getl(data_s);
				//zlog_err("yang test ...dev_type:%u", (info->dev_type));
				break;
				
            case PPP_INTERFACE_INTERFACEID:
                info->interfaceid = stream_getl(data_s);
				//zlog_err("yang test ...dev_type:%u", (info->dev_type));
				break;

			case PPP_INTERFACE_MULTIFLAGE:
			    info->multi_group = stream_getl(data_s);
				//zlog_err("yang test ...multi_flag:%u", (info->multi_group));
				break;
				
			case PPP_INTERFACE_INTERFACEIP: 
			    memset(info->interfaceip, 0, sizeof(info->interfaceip));
				stream_get(info->interfaceip, data_s, len);
				//zlog_err("yang test interfaceip:%s", info->interfaceip);
				break;

			case PPP_INTERFACE_ENABLE:
			    info->enable = stream_getl(data_s);
			    break;

			case PPP_INTERFACE_AUTHTYPE:
			    info->auth_type = stream_getl(data_s);
				//zlog_err("yang test ...auth_type:%u", (info->auth_type));
			    break;
			    
			case PPP_INTERFACE_AUTHNAME:
			    memset(info->auth_name, 0, sizeof(info->auth_name));
				stream_get(info->auth_name, data_s, len);
				//zlog_err("yang test auth_name:%s", info->auth_name);
				break;

			case PPP_INTERFACE_USERNAME:
			    memset(info->username, 0, sizeof(info->username));
				stream_get(info->username, data_s, len);
				//zlog_err("yang test username:%s", info->username);
                break;
                
			case PPP_INTERFACE_PSWD:
				memset(info->pswd, 0, sizeof(info->pswd));
				stream_get(info->pswd, data_s, len);
				//zlog_err("yang test pswd:%s", info->pswd);
                break;

            case PPP_INTERFACE_TIME:
				memset(info->time, 0, sizeof(info->time));
				stream_get(info->time, data_s, len);
				//zlog_err("yang test time:%s", info->time);
                break;
                
            case PPP_INTERFACE_REMARK:
                memset(info->remark, 0, sizeof(info->remark));
				stream_get(info->remark, data_s, len);
				//zlog_err("yang test remark:%s", info->remark);
                break;

             case PPP_INTERFACE_ACTION:
                info->action = stream_getl(data_s);
                listnode_add(digt_list, info);
				//zlog_err("yang test ...action:%u", (info->action));
                break;
            
			default:
			    list_delete(digt_list);
				zlog_err("mcp<%s:%d> wrong type:%u",__FUNCTION__,__LINE__,type);
				goto error;
		}		
	}

	return digt_list;

error:
	return NULL;	
}

static void mcp_printf_ppp_interface_info(struct pppd_interface_info *multi_info)
{
    PPPD_DEBUG_TCP("ppp interface info update local, op:%u, seq:%u, gwid:%s, interfaceid:%u, ip:%s, enalbe:%u, auth:%u, username:%s, paswd:%s ",
        multi_info->action, (multi_info->seq), remark_ip2str(multi_info->gwid), multi_info->interfaceid, 
        multi_info->interfaceip, multi_info->enable, multi_info->auth_type, multi_info->username, multi_info->pswd);
}

int mcp_recv_pppd_interface_info_ack(struct stream *data_s, int syn_flag)
{
    struct pppd_interface_info *info;
    struct listnode *mm;
    struct list* multi_list;
    //char tmp_buf[256];

    ZLOG_INFO("recv pppd interface info ");
    multi_list = mcp_pppd_interface_parse(data_s);
    if(multi_list == NULL) {
        PPPD_DEBUG_TCP("mcp ppp multilink info parse error");
        return -1;
    } 

    //if(multi_list->count == 0 && syn_flag == 1) {
    if(syn_flag == 1) {
        ppp_if_close_all_enalbe_channel();
        ppp_init_db_file();
        mcp_pppd_init_all_local_interface(); //这个一定要放ppp_if_close_all_enalbe_channel后面
    }

    for(ALL_LIST_ELEMENTS_RO(multi_list, mm, info)) {
        mcp_printf_ppp_interface_info(info);
        if(syn_flag == 0 && mcp_pppd_interface_changed(info) == 1)
            pppd_interface_disable(info->interfaceid); ;  
        mcp_ppp_interface_info_update_local(info);
	}

    list_delete(multi_list);
    return 0;
}

static int mcp_ppp_all_config_syn_parse_update(struct stream *data_s)
{
	int type;
	int len;
	struct stream* tmp_s;

    tmp_s = stream_new(10240);
	while(STREAM_READABLE(data_s) >= 4)
	{
		type = stream_getw(data_s);
		len = stream_getw(data_s);
		//zlog_debug("<%s,%d> type:%d len:%d", __FUNCTION__, __LINE__, type, len);

        if(len == 0)
            continue;
            
		switch(type)
		{
		    case MCP_PPPD_CONFIG_SYN_REMOT_USERINFO: 
				stream_put(tmp_s, data_s->data + stream_get_getp(data_s), len);
				mcp_recv_pppd_remote_userinfo_ack(tmp_s);
				stream_forward_getp(data_s, len);
				stream_reset(tmp_s);
				break;
				
			case MCP_PPPD_CONFIG_SYN_MULTILINK_INFO: 
				stream_put(tmp_s, data_s->data + stream_get_getp(data_s), len);
				mcp_recv_pppd_multilink_info_ack(tmp_s);
				stream_forward_getp(data_s, len);
				stream_reset(tmp_s);
				break;

			case MCP_PPPD_CONFIG_SYN_INTERFACE_INFO: 
			    stream_put(tmp_s, data_s->data + stream_get_getp(data_s), len);
			    mcp_recv_pppd_interface_info_ack(tmp_s, 1);
				stream_forward_getp(data_s, len);
				stream_reset(tmp_s);
				break;
			    
			default:
				zlog_err("mcp<%s:%d> wrong type:%u",__FUNCTION__,__LINE__,type);
				goto error;
		}		
	}

    stream_free(tmp_s);
	return 0;

error:
    stream_free(tmp_s);
	return -1;	
}

static void mcp_pppd_delete_all_local_info(void)
{
//    int i;
    
    list_delete_all_node(multilink_if_list);
    list_delete_all_node(remote_userinfo_list);

    //mcp_pppd_init_all_local_interface(); 不能执行这个
}

int mcp_pppd_recv_config_syn(struct ppp_mcp_sock* peer)
{
    PPPD_DEBUG_TCP("recv pppd config syn from peer:%s", (peer->hostname));

    mcp_pppd_delete_all_local_info(); /* 清除本地数据 */
    if(mcp_ppp_all_config_syn_parse_update(peer->ibuf) == -1) {
        PPPD_DEBUG_TCP("ppp parse syn info error");
        return -1;
    }
    
    return 0;
}

static int mcp_pppd_tcp_read_deal(struct ppp_mcp_sock *peer)
{
    unsigned int cmd;
    cmd = peer->control_cmd;
    
    switch(cmd) {
    case REMARK_IPINFO_CMD_ACK:
        MCP_TIMER_OFF(peer->t_wait_ipinfo_ack);
        PPPD_DEBUG_TCP("mcp recv pppd ipinfo ack from peer:%s", peer->hostname);
        break;
    case REMARK_BUDLE_CMD_ACK:
        MCP_TIMER_OFF(peer->t_wait_bundle_ack);
        PPPD_DEBUG_TCP("mcp recv pppd bundle info ack from peer:%s", peer->hostname);
        break;
    case REMARK_KEEPALIVE_CMD:
        PPPD_DEBUG_TCP("mcp recv pppd keepalive packet from peer:%s", peer->hostname);
        break;

    case REFORM_PPP_REMOTE_USERINFO_ACK:
        mcp_recv_pppd_remote_userinfo_ack(peer->ibuf);
        //write_config_file();
        return 0;

    case REFORM_PPP_MULTILINK_INFO_ACK:
        mcp_recv_pppd_multilink_info_ack(peer->ibuf);
        //write_config_file();
        return 0;

    case REFORM_PPP_INTERFACE_INFO_ACK:
        mcp_recv_pppd_interface_info_ack(peer->ibuf, 0);
        //write_config_file();
        return 0;
        
    case REFORM_PPP_ALL_CONFIG_SYN:
        mcp_pppd_recv_config_syn(peer);
        //write_config_file();
        return 0;
        
    default:
        PPPD_DEBUG_TCP("cmd:%u ,error", cmd);
        break;
    }
    
    return 0;
}

static int mcp_pppd_read(struct ppp_mcp_sock *peer)
{
    int readsize;
    int nbytes;

	readsize = peer->packet_size - stream_get_endp (peer->ibuf);
	if(readsize == 0)
	    return 0;
	    
	nbytes = stream_read_unblock (peer->ibuf, peer->fd, readsize); 
    if (nbytes <= 0) {
        if (errno == EAGAIN)
            return -1;
                
        PPPD_DEBUG_TCP("%s [Error] fd:%u, read packet error: %s", peer->hostname, peer->fd, safe_strerror (errno) );
        ppp_connect_mcp_error_deal(peer);

        return -1;
    }

    if(stream_get_endp(peer->ibuf) != peer->packet_size)
		return -1;

    return 0;
}

int ppp_tcp_read(struct thread *thread)
{
	struct ppp_mcp_sock *peer;
	//int data_len;

	/* Yes first of all get peer pointer. */
	peer = THREAD_ARG (thread);
	peer->t_read = NULL;

	if (peer->fd < 0)
	{
		PPPD_DEBUG_TCP("read: peer's fd is negative value %d", peer->fd);
		return -1;
	}
    
	MCP_READ_ON (peer->t_read, ppp_tcp_read, peer, peer->fd);

    if (peer->packet_size == 0)
		peer->packet_size = MCP_PPP_HEADER_SIZE;

    if (stream_get_endp (peer->ibuf) < MCP_PPP_HEADER_SIZE) {
        if(mcp_pppd_read(peer) == -1)
            return 0;

        peer->packet_size = stream_getl(peer->ibuf);
        peer->control_cmd = stream_getl(peer->ibuf);
    }
		
    if(mcp_pppd_read(peer) == -1) {
        PPPD_DEBUG_TCP("ppp read tcp error:%s", peer->hostname);
        return 0;
    }
    mcp_pppd_tcp_read_deal(peer);
    stream_reset (peer->ibuf);
    peer->packet_size = 0;
    pppd_postpone_holdtime_timer(peer);
    
	return 0;

}

int mcp_tcp_client_connect (struct ppp_mcp_sock *peer)
{
	unsigned int ifindex = 0;

	if(peer->fd > 0)
	{
		close(peer->fd);
		peer->fd = -1;
	}
	
	/* Make socket for the peer. */
	peer->fd = sockunion_socket (&peer->su);

	if (peer->fd < 0)
		return -1;

	/* If we can get socket for the peer, adjest TTL and make connection. */
	sockopt_ttl (peer->su.sa.sa_family, peer->fd, 512);

	sockopt_reuseaddr (peer->fd);
	sockopt_reuseport (peer->fd);

	PPPD_DEBUG_TCP("%s [Event] Connect start to %s fd %d",
	            peer->hostname, peer->hostname, peer->fd);

	/* Connect to the remote peer. */
	return sockunion_connect (peer->fd, &peer->su, htons(peer->port), ifindex);
}

int ppp_tcp_client_connect_check (struct thread *thread)
{
	int ret, status;
	socklen_t slen;
	struct ppp_mcp_sock *peer;

	/* Yes first of all get peer pointer. */
	peer = THREAD_ARG (thread);
	peer->t_check = NULL;

	/* Check file descriptor. */
	slen = sizeof (status);
	ret = getsockopt (peer->fd, SOL_SOCKET, SO_ERROR, (void *) & status, &slen);

	/* If getsockopt is fail, this is fatal error. */
	if (ret < 0) {
		PPPD_DEBUG_TCP("can't get sockopt for nonblocking connect");
	    goto error;
	}

	/* When status is 0 then TCP connection is established. */
	if (status == 0)
	{
		ppp_tcp_client_established (peer);
	}
	else
	{
//		ZLOG_INFO("[TCP CLIENT FSM] %s TCP Connect failed (%s)", peer->hostname, safe_strerror (errno) );
        PPPD_DEBUG_TCP("client connect server mcp error\n");
		goto error;
	}

    return 0;

error:
	ppp_connect_mcp_error_deal(peer);
	return 0;
}

int ppp_client_connection_mcp (struct thread *thread)
{
	struct ppp_mcp_sock *peer;
	//struct listnode *nn, *nm;
	unsigned int ifindex = 0;
	int ret;
	
    peer = THREAD_ARG (thread);
	peer->t_connect_admin = NULL;

    MCP_TIMER_ON (peer->t_connect_admin, ppp_client_connection_mcp, peer, MCP_TRANS_TCP_RECONNECT_ADMIN_TIME);
    
    if(peer->connect_status == CLIENT_CONNECT_SERVER_OK)
        return 0;

    if(peer->fd > 0) {
		close(peer->fd);
		peer->fd = -1;
	}
	
	peer->fd = sockunion_socket (&peer->su);
	if (peer->fd < 0) {
        PPPD_DEBUG_TCP("ppp client connect server peer:%s error", peer->hostname);
		return -1;
    }
    sockopt_reuseaddr (peer->fd);
	sockopt_reuseport (peer->fd);
	ret = sockunion_connect(peer->fd, &peer->su, htons(peer->port), ifindex);
	if(ret == connect_error) {
        PPPD_DEBUG_TCP("client connect server err");
        return -1;
	}
        
	MCP_WRITE_ON (peer->t_check, ppp_tcp_client_connect_check, peer, peer->fd);

	return 0;
}

static int ppp_tcp_wait_notify_ack_timer (struct thread *thread)
{
	struct ppp_mcp_sock *peer;
    
	peer = THREAD_ARG (thread);
	peer->t_wait_ipinfo_ack = NULL;
	
	PPPD_DEBUG_TCP("[TCP CLIENT FSM] Timer (wait ipinfo timer expire), peer:%s", peer->hostname);
	ppp_connect_mcp_error_deal(peer);
	return 0;
}

extern void ppp_all_ipinfo_tos(struct stream* s_new);
void remark_all_ipinfo_notify_mcp(void)
{
//    struct remark_ipinfo ipinfo;
    struct ppp_mcp_sock *peer;
    struct stream* s_new;
    
    peer = g_ppp_mcp_sock;

    PPPD_DEBUG_TCP("pppd send all ip info to mcp ..");
    s_new = stream_new(1024);
    ppp_all_ipinfo_tos(s_new);
    stream_fifo_push (peer->obuf, s_new);
    
    MCP_WRITE_ON (peer->t_write, ppp_tcp_write, peer, peer->fd);
//    MCP_TIMER_ON (peer->t_wait_ipinfo_ack, ppp_tcp_wait_notify_ack_timer, peer, CLIENT_WAIT_IPINFO_ACK_TIMER);

    return;
}

void remark_bundle_notify_mcp(unsigned int ifnum, unsigned int ifunit)
{
    struct remark_bundle bundleinfo;
    struct ppp_mcp_sock *peer;
    struct stream* s_new;

    return;
    peer = g_ppp_mcp_sock;
    
    bundleinfo.master = ifnum;
    bundleinfo.slave = ifunit;

    s_new = stream_new(1024);
    stream_putl(s_new, 4 + sizeof(struct remark_bundle));
    ppp_put_control_to_stream(s_new, REMARK_BUDLE_CMD);
    stream_put(s_new, (unsigned char*)(&bundleinfo), sizeof(struct remark_bundle));
    stream_fifo_push (peer->obuf, s_new);

    MCP_WRITE_ON (peer->t_write, ppp_tcp_write, peer, peer->fd);
//    MCP_TIMER_ON (peer->t_wait_bundle_ack, ppp_tcp_wait_notify_ack_timer, peer, CLIENT_WAIT_IPINFO_ACK_TIMER);

    return;
}

int ppp_remark_mem_init(void)
{
    remark_channel_init();   
    if(ppp_remark_mem_malloc() == -1) {
        PPPD_DEBUG_TCP("ppp malloc mem err");
        return -1;
    }

    return 0;
}

int ppp_remark_tcp_init(void)
{
    struct ppp_mcp_sock *peer;
    
    peer = g_ppp_mcp_sock;
    
	MCP_TIMER_ON(peer->t_connect_admin, ppp_client_connection_mcp, peer, 0);

    return 0;
}

