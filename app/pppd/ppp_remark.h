#ifndef __PPP_REMARK_H__
#define __PPP_REMARK_H__

#include "thread.h"

#ifndef u8
#define u8 unsigned char
#endif

#ifndef u16
#define u16 unsigned short
#endif

#ifndef u32
#define u32 unsigned int
#endif

#ifndef u64
#define u64 unsigned long long
#endif

#define REMARK_BUDLE_CMD     30
#define REMARK_IPINFO_CMD    41
#define REMARK_KEEPALIVE_CMD 52
#define REMARK_ALL_IPINFO_CMD  53

#define REMARK_IPINFO_CMD_ACK 511
#define REMARK_BUDLE_CMD_ACK 512

#define TIMER_COUNT      525 

#define MCP_PPP_HEADER_SIZE 8

#define PPP_IF_AUTH_NO  30
#define PPP_IF_AUTH_PAP 331
#define PPP_IF_AUTH_CHAP 42

#define REFORM_PPP_REMOTE_USERINFO_ACK 0X51
#define REFORM_PPP_MULTILINK_INFO_ACK 0X53
#define REFORM_PPP_INTERFACE_INFO_ACK 0X55
#define REFORM_PPP_ALL_CONFIG_SYN 0X56


#define PPP_IF_INDEX_RANGE_OK(ifindex) (ifindex >= 0 && ifindex < 16)
#define PPP_MULTI_GROUP_RANGE_OK(group) (group > 0 && group <= 100)
#define PPP_SET_MULTI_BIT(data, bit) (data |= (1 << bit));
#define PPP_CLEAR_MULTI_BIT(data, bit) (data &= ~(1 << bit))
#define PPP_MULTI_BIT_IS_ZERO(data, bit) ((data & (1 << bit)) == 0)

struct remark_ipinfo {
    unsigned int is_slave;
    unsigned int channo;
    unsigned int our_ip;
    unsigned int his_ip;
    unsigned int mask;
};

struct remark_bundle {
    unsigned int master;
    unsigned int slave;
};

struct remark_notice_mcp {
    int cmd;
    union {
        struct remark_ipinfo ipinfo;
        struct remark_bundle bundleinfo;
    };
};

#define MCP_PPPD_TCP_PORT 2321
#define MCP_PPPD_TCP_ADDR "122.20.0.1"


#define MCP_TRANS_TCP_RECONNECT_ADMIN_TIME 320
#define CLIENT_CONNECT_SERVER_OK  31
#define CLIENT_CONNECT_KEEPALIVE_TIMER 330
#define CLIENT_HOLD_TIME_EXPIRE 390
#define CLIENT_WAIT_IPINFO_ACK_TIMER 315
#define CLIENT_WAIT_BUNDINFO_ACK_TIMER 315

struct multilink_if_info {
    unsigned int multi_num;
    unsigned int multi_ip;

    //只有协商成功后才会添加进来
    unsigned int interface_bit;/* 记录有哪些接口添加到该multilink组中，以位图表示，如该值为3表示接口2加入该组 */
};

struct remote_userinfo {
    char remote_name[50];
    char remote_pwd[50];
};

#define ppp_REMOTEINFO_SEQ       30 
#define ppp_REMOTEINFO_GWID      31 
#define ppp_REMOTEINFO_DEV_TYPE  32 
#define ppp_REMOTEINFO_USERNAME  33
#define ppp_REMOTEINFO_PASSWD    34
#define ppp_REMOTEINFO_TIME      35
#define ppp_REMOTEINFO_REMARK    36
#define ppp_REMOTEINFO_ACTION    37

#define PPP_OP_EDIT 3
#define PPP_OP_ADD  12
#define ppp_OP_DEL  122

struct pppd_remote_userinfo {
    unsigned int seq;
    unsigned int gwid;
    unsigned int dev_type;
    char username[50];
    char passwd[50];
    char create_time[40];
    unsigned int action;
    char remark[50];
};

#define PPP_MULTILINK_INFO_SEQ      10
#define PPP_MULTILINK_INFO_GWID     11
#define PPP_MULTILINK_INFO_MULTIIP  12
#define PPP_MULTILINK_INFO_TIME     13
#define PPP_MULTILINK_INFO_REMARK   14
#define PPP_MULTILINK_INFO_ACTION   15

struct pppd_multilink_info {
    unsigned int seq;
    unsigned int gwid;
    char multi_ip[30];
    char create_time[40];
    unsigned int action;
    char remark[50];
};

#define PPP_INTERFACE_SEQ         10
#define PPP_INTERFACE_GWID        11
#define PPP_INTERFACE_SEVTYPE     12
#define PPP_INTERFACE_INTERFACEID 13
#define PPP_INTERFACE_MULTIFLAGE  14
#define PPP_INTERFACE_INTERFACEIP 15
#define PPP_INTERFACE_ENABLE      16
#define PPP_INTERFACE_AUTHTYPE    17
#define PPP_INTERFACE_AUTHNAME    18 /* 这个和7是重复的 */
#define PPP_INTERFACE_USERNAME    19
#define PPP_INTERFACE_PSWD        20
#define PPP_INTERFACE_TIME        21
#define PPP_INTERFACE_REMARK      22
#define PPP_INTERFACE_ACTION      23

struct pppd_interface_info {
    unsigned int seq;
    unsigned int gwid;
    unsigned int dev_type;
    unsigned int interfaceid;
    unsigned int multi_group; /*  大于0表示加入到了这个multilink组，如果未0，表示为非multilink方式  在命令中设置ppp multilink group <1-100>*/
    char interfaceip[20];
    unsigned int enable;
    unsigned int auth_type;
    char auth_name[30];
    char username[50];
    char pswd[50];
    char time[30];
    char remark[50];
    unsigned int action;
};

#define MCP_PPPD_CONFIG_SYN_REMOT_USERINFO   10
#define MCP_PPPD_CONFIG_SYN_MULTILINK_INFO   11
#define MCP_PPPD_CONFIG_SYN_INTERFACE_INFO   12


extern int remark_socket;
extern struct remark_ipinfo g_ipinfo;
extern struct remark_bundle g_bundleinfo;
extern struct list* multilink_if_list;
extern struct list* remote_userinfo_list;
extern struct thread_master *master;

extern void ZLOG_EXT_BASE(const char* filename, int lineno, const char* fmt, ...);
#define ZLOG_INFO_EXT(...) ZLOG_EXT_BASE(__FILE__, __LINE__,  __VA_ARGS__)
#define ZLOG_INFO(...) ZLOG_INFO_EXT(__VA_ARGS__)

#define MCP_READ_ON(T,F,A,S)	THREAD_READ_ON(master,T,F,A,S)
#define MCP_READ_OFF(X)      	THREAD_READ_OFF(X)
#define MCP_WRITE_ON(T,F,A,S)	THREAD_WRITE_ON(master,T,F,A,S)
#define MCP_WRITE_OFF(X)     	THREAD_WRITE_OFF(X)
#define MCP_TIMER_ON(T,F,A,S)	THREAD_TIMER_ON(master,T,F,A,S)
#define MCP_TIMER_OFF(X)      	THREAD_TIMER_OFF(X)

void remark_init();
int ppp_remark_create_ppp_unit();
int remark_log_socket (void);
int remark_stream_send(unsigned char* data, int size);
void remark_cfg_route(unsigned int default_gw);
void remark_one_ipinfo_notify_mcp(unsigned int ouraddr, unsigned int hisaddr, int mask, int ifunit);
void remark_bundle_notify_mcp(unsigned int ifnum, unsigned int ifunit);
void alarm_timer_init(void);
void ppp_log_destroy(void);
const char *remark_ip2str (u_int32_t addr);
int ppp_if_enable_auth(int unit, int type);
void ppp_remark_mem_free(void);
void ppp_remark_add_remote_userinfo(struct remote_userinfo* userinfo);
void ppp_remark_del_remote_userinfo(struct remote_userinfo* userinfo);
void ppp_remark_add_multilink_interface(struct multilink_if_info* info);
void ppp_remark_del_multilink_interface(unsigned int multi_num);
void ppp_remark_del_interface(unsigned int if_num);
void ppp_remark_interface_addto_multilink(int inter, int multi_num);
void ppp_remark_interface_del_from_multilink(int inter, int multi_num);
struct multilink_if_info* ppp_remark_lookup_multilink_interface(unsigned int multi_num);
struct remote_userinfo* ppp_remark_lookup_remote_userinfo(char *remote_name);
int ppp_remark_mem_init(void);
int ppp_tcp_write (struct thread *thread);
int ppp_tcp_read(struct thread *thread);
const unsigned int remark_str2ip(const char *ip_str);
int ppp_remark_check_remote_userinfo(char* remote_name, char* remote_pwd);
int ppp_get_user_passwd(char *username, char *passwd, int *pass_len);

extern int ppp_remark_create_ppp_unit(int unit);
int pppd_interface_enable(int unit);
int pppd_interface_disable(int unit);
int ppp_remark_tcp_init(void);
void remark_all_ipinfo_notify_mcp(void);

#endif

