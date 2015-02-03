#include "config.h"
#include "zebra.h"
#include "sockunion.h"

#include "pppd.h"
#include "ppp_remark.h"
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "stream.h"
#include "fsm.h"
#include "pathnames.h"
struct ppp_interface *ppp_if[NUM_PPP];
struct remark_ipinfo remark_ipinfo_all[NUM_PPP];

extern int ppp_remark_establish_ppp(int unit);
extern void ppp_remark_disestablish_ppp(int unit);

//见start_link
struct channel remark_channel = {
    options: NULL,
    process_extra_options: NULL,
    check_options: NULL,
    connect: NULL,
    disconnect: NULL,
    establish_ppp: &ppp_remark_establish_ppp,
    disestablish_ppp: &ppp_remark_disestablish_ppp,
    send_config: NULL,
    recv_config: NULL,
    close: NULL,
    cleanup: NULL
};
extern u_int32_t xmit_accm[8];	

void remark_channel_init()////channel初始化，默认就是全局的tty_channel，里面包括很多TTY函数指针   
{
    the_channel = &remark_channel;
    xmit_accm[3] = 0x60000000;
}

void pppd_interface_neg_variable_init(struct ppp_interface *pif)
{
    struct chap_client_state *cs = &(pif->client);
    
    pif->is_master = 0;
    pif->doing_multilink = 0;
    pif->is_ipcp_up = 0;
    pif->attach_to_unit = -1;
    pif->auth_ok = 0;
    pif->is_lcp_up = 0;

    cs->flags &= ~AUTH_STARTED;
}

void ppp_if_mem_malloc(void)
{
    int i = 0;//, k = 0;
    struct ppp_interface *pif;

    memset((char*)remark_ipinfo_all, 0 , sizeof(struct remark_ipinfo) * NUM_PPP);
    for(i = 0; i < NUM_PPP; i++) {
        ppp_if[i] = malloc(sizeof(struct ppp_interface));

        pif = ppp_if[i];
        memset(pif, 0, sizeof(struct ppp_interface));
        pif->unit = i;
    	pif->sconfreq_timeout = DEFTIMEOUT;
    	pif->maxsconfreq_times = DEFMAXCONFREQS;
    	pif->lcp.echo_interval = DEFTIMEOUT;
        snprintf(pif->ifname, sizeof(pif->ifname), "ppp%u", i);
        
    	pif->out_buf = malloc(PPP_MRU + PPP_HDRLEN + 4 + 1000);
    	memset(pif->out_buf, 0, PPP_MRU + PPP_HDRLEN + 4 + 1000);
        pif->ppp_dev_fd = -1;
        pif->dev_fd = -1;

        pppd_interface_neg_variable_init(pif);
    }
}

void ppp_if_mem_free(void)
{
    int i;
    
    for(i = 0; i < NUM_PPP; i++) {
        if(ppp_if[i] == NULL)
            continue;

        if(ppp_if[i]->out_buf != NULL)
            free(ppp_if[i]->out_buf);
        free(ppp_if[i]);
        ppp_if[i] = NULL;
    }
}

void ppp_remark_del_interface(unsigned int if_num)
{
//    struct ppp_interface *pif;

    if(!PPP_IF_INDEX_RANGE_OK(if_num)) {
        ZLOG_INFO("ppp del interface err, ifindex:%u\n", if_num);
        return;
    }

    //pif = ppp_if[if_num];

    //memset(pif, 0, sizeof(struct ppp_interface));

    return;
}

void mcp_pppd_init_one_local_interface(int unit)
{
    struct ppp_interface *pif = ppp_if[unit];
    lcp_options *wo = &(ppp_if[unit]->lcp.lcp_wantoptions);
    
    pif->unit = unit;
    pif->enable = 0;
    pif->local_ip = 0;
    memset(pif->pap_user, 0, sizeof(pif->pap_user));
    memset(pif->pap_passwd, 0, sizeof(pif->pap_passwd));
    memset(pif->chap_user, 0, sizeof(pif->chap_user));
    memset(pif->chap_passwd, 0, sizeof(pif->chap_passwd));
    pif->multilink_flags = 0;
    pif->mp_ifindex = 0;
	pif->sconfreq_timeout = DEFTIMEOUT;
	pif->maxsconfreq_times = DEFMAXCONFREQS;
	pif->lcp.echo_interval = DEFTIMEOUT;
	pif->attach_to_unit = -1;
	wo->neg_upap = wo->neg_chap = 0;
	wo->chap_mdtype = 0;
	pppd_interface_neg_variable_init(pif); /* 这里不能调用该函数，否则在不是能接口的时候会影响pppd_interface_disable中的lcp_close流程 */
}

int mcp_pppd_interface_changed(struct pppd_interface_info *info)
{
    unsigned int unit = info->interfaceid;
    struct ppp_interface *pif = ppp_if[unit];
    lcp_options *wo;
    int oldauth;

    if(pif == NULL)
        return 0;

    if(info->enable == 0) //删除操作会在外层做处理
        return 0;
        
    if(info->multi_group == 0 && remark_str2ip(info->interfaceip) != pif->local_ip)
        return 1;

    wo = &(ppp_if[unit]->lcp.lcp_wantoptions);
    if(wo->neg_upap == 1)
        oldauth = PPP_IF_AUTH_PAP;
    else if(wo->neg_chap == 1)
        oldauth = PPP_IF_AUTH_CHAP;
    else  
        oldauth = PPP_IF_AUTH_NO;
        
    if(info->auth_type != oldauth)
        return 1;

    if(info->auth_type == PPP_IF_AUTH_PAP && 
      (strcmp(info->username, pif->pap_user) != 0 || strcmp(info->pswd, pif->pap_passwd) != 0))
        return 1;

    if(info->auth_type == PPP_IF_AUTH_CHAP && 
     (strcmp(info->username, pif->chap_user) != 0 || strcmp(info->pswd, pif->chap_passwd) != 0))
        return 1;
}

int mcp_ppp_interface_info_update_local(struct pppd_interface_info *info)
{
    unsigned int unit = info->interfaceid;
    struct ppp_interface *pif = ppp_if[unit];
    int old_enable = pif->enable;
    struct multilink_if_info* mul_info;

    if(info->action == ppp_OP_DEL) {
        pppd_interface_disable(unit); 
        mcp_pppd_init_one_local_interface(unit);
        return 0;
    }

    if(info->enable == 0) {
        pppd_interface_disable(unit); 
    }

    mcp_pppd_init_one_local_interface(unit);
    pif->enable = info->enable;
    pif->mp_ifindex = info->multi_group;
    if(pif->mp_ifindex > 0)
        pif->multilink_flags = 1;
        
    if(pif->mp_ifindex == 0 && strlen(info->interfaceip) > 0)
        pif->local_ip = remark_str2ip(info->interfaceip);
    else {
        mul_info = ppp_remark_lookup_multilink_interface(pif->mp_ifindex);
        if(mul_info == NULL) {
            ZLOG_INFO("pppd interface info deal error, mul_info = NULL, MP:%u", pif->mp_ifindex);
        } else {
            pif->local_ip = mul_info->multi_ip;
        }
    }
    
    ppp_if_enable_auth(unit, info->auth_type);
    memset(pif->pap_user, 0, sizeof(pif->pap_user));
	memset(pif->pap_passwd, 0, sizeof(pif->pap_passwd));
	memset(pif->chap_passwd, 0, sizeof(pif->chap_passwd));
	memset(pif->chap_user, 0, sizeof(pif->chap_user));
   //	if (info->auth_type == PPP_IF_AUTH_PAP) {
		strcpy(pif->pap_user, info->username);
		strcpy(pif->pap_passwd, info->pswd);
	//} else if (info->auth_type == PPP_IF_AUTH_CHAP) {
		strcpy(pif->chap_user, info->username);
		strcpy(pif->chap_passwd, info->pswd);
	//}

    if(old_enable == info->enable) {
        ZLOG_INFO("pif unit:%u, enable not change", unit);
	    return 0;
    }

	if(info->enable == 1) {
        pppd_interface_enable(unit);
    }
    
    return 0;
}

void pppd_interface_start(int unit)
{
	struct ppp_interface *pif;

	if (unit < 0 || unit >= NUM_PPP || ppp_if[unit] == NULL) {
		return;
	}

	pif = ppp_if[unit];
	lcp_open(unit);	/* 这里只是把状态置为f->state = STARTING */	
    start_link(unit);
}

int pppd_interface_enable(int unit)
{
	struct protent *protp;
	int i;
	
	if (unit < 0 || unit >= NUM_PPP || ppp_if[unit] == NULL) {
        ZLOG_INFO("ppp interface unit:%u, error\n", unit);
		return -1;
	}

    /* Initialize each protocol. */
    for (i = 0; (protp = protocols[i]) != NULL; ++i){  /* 这里面设置本地IP地址 */
        (*protp->init)(unit);
 		if (protp->check_options != NULL)
		    (*protp->check_options)(unit); /* 调用ip_check_options */
	}

    new_phase(unit, PHASE_INITIALIZE);
    mp_check_options(unit);
    ppp_remark_create_ppp_unit(unit);
	
	pppd_interface_start(unit);
	return 0;
}

int pppd_interface_disable(int unit)
{
	struct ppp_interface *pif;
    struct multilink_if_info* multi_info;
    char buf[256];
    //fsm *f = GET_LCP_FSM(unit);
    
	if (unit < 0 || unit > NUM_PPP || ppp_if[unit] == NULL) {
		ZLOG_INFO("ppp interface unit:%u, error\n", unit);
		return 0;
	}

	pif = ppp_if[unit];

    snprintf(buf, sizeof(buf), "no encapsulate ppp, unit:%u", unit);
	lcp_close(unit, buf);
	if (pif->multilink_flags) {
		multi_info = ppp_remark_lookup_multilink_interface(pif->mp_ifindex);
		if(multi_info == NULL) {
            ZLOG_INFO("interface index:%u, not add group:%u", pif->unit, pif->mp_ifindex);
		} else {
            PPP_CLEAR_MULTI_BIT(multi_info->interface_bit, pif->unit);
		}
	}

	//UNTIMEOUT(fsm_timeout, f);
	//UNTIMEOUT(fsm_auto_start, f);
	the_channel->disestablish_ppp(unit);	
	
    pif->enable = 0;
	pppd_interface_neg_variable_init(pif);
	return 0;
}

int mcp_pppd_have_channel_to_group(struct multilink_if_info* multi_info)
{
    unsigned int interface_bit;
    int i;
    
    interface_bit = multi_info->interface_bit;
    for(i = 0; i < NUM_PPP; i++) {
        if(!PPP_MULTI_BIT_IS_ZERO(interface_bit, i))
            return 1;
    }

    return 0;
}

int mcp_pppd_disable_allinterface_addto_group(struct multilink_if_info* multi_info)
{
    unsigned int interface_bit;
    int i;
    struct ppp_interface *pif;

    interface_bit = multi_info->interface_bit;
    for(i = 0; i < NUM_PPP; i++) {
        if(!PPP_MULTI_BIT_IS_ZERO(interface_bit, i)) { //multilink IP发生变化，需要重新协商           
            pppd_interface_disable(i);

            pif = ppp_if[i];
            if(pif == NULL)
                continue;

            pif->enable = 1;
            pppd_interface_enable(i);
        }
    }

    return 0;
}

int mcp_pppd_update_allinterface_addto_group(unsigned int old_multi_ip, unsigned int new_multi_ip)
{
    int i;
    struct ppp_interface *pif;

    for(i = 0; i < NUM_PPP; i++) {        
        pif = ppp_if[i];
        if(pif == NULL)
            continue;

        if(pif->local_ip == old_multi_ip)
            pif->local_ip = new_multi_ip;
    }

    return 0;
}



struct ppp_interface* mcp_pppd_is_channel_to_group(struct multilink_if_info* multi_info, unsigned int channel)
{
    unsigned int interface_bit;
    struct ppp_interface *pif;

    pif = ppp_if[channel];
    interface_bit = multi_info->interface_bit;
    if(!PPP_MULTI_BIT_IS_ZERO(interface_bit, channel))
        return pif;

    return NULL;
}

void mcp_pppd_init_all_local_interface(void)
{
    int i;
   
    for(i = 0; i < NUM_PPP; i++) {
        mcp_pppd_init_one_local_interface(i);
    }
}

int ppp_if_close_all_enalbe_channel(void)
{
    int i;
    struct ppp_interface *pif;

    for(i = 0; i < NUM_PPP; i++) {
        pif = ppp_if[i];
        if(pif == NULL)
            continue;

        if(pif->enable == 1)
            pppd_interface_disable(i); ;  
    }

    return 0;
}

struct ppp_interface * ppp_if_exist_mp_mater(unsigned int group)
{
    int i;
    struct ppp_interface *pif;

    if(group == 0)
        return NULL;
    
    for(i = 0; i < NUM_PPP; i++) {
        pif = ppp_if[i];
        if(pif == NULL || pif->mp_ifindex == 0)
            continue;

        //printf("yang test ................ ppp if exist mp master:%u  ismaster:%u\n", pif->mp_ifindex, pif->is_master);  
        if(pif->mp_ifindex == group && pif->is_master == 1)
            return pif;  
    }

    return NULL;
}

int ppp_if_get_mp_mater(unsigned int unit)
{
    int i;
    struct ppp_interface *pif, *tmp_if;
    int group;
    
    pif = ppp_if[unit];
    group = pif->mp_ifindex;
    
    if(group == 0)
        return -1;
    
    for(i = 0; i < NUM_PPP; i++) {
        tmp_if = ppp_if[i];
        if(tmp_if == NULL || tmp_if->mp_ifindex == 0)
            continue;

        if(tmp_if == pif)
            continue;

        if(tmp_if->mp_ifindex == group && tmp_if->is_master == 1)
            return i;  
    }

    return -1;
}

int ppp_have_interface_is_enable(void)
{
    int i;
    struct ppp_interface *pif;
    
    for(i = 0; i < NUM_PPP; i++) {
        pif = ppp_if[i];
        if(pif == NULL)
            continue;

        if(pif->enable == 1)
            return 1;
    }

    return 0;
}

void ppp_set_ifip_by_groupip(unsigned int group, unsigned int groupip)
{
    int i;
    
    for(i = 0; i < NUM_PPP; i++) {
        if(ppp_if[i] == NULL)
            continue;
            
        if(ppp_if[i]->mp_ifindex == group)
            ppp_if[i]->local_ip = groupip;
    }
}

extern void ppp_one_if_create(int unit);
void ppp_if_create_init(void)
{
    int i;
    
    for(i = 0; i < NUM_PPP; i++) {
        ppp_one_if_create(i);
    }
}

void ppp_all_ipinfo_tos(struct stream* s_new)
{
    stream_putl(s_new, 4 + sizeof(struct remark_ipinfo) * NUM_PPP);
    stream_putl(s_new, REMARK_ALL_IPINFO_CMD);
    stream_put(s_new, (unsigned char*)(remark_ipinfo_all), sizeof(struct remark_ipinfo) * NUM_PPP);
    
    return;
}

void ppp_init_db_file(void)
{
    char tmp_buf[256];
    
    snprintf(tmp_buf, sizeof(tmp_buf), "echo > %s", _PATH_PPPDB);
    system(tmp_buf);
}

