
/* Copyright(C) 2012 fenyun Network. All rights reserved.
 */
/*
 * nc_vty.c
 *
 * CLI命令相关初始化和处理函数
 *
 * History
 *
 */
#include "config.h"
#include "zebra.h"
#include "sockunion.h"
#include "thread.h"
//#include "zserv.h"
#include "if.h"

#include "command.h"
#include "linklist.h"
#include "zserv.h"
#include "if.h"
#include "zebra.h"
#include "thread.h"
#include "memory.h"
#include "log.h"  
#include "sigevent.h" 
#include "vty.h"
#include "pppd.h"
#include "ppp_remark.h"
#include "prefix.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "pppd_tmp.h"
#include "memory.h"

#include "config.h"
#include "zebra.h"
#include "sockunion.h"
#include "pppd_tmp.h"
#include "pppd_debug.h"

struct thread_master *master;
char *pppd_config_file = "/usr/local/co3nf/pppd.conf";
#define NC_DEFAULT_VTY_PORT 3335

#define MCP_DEFAULT_PID_FILE		"pppd.pid"
char *mcp_pid_file =  MCP_DEFAULT_PID_FILE;

static struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
  1,
};

DEFUN (ppp_remark_ip,
		ppp_remark_ip_cmd,
		"ip address A.B.C.D",
		"Config ip of the interface\n" "Set the IP address of an interface\n"
		"A.B.C.D\n")
{
	int ret;
    int index;
	union sockunion su; /* 这里一定要注意，如果是用系统的头文件的时候，是不包含sockaddr_in6的，容易越界，所以这里务必使用zebra的头 */
//    struct multilink_if_info* mul_if;
    struct interface *ifp;
    
    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

	ret = str2sockunion (argv[0], &su);
	if (ret < 0)
	{
		vty_out (vty, "%% Malformed address: %s%s", argv[0], VTY_NEWLINE);

		return CMD_WARNING;
	}

    ppp_if[index]->local_ip = ntohl(su.sin.sin_addr.s_addr);
    vty_out (vty, "ip address %s %s", remark_ip2str(ppp_if[index]->local_ip), VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_ppp_remark_ip,
		no_ppp_remark_ip_cmd,
		"no ip address", 
		"no\n"
		"Config ip of the interface\n" 
		"Set the IP address of an interface\n")
{
    struct interface *ifp;
    int index;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    ppp_if[index]->local_ip = 0;
    vty_out (vty, "no ip address%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


DEFUN (ppp_remark_encapsulate_ppp,
		ppp_remark_encapsulate_ppp_cmd,
		"encapsulate ppp",
		"Encapsulate\n" " Encapsulate ppp on Serial.\n")
{
    struct interface *ifp;
    int index;
    struct ppp_interface *pif;
    int ret;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    pif = ppp_if[index];
    if(pif->enable == 1) {
        vty_out (vty, "encapsulate ppp%s", VTY_NEWLINE);
	    return CMD_SUCCESS;
    }

    ret = pppd_interface_enable(index);
    if(ret !=0) {
        vty_out (vty, "encapsulate ppp%s error, pif=NULL", VTY_NEWLINE);
        return CMD_WARNING;
    }

    pif->enable = 1;
    vty_out (vty, "encapsulate ppp%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_ppp_remark_encapsulate_ppp,
		no_ppp_remark_encapsulate_ppp_cmd,
		"no encapsulate ppp",
		"no\n"
		"Encapsulate\n" 
		"Encapsulate ppp on Serial.\n")
{
    struct interface *ifp;
    int index;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(ppp_if[index]->enable == 0) {
        vty_out (vty, "no encapsulate ppp%s", VTY_NEWLINE);
	    return CMD_SUCCESS;
    }
    
    ppp_if[index]->enable = 0;
    pppd_interface_disable(index);
    vty_out (vty, "no encapsulate ppp%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (ppp_remark_auth_ppp,
		ppp_remark_auth_ppp_cmd,
		"ppp authentication (chap|pap)",
		"Set ppp protocol parameters\n" "Enable ppp authentication service\n" 
		"Chap authentication\n" "Pap authentication\n")
{
    struct interface *ifp;
    int index;
    int authmode;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(strncmp(argv[0], "c", 1) == 0)
        authmode = PPP_IF_AUTH_CHAP;
    else if(strncmp(argv[0], "p", 1) == 0)
        authmode = PPP_IF_AUTH_PAP;
    else
        authmode = PPP_IF_AUTH_NO;

    ppp_if_enable_auth(index, authmode);
    
    vty_out (vty, "ppp authentication %s%s", argv[0], VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_ppp_remark_auth_ppp,
		no_ppp_remark_auth_ppp_cmd,
		"no ppp authentication",
		"no\n"
		"Set ppp protocol parameters\n" 
		"Enable ppp authentication service\n")
{
    struct interface *ifp;
    int index;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    ppp_if_enable_auth(index, PPP_IF_AUTH_NO);
    
    vty_out (vty, "no ppp authentication %s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (ppp_remark_ppp_chap_hostname,
		ppp_remark_ppp_chap_hostname_cmd,
		"ppp chap hostname NAME",
		"set ppp protocol parameters\n" "chap\n" "Add hostname\n" "Alternate CHAP hostname")
{
    struct interface *ifp;
    int index;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    memset(ppp_if[index]->chap_user, 0, sizeof(ppp_if[index]->chap_user));
    strcpy(ppp_if[index]->chap_user, argv[0]);

    vty_out (vty, "ppp chap hostname %s%s", ppp_if[index]->chap_user, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_ppp_remark_ppp_chap_hostname,
		no_ppp_remark_ppp_chap_hostname_cmd,
		"no ppp chap hostname",
		"no\n"
		"set ppp protocol parameters\n" "chap\n" "Add hostname\n")
{
    struct interface *ifp;
    int index;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    memset(ppp_if[index]->chap_user, 0, sizeof(ppp_if[index]->chap_user));

    vty_out (vty, "no ppp chap hostname%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


DEFUN (ppp_remark_ppp_chap_pwd,
		ppp_remark_ppp_chap_pwd_cmd,
		"ppp chap password NAME",
		"set ppp protocol parameters\n" "chap\n" "Add password\n" "Alternate CHAP password")
{
    struct interface *ifp;
    int index;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    memset(ppp_if[index]->chap_passwd, 0, sizeof(ppp_if[index]->chap_passwd));
    strcpy(ppp_if[index]->chap_passwd, argv[0]);

    vty_out (vty, "ppp chap password %s%s", ppp_if[index]->chap_passwd, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_ppp_remark_ppp_chap_pwd,
		no_ppp_remark_ppp_chap_pwd_cmd,
		"no ppp chap password",
		"no\n"
		"set ppp protocol parameters\n" "chap\n" "password\n")
{
    struct interface *ifp;
    int index;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    memset(ppp_if[index]->chap_passwd, 0, sizeof(ppp_if[index]->chap_passwd));

    vty_out (vty, "no ppp chap password%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (if_ppp_pap_username_password,
     if_ppp_pap_username_password_cmd,
     "ppp pap sent-username NAME password WORD",
     "Set ppp protocol parameters\n" 
     "Set PAP authentication parameters\n" 
     "Set outbound PAP username\n" 
     "Outbound PAP username\n" 
     "Set outbound PAP password\n"
     "Outbound PAP password\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    pif = ppp_if[index];
    
	snprintf(pif->pap_user, sizeof(pif->pap_user), "%s", argv[0]);
	snprintf(pif->pap_passwd, sizeof(pif->pap_passwd), "%s", argv[1]);
	
    vty_out (vty, "ppp pap sent-username %s password %s%s", pif->pap_user, pif->pap_passwd, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_if_ppp_pap_username_password,
     no_if_ppp_pap_username_password_cmd,
     "no ppp pap sent-username",
     "no\n"
     "Set ppp protocol parameters\n" 
     "Set PAP authentication parameters\n" 
     "Set outbound PAP username\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    pif = ppp_if[index];

	memset(pif->pap_user, 0, sizeof(pif->pap_user));
	memset(pif->pap_passwd, 0, sizeof(pif->pap_passwd));
	
    vty_out (vty, "no ppp pap sent-username%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


DEFUN (if_ppp_config_timeout,
     if_ppp_config_timeout_cmd,
     "ppp config-timeout <1-255>",
     "Set ppp protocol parameters\n"
     "Set the timeout value of config_request\n"
     "Set the seconds timeout value of config_request\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;
    int timeout;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }
    
	pif = ppp_if[index];
	
	timeout = atoi(argv[0]);
	if (timeout > 0) {
		pif->sconfreq_timeout = timeout;
	}

    vty_out (vty, "ppp config-timeout %u%s", pif->sconfreq_timeout, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_if_ppp_config_timeout,
     no_if_ppp_config_timeout_cmd,
     "no ppp config-timeout",
     "Set ppp protocol parameters\n"
     "Set the timeout value of config_request\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;
//    int timeout;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }
    
	pif = ppp_if[index];

	pif->sconfreq_timeout = DEFTIMEOUT;

    vty_out (vty, "no ppp config-timeout%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


DEFUN (if_ppp_echo_timeout,
     if_ppp_echo_timeout_cmd,
     "ppp echo-timeout <0-65535>",
     "Set ppp protocol parameters\n"
     "Set the time value between echo request\n"
     "Time value between echo request\n")
{
	struct interface *ifp;
    int index;
    int timeout;
    struct ppp_interface *pif;
    int old;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }
    
	pif = ppp_if[index];

	old = pif->lcp.echo_interval;
	timeout = atoi(argv[0]);
	pif->lcp.echo_interval = timeout;

	if (timeout == 0) {
		lcp_echo_lowerdown(index);
	} else if (old == 0) {
		lcp_echo_lowerup(index);
	}

	return CMD_SUCCESS;
}

DEFUN (no_if_ppp_echo_timeout,
     no_if_ppp_echo_timeout_cmd,
     "no ppp echo-timeout",
     "Set ppp protocol parameters\n"
     "Set the time value between echo request\n")
{
	struct interface *ifp;
    int index;
   // int timeout;
    struct ppp_interface *pif;
  //  int old;

    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }
    
	pif = ppp_if[index];

	pif->lcp.echo_interval = DEFTIMEOUT;

	return CMD_SUCCESS;
}

DEFUN (if_ppp_remote_username_password,
     if_ppp_remote_username_password_cmd,
     "username NAME password WORD",
     "username\n" 
     "name\n" 
     "password\n" 
     "WORD\n")
{
    struct remote_userinfo userinfo;
    
	snprintf(userinfo.remote_name, sizeof(userinfo.remote_name), "%s", argv[0]);
	snprintf(userinfo.remote_pwd, sizeof(userinfo.remote_pwd), "%s", argv[1]);

	ppp_remark_add_remote_userinfo(&userinfo);
	
    vty_out (vty, "username %s password %s %s", userinfo.remote_name, userinfo.remote_pwd, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_if_ppp_remote_username_password,
     no_if_ppp_remote_username_password_cmd,
     "no username NAME password WORD",
     "no\n"
     "username\n" 
     "name\n" 
     "password\n" 
     "WORD\n")
{
    struct remote_userinfo userinfo;


	snprintf(userinfo.remote_name, sizeof(userinfo.remote_name), "%s", argv[0]);
	snprintf(userinfo.remote_pwd, sizeof(userinfo.remote_pwd), "%s", argv[1]);

	ppp_remark_del_remote_userinfo(&userinfo);
	
    vty_out (vty, "no username %s password %s %s", argv[0], argv[1], VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (if_ppp_max_configure,
     if_ppp_max_configure_cmd,
     "ppp max-configure <1-65535>",
     "Set ppp protocol parameters\n"
     "Number of conf-reqs sent before assuming peer is unable to respond\n"
     "Number of attempts allowed\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;
    
    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    pif = ppp_if[index];

    pif->maxsconfreq_times = atoi(argv[0]);
    vty_out (vty, "ppp max-configure %u%s", pif->maxsconfreq_times, VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN (no_if_ppp_max_configure,
     no_if_ppp_max_configure_cmd,
     "no ppp max-configure",
     "no\n"
     "Set ppp protocol parameters\n"
     "Number of conf-reqs sent before assuming peer is unable to respond\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;
    
    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    pif = ppp_if[index];

    pif->maxsconfreq_times = DEFMAXCONFREQS;
    vty_out (vty, "no ppp max-configure%s", VTY_NEWLINE);
    return CMD_SUCCESS;
}



DEFUN (if_ppp_add_group,
     if_ppp_add_group_cmd,
     "ppp multilink group <1-100>",
     "ppp\n" 
     "multilink\n" 
     "group\n" 
     "<1-100>\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;
    int group;
    struct multilink_if_info* mul_if;
    
    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    group = atoi(argv[0]);

    mul_if = ppp_remark_lookup_multilink_interface(group);
    if(mul_if == NULL) {
        vty_out(vty, "error, multi group:%u not exist%s", group, VTY_NEWLINE);
        return CMD_WARNING;
    }
    
    if(!PPP_MULTI_GROUP_RANGE_OK(group)) {
        vty_out(vty, "multi group:%u err,range is (0-100)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }
    pif = ppp_if[index];

    pif->mp_ifindex = group;
    pif->multilink_flags = 1;
	//ppp_remark_interface_addto_multilink(index, group);

	if(pif->mp_ifindex > 0) {
        pif->local_ip = mul_if->multi_ip;
    }
	
    vty_out (vty, "ppp multilink group %u%s", group, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (no_if_ppp_add_group,
     no_if_ppp_add_group_cmd,
     "no ppp multilink group",
     "no\n"
     "ppp\n" 
     "multilink\n" 
     "group\n")
{
	struct interface *ifp;
    int index;
    struct ppp_interface *pif;
    int group;
    
    ifp = (struct interface *)vty->index;

    index = ifp->ifindex;
    if(!PPP_IF_INDEX_RANGE_OK(index)) {
        vty_out(vty, "ifindex:%u err,range is (0-15)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }

    group = atoi(argv[0]);

    if(ppp_remark_lookup_multilink_interface(group) == NULL) {
        vty_out(vty, "error, multi group:%u not exist%s", group, VTY_NEWLINE);
        return CMD_WARNING;
    }
    
    if(!PPP_MULTI_GROUP_RANGE_OK(group)) {
        vty_out(vty, "multi group:%u err,range is (0-100)%s", index, VTY_NEWLINE);
        return CMD_WARNING;
    }
    pif = ppp_if[index];

    pif->mp_ifindex = 0;
    pif->multilink_flags = 0;
	ppp_remark_interface_del_from_multilink(index, group);
	
    vty_out (vty, "no ppp multilink group%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN (mcp_ppp_ip_info,
		mcp_ppp_ip_info_cmd,
		"show mcp ppp ip-info",
		"show\n" "mcp\n" "ppp\n" "ip-info")
{
    int i;
    
    vty_out(vty, "show ppp interface ip-info:  %s", VTY_NEWLINE);

	for(i = 0; i < NUM_PPP; i++) {
	    
        if(remark_ipinfo_all[i].our_ip == 0)
            continue;

        vty_out(vty, "chann %u:  local ip(%s), remote ip(%s)%s", i, remark_ip2str(remark_ipinfo_all[i].our_ip),  
        remark_ip2str(remark_ipinfo_all[i].his_ip),VTY_NEWLINE);
	}
    vty_out(vty, "%s", VTY_NEWLINE);
    
	return CMD_SUCCESS;
}


DEFUN (reform_interface,
       reform_interface_cmd,
       "interface xxenterface <0-15>",
       "Select an interface to configure\n"
       "Interface's name\n" "<0-15>\n")
{
  struct interface *ifp;
  size_t sl;
//  char buf[INTERFACE_NAMSIZ + 1];
  
  if ((sl = strlen(argv[0])) > INTERFACE_NAMSIZ)
    {
      vty_out (vty, "%% Interface name %s is invalid: length exceeds "
    	    "%d characters%s",
           argv[0], INTERFACE_NAMSIZ, VTY_NEWLINE);
      return CMD_WARNING;
    }
   
#ifdef SUNOS_5
   ifp = if_sunwzebra_get (argv[0], sl);
#else
   ifp = if_get_by_name_len(argv[0], sl);
#endif  /*SUNOS_5 */

  ifp->ifindex = atoi(argv[0]);
  vty->index = ifp;
  vty->node = INTERFACE_NODE;

  vty_out (vty, "interface xxenterface %s%s", ifp->name, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN_NOSH (no_reform_interface,
           no_reform_interface_cmd,
           "no interface xxinterface <0-15>",
           NO_STR
           "Delete a pseudo interface's configuration\n"
           "Interface's name\n" "xxenterface\n" "<0-15>\n")
{
  // deleting interface
  struct interface *ifp;

  ifp = if_lookup_by_name (argv[0]);

  if (ifp == NULL)
    {
      vty_out (vty, "%% Interface %s does not exist%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (PPP_CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE)) 
    {
      vty_out (vty, "%% Only inactive interfaces can be deleted%s",
	      VTY_NEWLINE);
      return CMD_WARNING;
    }

  ppp_remark_del_interface(ifp->ifindex);

  if_delete(ifp);

  vty_out (vty, "no interface xxenterface %s%s", argv[0], VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (reform_multilink,
       reform_multilink_cmd,
       "interface reform-multilink <1-100> ip A.B.C.D",
       "Select an interface to configure\n"
       "Interface's name\n" "<1-100>\n" "A.B.C.D")
{
    int ret;
	union sockunion su;
	struct multilink_if_info multi_if;
	
    ret = str2sockunion (argv[1], &su);
    if (ret < 0)
    {
    	vty_out (vty, "%% Malformed address: %s%s",
    			argv[0], VTY_NEWLINE);

    	return CMD_WARNING;
    }

    memset(&multi_if, 0, sizeof(struct multilink_if_info));
    multi_if.multi_num = atoi(argv[0]);
  /*  if(ppp_remark_lookup_multilink_interface(multi_if.multi_num) != NULL) {
        vty_out (vty, "error, multilink group:%u have exist %s", multi_if.multi_num, VTY_NEWLINE);
    	return CMD_WARNING;
    }*/
    
    multi_if.multi_ip = ntohl(su.sin.sin_addr.s_addr);
    multi_if.interface_bit = 0;

    ppp_remark_add_multilink_interface(&multi_if);
    vty_out (vty, "interface reform-multilink %u ip %s%s", multi_if.multi_num, remark_ip2str(multi_if.multi_ip), VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN(no_reform_multilink,
           no_reform_multilink_cmd,
           "no interface reform-multilink <1-100>",
           NO_STR
           "Delete a pseudo interface's configuration\n"
           "Interface's name\n" "xxenterface\n" "<1-100>\n")
{
    unsigned int multi_num;
    struct multilink_if_info* p;

    multi_num = atoi(argv[0]);
    p = ppp_remark_lookup_multilink_interface(multi_num);
    if(p == NULL) {
        vty_out (vty, "not exist interface reform-multilink %u%s", multi_num, VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(mcp_pppd_have_channel_to_group(p) == 1) {
        vty_out (vty, "exist channels connect to interface reform-multilink %u, can not del%s", multi_num, VTY_NEWLINE);
        return CMD_WARNING;
    }
    
    ppp_remark_del_multilink_interface(multi_num);
    
    vty_out (vty, "no interface reform-multilink %u%s", multi_num, VTY_NEWLINE);
    return CMD_SUCCESS;
}

#define PPP_PROT_ON_OR_OFF(proto) ((proto == 1) ? "on":"off")
DEFUN (show_pppd_status,
		show_pppd_status_cmd,
		"show ppp negotiat status",
		"show\n" "ppp\n" "negotiat\n" "status\n")
{
//    struct listnode *node;
  //  struct interface *ifp;
    struct ppp_interface *pppif;
    int i;
    int master = -1;
    int slave_num = 0;

    struct multilink_if_info* p;
    struct listnode *nn, *mm;
    struct list* list;
    char tmpbuf[128];
    char slavebuf[128];
    
    list = multilink_if_list;
    for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
        master = -1;
        pppif = ppp_if_exist_mp_mater(p->multi_num);
        if(pppif != NULL)
            master = pppif->unit;

        memset(slavebuf, 0, sizeof(slavebuf));
        for(i = 0; i < NUM_PPP; i++) {
            if(i == master)
                continue;

            if(mcp_pppd_is_channel_to_group(p, i) == NULL)
                continue;
            
            slave_num++;
            if(slave_num == 1)
                snprintf(slavebuf, sizeof(slavebuf), "slave interface:%2u", i);
            else {
                snprintf(tmpbuf, sizeof(tmpbuf), ",%2u", i);
                strcat(slavebuf, tmpbuf);
            }
        }

        if(master == -1 && slave_num == 0)
            continue;

        if(master == -1 && slave_num != 0)
            vty_out (vty,"multilink group:%2u, bitmap:0x%x: (%s)%s", p->multi_num, p->interface_bit, slavebuf, VTY_NEWLINE);

        if(master != -1 && slave_num == 0)
            vty_out (vty,"multilink group %2u, bitmap:0x%x: (master:%2d)%s", p->multi_num, p->interface_bit, master, VTY_NEWLINE);

        if(master != -1 && slave_num != 0)
            vty_out (vty,"multilink group %2u, bitmap:0x%x: (master:%2d, %s)%s", p->multi_num, p->interface_bit, master, slavebuf, VTY_NEWLINE);
    }

    vty_out (vty, "%s", VTY_NEWLINE);
    vty_out (vty, "%s", VTY_NEWLINE);
    
    for(i = 0; i < NUM_PPP; i++) {
        pppif = ppp_if[i];
        if(pppif == NULL)
            continue;

        if(pppif->multilink_flags == 0) {
            vty_out (vty,"xxenterface %3u status: (lcp:%4s, auth:%4s, ipcp:%4s)%s", 
                i, PPP_PROT_ON_OR_OFF(pppif->is_lcp_up),PPP_PROT_ON_OR_OFF(pppif->auth_ok), 
                PPP_PROT_ON_OR_OFF(pppif->is_ipcp_up), VTY_NEWLINE);
            continue;
        }   
        
        if(pppif->is_master != 1)
            vty_out (vty,"xxenterface %3u status: (lcp:%4s, auth:%4s, ipcp:%4s, attach to master:%d)%s", 
                i, PPP_PROT_ON_OR_OFF(pppif->is_lcp_up),PPP_PROT_ON_OR_OFF(pppif->auth_ok), 
                PPP_PROT_ON_OR_OFF(pppif->is_ipcp_up), pppif->attach_to_unit, VTY_NEWLINE);
        else
            vty_out (vty,"xxenterface %3u status: (lcp:%4s, auth:%4s, ipcp:%4s)(master)%s", 
                i, PPP_PROT_ON_OR_OFF(pppif->is_lcp_up),PPP_PROT_ON_OR_OFF(pppif->auth_ok), 
                PPP_PROT_ON_OR_OFF(pppif->is_ipcp_up), VTY_NEWLINE);
    }
    vty_out (vty, "%s", VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (config_pppd_if_debug,
		config_pppd_if_debug_cmd,
		"ppp debug xxenterface <0-15> (on|off)",
		"pppd\n" 
		"debug\n" 
		"xxenterface\n"
		"<0-15>\n"
		"(on|off)\n")
{
    int interfac = atoi(argv[0]);

    if(!PPP_IF_INDEX_RANGE_OK(interfac)) {
        vty_out (vty, "error, interface %u not exist%s", interfac, VTY_NEWLINE);
        return CMD_WARNING;
    }

	if(strcmp(argv[1],"on") == 0)	
		PPP_SET_FLAG(pppd_debug_if, (1<<interfac));
	else 
		PPP_UNSET_FLAG(pppd_debug_if,(1<<interfac));	
    
	return CMD_SUCCESS;
}

DEFUN (config_pppd_ifall_debug,
		config_pppd_ifall_debug_cmd,
		"ppp debug xxenterface all (on|off)",
		"pppd\n" 
		"debug\n" 
		"xxenterface\n"
		"all\n"
		"(on|off)\n")
{
	if(strcmp(argv[0],"on") == 0)	
	    pppd_debug_if = 0xFFFFFFFF;
	else 
		pppd_debug_if = 0;	
    
	return CMD_SUCCESS;
}

DEFUN (show_mcp_debug,
		show_pppd_debug_cmd,
		"ppp debug show",
		"mcp\n" "debug\n" "show\n")
{
	int bRet = 0;
    int i;

    vty_out(vty,"pppd_debug_flags:0x%x pppd_debug_if:0x%x %s", pppd_debug_flags, pppd_debug_if, VTY_NEWLINE);
	bRet = CHECK_FLAG(pppd_debug_flags,DEBUG_TCP_FLAG);
	vty_out(vty,"%12s DEBUG %3s %s", "TCP", bRet ? "ON" : "OFF", VTY_NEWLINE);

	bRet = CHECK_FLAG(pppd_debug_flags,DEBUG_NEG_FLAG);
	vty_out(vty,"%12s DEBUG %3s %s", "NEG", bRet ? "ON" : "OFF", VTY_NEWLINE);

	bRet = CHECK_FLAG(pppd_debug_flags,DEBUG_PKT_FLAG);
	//vty_out(vty,"pppd_debug_flags:0x%x DEBUG_PKT_FLAG:0x%x, ret:%u %s", pppd_debug_flags, DEBUG_PKT_FLAG, bRet, VTY_NEWLINE);
	vty_out(vty,"%12s DEBUG %3s %s", "PACKET", bRet ? "ON" : "OFF", VTY_NEWLINE);

	if(pppd_debug_if == 0xFFFFFFFF)
	    vty_out(vty,"%12s DEBUG ALL ON %s", "INTERFACE", VTY_NEWLINE);
	else if(pppd_debug_if == 0)
	    vty_out(vty,"%12s DEBUG ALL OFF %s", "INTERFACE", VTY_NEWLINE);
	else {
        for(i = 0; i < NUM_PPP; i++) {
            bRet = CHECK_FLAG(pppd_debug_if, (1<<i));
	        vty_out(vty,"%12s DEBUG %3d %3s %s", "INTERFACE", i, bRet ? "ON" : "OFF", VTY_NEWLINE);
    
        }
	}

	return CMD_SUCCESS;
}


DEFUN (config_pppd_debug,
		config_pppd_debug_cmd,
		"ppp debug (tcp|neg|packet|all) (on|off)",
		"pppd\n" 
		"debug\n" 
		"tcp(on|off)\n"
		"neg(on|off)\n"
		"packet(on|off)\n"
		"all(on|off)\n")
{
	if(strcmp(argv[0],"tcp") == 0)
	{
		if(strcmp(argv[1],"on") == 0)	
			PPP_SET_FLAG(pppd_debug_flags,DEBUG_TCP_FLAG);
		else 
			PPP_UNSET_FLAG(pppd_debug_flags,DEBUG_TCP_FLAG);	
		return CMD_SUCCESS;
	}	

	if(strcmp(argv[0],"neg") == 0)
	{
		if(strcmp(argv[1],"on") == 0)	
			PPP_SET_FLAG(pppd_debug_flags,DEBUG_NEG_FLAG);
		else 
			PPP_UNSET_FLAG(pppd_debug_flags,DEBUG_NEG_FLAG);	
			
		return CMD_SUCCESS;
	}


	if(strcmp(argv[0],"packet") == 0)
	{
		if(strcmp(argv[1],"on") == 0)	
			PPP_SET_FLAG(pppd_debug_flags,DEBUG_PKT_FLAG);
		else 
			PPP_UNSET_FLAG(pppd_debug_flags,DEBUG_PKT_FLAG);	
		return CMD_SUCCESS;
	}

	if(strcmp(argv[0],"all") == 0)
	{
		if(strcmp(argv[1],"on") == 0) {	
			pppd_debug_flags = 0XFFFFFFFF;
            pppd_debug_if = 0xFFFFFFFF;
	    } else {
            pppd_debug_if = 0;
			pppd_debug_flags = 0;	
		}
		
		return CMD_SUCCESS;
	}

	return 0;
}

static void ppp_interface_config_write (struct vty *vty)
{
  struct listnode *node;
  struct interface *ifp;
  struct ppp_interface *pppif;
  int index = 0;
  lcp_options *lcp_wo;

  struct multilink_if_info* p;
  struct remote_userinfo* user;
  struct listnode *nn, *mm;
  struct list* list;
  
  list = multilink_if_list;
  for(ALL_LIST_ELEMENTS(list, nn, mm, p)) {
      vty_out (vty,"interface reform-multilink %u ip %s%s", p->multi_num, remark_ip2str(p->multi_ip), VTY_NEWLINE);
  }
  vty_out (vty, "!%s", VTY_NEWLINE);
  vty_out (vty, "!%s", VTY_NEWLINE);
  
  list = remote_userinfo_list;
  for(ALL_LIST_ELEMENTS(list, nn, mm, user)) {
      vty_out (vty,"username %s password %s%s", user->remote_name, user->remote_pwd, VTY_NEWLINE);
  }
  vty_out (vty, "!%s", VTY_NEWLINE);
  vty_out (vty, "!%s", VTY_NEWLINE);
  
  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp)) {
  //for(index = 0; index < NUM_PPP; index) {
      index = ifp->ifindex;
      pppif = ppp_if[index];
      if(pppif == NULL)
          continue;
          
      vty_out (vty, "interface xxenterface %s%s", ifp->name, VTY_NEWLINE);

      if(pppif->multilink_flags == 1)
          vty_out (vty,"  ppp multilink group %u%s", pppif->mp_ifindex, VTY_NEWLINE);
        
      lcp_wo= &pppif->lcp.lcp_wantoptions;
	  if (lcp_wo->neg_upap)
		  vty_out (vty,"  ppp authentication pap%s", VTY_NEWLINE);
	  if (lcp_wo->neg_chap)
		  vty_out (vty,"  ppp authentication chap%s", VTY_NEWLINE);

      //if(pppif->local_ip != 0 && pppif->mp_ifindex == 0)
      if(pppif->local_ip != 0)// && pppif->mp_ifindex == 0)
          vty_out (vty,"  ip address %s%s", remark_ip2str(pppif->local_ip), VTY_NEWLINE);
          
      if (pppif->pap_user[0] != 0 && pppif->pap_passwd[0] != 0)
          vty_out (vty,"  ppp pap sent-username %s password %s%s", pppif->pap_user, pppif->pap_passwd, VTY_NEWLINE);
      if (pppif->chap_user[0] != 0)
		  vty_out (vty,"  ppp chap hostname %s%s", pppif->chap_user, VTY_NEWLINE);
	  if (pppif->chap_passwd[0] != 0)
		  vty_out (vty,"  ppp chap password %s%s", pppif->chap_passwd, VTY_NEWLINE);

      if (pppif->maxsconfreq_times != DEFMAXCONFREQS)
          vty_out (vty,"  ppp max-configure %d%s", pppif->maxsconfreq_times, VTY_NEWLINE);
      if (pppif->sconfreq_timeout != DEFTIMEOUT)
          vty_out (vty,"  ppp config-timeout %d%s", pppif->sconfreq_timeout, VTY_NEWLINE);
      if (pppif->lcp.echo_interval != DEFTIMEOUT)
          vty_out (vty,"  ppp echo-timeout %d%s", pppif->lcp.echo_interval, VTY_NEWLINE);

      if(pppif->enable == 1)
          vty_out (vty, "  encapsulate ppp%s", VTY_NEWLINE);
	  vty_out (vty, "!%s", VTY_NEWLINE);       
  } 
  
  return;
}

DEFUN (show_pppd_config,
		show_pppd_config_cmd,
		"show ppp config",
		"show\n" "ppp\n" "config\n")
{
    ppp_interface_config_write(vty);

	return CMD_SUCCESS;
}


void ppp_one_if_create(int unit)
{
//    int i;
    char name[20];
    struct interface *ifp;

    snprintf(name, sizeof(name), "%u", unit);
    ifp = if_get_by_name_len(name, strlen(name));
    ifp->ifindex = unit;
}

static struct cmd_node reform_interface_node =
{
  INTERFACE_NODE,
  "%s(config-xxenterface)# ",
  1,
};

void ppp_cli_init (void)
{
    install_show_run (ppp_interface_config_write);

   	install_element (CONFIG_NODE, &reform_multilink_cmd);
    install_element (CONFIG_NODE, &no_reform_multilink_cmd);
    install_element (CONFIG_NODE, &if_ppp_remote_username_password_cmd);
	install_element (CONFIG_NODE, &no_if_ppp_remote_username_password_cmd); 
	
    if_init();
    ppp_if_create_init();
    install_node (&reform_interface_node, NULL);

    install_element (ENABLE_NODE, &show_pppd_status_cmd);
	install_element (ENABLE_NODE, &show_pppd_debug_cmd);
	install_element (ENABLE_NODE, &show_pppd_config_cmd);
	
    install_element (CONFIG_NODE, &reform_interface_cmd);
    install_element (CONFIG_NODE, &no_reform_interface_cmd);
    install_element (CONFIG_NODE, &config_pppd_debug_cmd);
    install_element (CONFIG_NODE, &config_pppd_if_debug_cmd);
    install_element (CONFIG_NODE, &config_pppd_ifall_debug_cmd);
    
	
    install_default (INTERFACE_NODE);
	install_element (INTERFACE_NODE, &ppp_remark_ip_cmd);
	install_element (INTERFACE_NODE, &no_ppp_remark_ip_cmd);
	install_element (INTERFACE_NODE, &ppp_remark_auth_ppp_cmd);
	install_element (INTERFACE_NODE, &no_ppp_remark_auth_ppp_cmd);
	install_element (INTERFACE_NODE, &ppp_remark_ppp_chap_hostname_cmd);
	install_element (INTERFACE_NODE, &no_ppp_remark_ppp_chap_hostname_cmd);
	install_element (INTERFACE_NODE, &ppp_remark_ppp_chap_pwd_cmd);
	install_element (INTERFACE_NODE, &no_ppp_remark_ppp_chap_pwd_cmd);
	install_element (INTERFACE_NODE, &if_ppp_pap_username_password_cmd);
	install_element (INTERFACE_NODE, &no_if_ppp_pap_username_password_cmd);
	install_element (INTERFACE_NODE, &if_ppp_config_timeout_cmd);
	install_element (INTERFACE_NODE, &no_if_ppp_config_timeout_cmd);

	install_element (INTERFACE_NODE, &if_ppp_max_configure_cmd);
	install_element (INTERFACE_NODE, &no_if_ppp_max_configure_cmd);
	
	install_element (INTERFACE_NODE, &if_ppp_echo_timeout_cmd);
	install_element (INTERFACE_NODE, &no_if_ppp_echo_timeout_cmd);
    install_element (INTERFACE_NODE, &if_ppp_add_group_cmd);
    install_element (INTERFACE_NODE, &no_if_ppp_add_group_cmd);
    install_element (INTERFACE_NODE, &mcp_ppp_ip_info_cmd);
    
    install_element (INTERFACE_NODE, &ppp_remark_encapsulate_ppp_cmd);
	install_element (INTERFACE_NODE, &no_ppp_remark_encapsulate_ppp_cmd);
}

void* ppp_vty_init(void *arg)
{
    struct thread thread;
    
    master = thread_master_create();  
    if(master == NULL) {
        zlog_err("thread_master_create failed, <%s,%d>", __FUNCTION__, __LINE__);
    }

	cmd_init(1);
	vty_init(master);
	memory_init();
	sort_node();
	ppp_cli_init();
	vty_read_config(pppd_config_file, "./"); 
    ppp_remark_tcp_init();
	vty_serv_sock ("127.0.0.1", NC_DEFAULT_VTY_PORT, NULL);
    while (thread_fetch (master, &thread))
        thread_call (&thread);

    printf("WARNING: ppp vty main exit\n");
    pthread_exit(NULL);

    return NULL;
}

/*int main()
{
	ppp_vty_init();
	return 1;
}*/
