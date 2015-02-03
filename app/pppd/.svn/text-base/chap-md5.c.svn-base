/*
 * chap-md5.c - New CHAP/MD5 implementation.
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

#define RCSID	"$Id: chap-md5.c,v 1.4 2004/11/09 22:39:25 paulus Exp $"

#include <stdlib.h>
#include <string.h>
#include "pppd.h"
#include "chap-new.h"
#include "chap-md5.h"
#include "magic.h"
#include "md5.h"

#define MD5_HASH_SIZE		16
#define MD5_MIN_CHALLENGE	16
#define MD5_MAX_CHALLENGE	24

static void
chap_md5_generate_challenge(unsigned char *cp)
{
	int clen;

	clen = (int)(drand48() * (MD5_MAX_CHALLENGE - MD5_MIN_CHALLENGE))
		+ MD5_MIN_CHALLENGE;
	*cp++ = clen;
	random_bytes(cp, clen);
}

//把id  secret challege三个内容做MD5运算，与从第二步收到的应答CHAP_RESPONSE中获取到的hash值做比较，相等说明成功
static int
chap_md5_verify_response(int id, char *name,
			 unsigned char *secret, int secret_len,
			 unsigned char *challenge, unsigned char *response,
			 char *message, int message_space)
{
	MD5_CTX ctx;
	unsigned char idbyte = id;
	unsigned char hash[MD5_HASH_SIZE];
	int challenge_len, response_len;

	challenge_len = *challenge++;
	response_len = *response++;
	if (response_len == MD5_HASH_SIZE) {
		/* Generate hash of ID, secret, challenge */
		MD5_Init(&ctx);
		MD5_Update(&ctx, &idbyte, 1);
		MD5_Update(&ctx, secret, secret_len);
		MD5_Update(&ctx, challenge, challenge_len);
		MD5_Final(hash, &ctx);

		/* Test if our hash matches the peer's response */
		if (memcmp(hash, response, MD5_HASH_SIZE) == 0) {
			slprintf(message, message_space, "Access granted");
			return 1;
		}
	}
	slprintf(message, message_space, "Access denied");
	return 0;
}

//把id(报文头中的id序号) secret(从remote_userinfo_list链表中获取到的第一个密码)和从主动发起挑战字 做md5运算并存到response内存空间，并且内存空间的第一个字节存放整个空间md5运算结果长度16
static void
chap_md5_make_response(unsigned char *response, int id, char *our_name,
		       unsigned char *challenge, char *secret, int secret_len,
		       unsigned char *private)
{
	MD5_CTX ctx;
	unsigned char idbyte = id;
	int challenge_len = *challenge++;

	MD5_Init(&ctx);
	MD5_Update(&ctx, &idbyte, 1);
	MD5_Update(&ctx, secret, secret_len);
	MD5_Update(&ctx, challenge, challenge_len);
	MD5_Final(&response[1], &ctx);
	response[0] = MD5_HASH_SIZE;
}

/*
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
询问握手认证协议（CHAP）通过三次握手周期性的校验对端的身份，在初始链路建立时完成，可以在链路建立之后的任何时候重复进行。
1. 链路建立阶段结束之后，认证者向对端点发送“challenge”消息。
2. 对端点用经过单向哈希函数计算出来的值做应答。
3. 认证者根据它自己计算的哈希值来检查应答，如果值匹配，认证得到承认；否则，连接应该终止。
4. 经过一定的随机间隔，认证者发送一个新的 challenge 给端点，重复步骤 1 到 3 。
通过递增改变的标识符和可变的询问值，CHAP 防止了来自端点的重放攻击，使用重复校验可以限制暴露于单个攻击的时间。认证者控制验证频度和时间。

总的过程如下:
1.认证端(服务端)发送:挑战字 + 服务端用户名  给被验证端
2.被验证端(客户端)收到1来的包后，获取1中的用户名，然后从remote_userinfo_list中获取1中用户名对应的密码，然后用(id + 服务端用户对应的密码 + 挑战字)进行
  MD5计算，然后发送(MD5值 + 客户端用户名)给服务端
3. 服务端收到2的包后，获取到2中用户名(客户端)，然后从remote_userinfo_list中获取2中用户名(客户端)对应的密码，然后用(id + (客户端)用户对应的密码 + 挑战字)进行
   MD5计算，用这个新的MD5值与2中发送过来的MD5进行比较。相等说明成功，然后发送SUCCESS给客户端，否则发送fail给客户端

交互过程可以参考:chap_input
*/
static struct chap_digest_type md5_digest = { //chap两端用户名和密码必须一致
	CHAP_MD5,		/* code */
	chap_md5_generate_challenge, //第一步，主动挑战端产生随机数(实际上在外层发送out的时候为:挑战字 + 服务端用户名)，见chap_generate_challenge
	chap_md5_verify_response, //第三步，//把id  secret challege三个内容做MD5运算，与从第二步收到的应答CHAP_RESPONSE中获取到的hash值做比较，相等说明成功
    /*
 第二部，把收到的主动挑战端的:id(报文头中的id序号) 挑战端用户名对应的secret和从主动发起挑战字 做md5运算并存到response内存空间，并且
 内存空间的第一个字节存放整个空间md5运算结果长度16。外层发送的时候还要加上本端(被验证方)的用户名，见chap_respond
     */
	chap_md5_make_response, 
	NULL,			/* check_success */
	NULL,			/* handle_failure */
};

void
chap_md5_init(void)
{
	chap_register_digest(&md5_digest);
}
