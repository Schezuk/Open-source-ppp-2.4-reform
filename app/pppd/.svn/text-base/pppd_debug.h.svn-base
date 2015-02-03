#ifndef __PPPD_DEBUG_H
#define __PPPD_DEBUG_H

#define DEBUG_TCP_FLAG  		(1<<1)
#define DEBUG_NEG_FLAG  		(1<<2)
#define DEBUG_PKT_FLAG  		(1<<3)

#define PPP_CHECK_FLAG(V,F)      ((V) & (F))
#define PPP_SET_FLAG(V,F)        (V) |= (F)
#define PPP_UNSET_FLAG(V,F)      (V) &= ~(F)

extern unsigned int pppd_debug_flags;
extern unsigned int pppd_debug_if;

#define PPPD_DEBUG_TCP(...) 												\
	do{                         										\
		if(PPP_CHECK_FLAG(pppd_debug_flags,DEBUG_TCP_FLAG))					\
		{																\
			char debug_buf2[1024];										\
			snprintf(debug_buf2, sizeof(debug_buf2),__VA_ARGS__);		\
			ZLOG_INFO("[TCP]%s",debug_buf2);								\
		}																\
	}while(0)

#define PPPD_DEBUG_NEGTIAT(...) 												\
            do{                                                                 \
                if(PPP_CHECK_FLAG(pppd_debug_flags,DEBUG_NEG_FLAG))                 \
                {                                                               \
                    char debug_buf2[1024];                                       \
                    snprintf(debug_buf2, sizeof(debug_buf2),__VA_ARGS__);       \
                    ZLOG_INFO("[NEG]%s",debug_buf2);                               \
                }                                                               \
            }while(0)

#define PPPD_DEBUG_PKT(...) 												\
            do{                                                                 \
                if(PPP_CHECK_FLAG(pppd_debug_flags,DEBUG_PKT_FLAG))                 \
                {                                                               \
                    char debug_buf2[1024];                                       \
                    snprintf(debug_buf2, sizeof(debug_buf2),__VA_ARGS__);       \
                    ZLOG_INFO("[PKT]%s",debug_buf2);                               \
                }                                                               \
            }while(0)


#endif

