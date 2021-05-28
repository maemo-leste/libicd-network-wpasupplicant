#include <icd/support/icd_log.h>

#ifndef _WPAICD_LOG_COMMON_H_
#define _WPAICD_LOG_COMMON_H_

#define WPALOG_PREFIX "libicd-network-wpasupplicant: "

#define WPALOG_DEBUG(...) \
    ILOG_DEBUG(WPALOG_PREFIX __VA_ARGS__)

#define WPALOG_INFO(...) \
    ILOG_INFO(WPALOG_PREFIX __VA_ARGS__)

#define WPALOG_CRIT(...) \
    ILOG_CRIT(WPALOG_PREFIX __VA_ARGS__)

#define WPALOG_ERR(...) \
    ILOG_ERR(WPALOG_PREFIX __VA_ARGS__)

#endif /* _WPAICD_LOG_COMMON_H_ */
