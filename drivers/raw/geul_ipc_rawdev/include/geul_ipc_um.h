/**
 *  @ geul_ipc_um.h
 *
 * NXP 2019
 *
 * Author: Ashish Kumar <ashish.kumar@freescale.com>
 */

#ifndef GEUL_IPC_UM_H_
#define GEUL_IPC_UM_H_

#include <geul_ipc_types.h>
#include <geul_ipc.h>
#define MAX_MEM_POOL_COUNT 8
#ifndef DEBUG
#define pr_debug(...) printf(__VA_ARGS__)
#else
#define pr_debug
#endif

typedef struct ipc_channel_us_priv {
        void            *msg_ring_vaddr; /* TODO not sure how to use */
        ipc_cbfunc_t    cbfunc;
        uint32_t        signal;
        uint32_t        channel_id;
} ipc_channel_us_t;

typedef struct ipc_priv_t {
        int instance_id;
	int dev_ipc;
	int dev_mem;
        struct rte_mempool *rtemempool[MAX_MEM_POOL_COUNT];
        sys_map_t sys_map;
        mem_range_t modem_ccsrbar;
        mem_range_t peb_start;
        mem_range_t mhif_start;
        mem_range_t hugepg_start;
        ipc_channel_us_t *channels[IPC_MAX_CHANNEL_COUNT];
        ipc_instance_t *instance;
} ipc_userspace_t;

#endif /* FSL_IPC_UM_H_ */
