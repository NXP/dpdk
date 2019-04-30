/*
 *
 * NXP 2019
 *
 * ipc lib.c
 *
 */

/* Not sure how the PCI BAR does translation
 * assuming that translation is not done, so host_phys and modem_phys
 * exits else only host_phys is required
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#include <geul_ipc_um.h>
#include <geul_ipc.h>
#include <gul_host_if.h>

mem_range_t chvpaddr_arr[IPC_MAX_INSTANCE_COUNT][IPC_MAX_CHANNEL_COUNT];
#define TBD 0
#define UNUSED(x) (void)x;

#define MHIF_VADDR(A) \
	(void *)((unsigned long)(A) \
			- (ipc_priv->mhif_start.host_phys) \
			+  ipc_priv->mhif_start.vaddr)

#define IPC_CH_VADDR(A) \
	(void *)((unsigned long)(A) \
			- ipc_priv->ipc_start.host_phys \
			+ ipc_priv->ipc_start.host_vaddr)

#define MODEM_V2P(A) \
	((uint32_t) ((unsigned long) (A) \
	 		+ ipc_priv->hugepg_start.modem_phys \
			- (unsigned long )(ipc_priv->hugepg_start.host_vaddr)))
#define HOST_V2P(A) \
	((uint64_t) ((unsigned long) (A) \
	 		+ ipc_priv->hugepg_start.host_phys \
			- (unsigned long )(ipc_priv->hugepg_start.host_vaddr)))
#define MODEM_P2V(A) \
	((void *) ((unsigned long) (A) \
	 		- ipc_priv->peb_start.modem_phys \
			+ (unsigned long )(ipc_priv->hugepg_start.host_vaddr)))

#define HOST_RANGE_V(x) \
	(((uint64_t)(x) < (uint64_t)ipc_priv->hugepg_start.host_vaddr || \
	  (uint64_t)(x) > ((uint64_t)ipc_priv->hugepg_start.host_vaddr \
	  + ipc_priv->hugepg_start.size)) == 1 ? 1 : 0) 
#if TBD
static void *get_channel_vaddr(uint32_t channel_id, ipc_userspace_t *ipc_priv);
static void *__get_channel_vaddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv);
static unsigned long get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv);
static unsigned long __get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv);
#endif
#if 0 /* NOT needed */
static int get_ipc_inst(ipc_userspace_t *ipc_priv, uint32_t inst_id);
static int get_channels_info(ipc_userspace_t *ipc, uint32_t instance_id);
#endif
void signal_handler(int signo, siginfo_t *siginfo, void *data);

/*AK signal and PID to be sent kernel */
#if TBD
extern int rte_mempool_get (struct rte_mempool *rtemempool, void **obj_p) __attribute__((weak));
int rte_mempool_get (struct rte_mempool *rtemempool, void **obj_p)
{
	return 0;
}
#endif

static inline void ipc_fill_errorcode(int *err, int code)
{
	if (err)
		*err = code;
}

static inline int open_devmem(void)
{
        int dev_mem = open("/dev/mem", O_RDWR);
        if (dev_mem == -1) {
                printf("Error: Cannot open /dev/mem \n");
                return -1;
        }
        return dev_mem;
}

static inline int open_devipc(void)
{
        int devipc = open("/dev/gulipc", O_RDWR);
        if (devipc == -1) {
                printf("Error: Cannot open /dev/ipc \n");
                return -1;
        }
        return devipc;
}

static inline void ipc_mark_channel_as_configured(uint32_t channel_id, ipc_instance_t *instance)
{
	/* Read mask */
	ipc_bitmask_t mask = instance->cfgmask[channel_id / bitcount(ipc_bitmask_t)];

	/* Set channel specific bit */
	mask |= 1 << (channel_id % bitcount(mask));

	/* Write mask */
	instance->cfgmask[channel_id / bitcount(ipc_bitmask_t)] = mask;
}

int ipc_is_channel_configured(uint32_t channel_id, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance; 

	/* Validate channel id */
	if (!ipc_instance || channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;
	/* Read mask */
	ipc_bitmask_t mask = ipc_instance->cfgmask[channel_id / bitcount(ipc_bitmask_t)];

	/* !! to return either 0 or 1 */
	return !!(mask & (1 << (channel_id % bitcount(mask))));
}

/* list array size must be IPC_BITMASK_ARRAY_SIZE */
int ipc_get_list_of_configured_channel(ipc_bitmask_t list[], ipc_t instance)
{
	uint32_t i;
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance; 

	/* Validate instance*/
	if (!ipc_instance || !(ipc_instance->initialized))
		return IPC_INSTANCE_INVALID;
	
	/* Fill masks from metadata to the argument list */
	for (i = 0; i < IPC_BITMASK_ARRAY_SIZE; i++)
		list[i] = ipc_instance->cfgmask[i];

	return 0;
}

/*
 * Host should init free buffer list
 * So not implemented on modem as of now
 * Internal so done in configure channel
 */
int ipc_init_ptr_buf_list(uint32_t channel_id,
		uint32_t depth, uint32_t size, ipc_t instance)
{
	UNUSED(channel_id);
	UNUSED(instance);
	UNUSED(depth);
	UNUSED(size);

	return IPC_NOT_IMPLEMENTED;
}

/* MODEM ONLY */
ipc_sh_buf_t* ipc_get_buf(uint32_t channel_id, ipc_t instance, int *err)
{
	UNUSED(channel_id);
	UNUSED(instance);
	ipc_fill_errorcode(err, IPC_NOT_IMPLEMENTED);
	return NULL;
}

/*
 * As per current use case/design where PTR channel is used to transfer RX TB
 * from modem to host through shared buffer, This API will be called from host
 * side only to put back the received buffer to free buffer list.
 *
 * HOST only.
 */
int ipc_put_buf(uint32_t channel_id, ipc_sh_buf_t *buf_to_free, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance; 
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t occupied, ring_size, pi, ci;
	ipc_sh_buf_t *sh = buf_to_free;

	if (!ipc_instance || !ipc_instance->initialized)
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;

	if (HOST_RANGE_V(sh))
		return IPC_INPUT_INVALID;
	
	ch = &(ipc_instance->ch_list[channel_id]);

	if (!ipc_is_channel_configured(channel_id, ipc_priv) ||
			ch->ch_type != IPC_CH_PTR || !ch->bl_initialized)
		return IPC_CH_INVALID;

	md = &(ch->br_bl_desc.md);

	occupied = md->occupied;
	ring_size = md->ring_size;

	pi = md->pi;
	ci = md->ci; /* Modification from consumer only */

	pr_debug("%s enter: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n", __func__,
			pi, ci, occupied, ring_size);

	pi = (pi + 1) % ring_size;
	
	/* Copy back to ipc_sh_buf_t */
	ch->br_bl_desc.bd[pi].mod_phys = MODEM_V2P(sh);
	ch->br_bl_desc.bd[pi].host_virt = (uint64_t)(sh);
	ch->br_bl_desc.bd[pi].host_phys = HOST_V2P(sh); /* Should be unused */
	occupied = occupied - 1;

	pr_debug("%s exit: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n", __func__,
			pi, ci, occupied, ring_size);

	md->occupied = occupied;

	return IPC_SUCCESS;

}

/* AK NOT to implemented */
int ipc_send_ptr(uint32_t channel_id,
		ipc_sh_buf_t *buf,
		ipc_t instance)
{
	UNUSED(channel_id);
	UNUSED(buf);
	UNUSED(instance);

	return IPC_NOT_IMPLEMENTED;
}

/*
 * Not to be implemented as of now.
 */
int ipc_get_prod_buf_ptr(uint32_t channel_id, void **buf_ptr, ipc_t instance)
{
	UNUSED(channel_id);
	UNUSED(buf_ptr);
	UNUSED(instance);

	return IPC_NOT_IMPLEMENTED;
}

int ipc_send_msg(uint32_t channel_id,
		void *src,
		uint32_t len,
		ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch = &(ipc_instance->ch_list[channel_id]);
	ipc_br_md_t *md = &(ch->br_msg_desc.md);
	uint32_t occupied, ring_size, pi, ci;
	ipc_bd_t *bdr, *bd;

	if (!src || !len)
		return IPC_INPUT_INVALID;

	if (!ipc_instance || !ipc_instance->initialized)
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;

	if (!ipc_is_channel_configured(channel_id, ipc_priv))
		return IPC_CH_INVALID;

	if (len > md->msg_size)
		return IPC_INPUT_INVALID;

	occupied = md->occupied;
	ring_size = md->ring_size;


	ci = md->ci;
	pi = md->pi;
	if ((pi - ci) == ring_size)
		return IPC_CH_FULL;

	pr_debug("%s enter: pi: %u, ci: %u, occupied: %u, ring size: %u, len: %u\r\n",
			__func__, pi, ci, occupied, ring_size, len);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[pi];

	memcpy((void *)(bd->host_virt), src, len);
	bd->len = len;

	occupied += 1;
	pi = (pi + 1) % ring_size;

	md->occupied = occupied;
	md->pi = pi;

	pr_debug("%s enter: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n", __func__,
			pi, ci, occupied, ring_size);

	return IPC_SUCCESS;
}

/* 
 * PTR channel is used to transfer RX TB from modem to host.
 * So this API will only be used by host to receive RX TB.
 */
ipc_sh_buf_t* ipc_recv_ptr(uint32_t channel_id,	ipc_t instance, int *err)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance; 
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t occupied, ring_size, pi, ci;
	ipc_bd_t *bdr, *bd;
	ipc_sh_buf_t *sh;


	if (!ipc_instance || !ipc_instance->initialized) {
		ipc_fill_errorcode(err,IPC_INSTANCE_INVALID);
		return NULL;
	}

	if (channel_id >= IPC_MAX_CHANNEL_COUNT) {
		ipc_fill_errorcode(err, IPC_CH_INVALID);
		return NULL;
	}	

	ch = &(ipc_instance->ch_list[channel_id]);

	if (!ipc_is_channel_configured(channel_id, ipc_priv)) {
		ipc_fill_errorcode(err, IPC_CH_INVALID);
		return NULL;
	}	

	md = &(ch->br_msg_desc.md);

	occupied = md->occupied;

	ci = md->ci;
	pi = md->pi; /* Modification from Producer only */
	if ((pi - ci) == 0) {
		ipc_fill_errorcode(err, IPC_CH_EMPTY);
		return NULL;
	}	

	ring_size = md->ring_size;

	pr_debug("%s enter: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n",
			__func__, pi, ci, occupied, ring_size);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[ci];

	sh = (void *)(bd->host_virt);

	occupied -= 1;
	ci = (ci + 1) % ring_size;

	md->occupied = occupied;
	md->ci = ci;;

	pr_debug("%s exit: pi: %u, ci: %u, occupied: %u, ring size: %u,host_virt: %lx\r\n",
			__func__, pi, ci, occupied, ring_size, bd->host_virt);

	return sh;
}

int ipc_recv_msg(uint32_t channel_id, void *dst,
		uint32_t *len, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t occupied, ring_size, pi, ci, msg_len;
	ipc_bd_t *bdr, *bd;

	if (!dst || !len)
		return IPC_INPUT_INVALID;

	if (!ipc_instance || !ipc_instance->initialized)
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;

	ch = &(ipc_instance->ch_list[channel_id]);

	if (!ipc_is_channel_configured(channel_id, ipc_priv))
		return IPC_CH_INVALID;

	md = &(ch->br_msg_desc.md);

	occupied = md->occupied;
	/* Race condition use pi-ci*/

	ci = md->ci;
	pi = md->pi;
	ring_size = md->ring_size;
	if ((pi - ci) == 0)
		return IPC_CH_EMPTY;

	pr_debug("%s enter: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n",
			__func__, pi, ci, occupied, ring_size);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[ci];

	msg_len = bd->len;
	if (msg_len > md->msg_size)
		return IPC_INPUT_INVALID;

	memcpy(dst, (void *)(bd->host_virt), msg_len);
	*len = msg_len;

	occupied -= 1;
	ci = (ci + 1) % ring_size;

	md->occupied = occupied;
	md->ci = ci;;

	pr_debug("%s exit: pi: %u, ci: %u, occupied: %u, ring size: %u, len: %u\r\n",
			__func__, pi, ci, occupied, ring_size, msg_len);

	return 0;
}

int ipc_recv_msg_ptr(uint32_t channel_id, void **dst_buffer,
		uint32_t *len, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t occupied, ring_size, pi, ci;
	ipc_bd_t *bdr, *bd;

	if (!dst_buffer || !(*dst_buffer) || !len)
		return IPC_INPUT_INVALID;

	if (!ipc_instance || !ipc_instance->initialized)
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;

	ch = &(ipc_instance->ch_list[channel_id]);

	if (!ipc_is_channel_configured(channel_id, ipc_priv))
		return IPC_CH_INVALID;

	md = &(ch->br_msg_desc.md);
	
	ci = md->ci;
	pi = md->pi;
	ring_size = md->ring_size;

	occupied = md->occupied;
	if ((pi - ci) == 0)
		return IPC_CH_EMPTY;


	pr_debug("%s enter: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n",
			__func__, pi, ci, occupied, ring_size);

	bdr = ch->br_msg_desc.bd;
	bd = &bdr[ci];
	/* host_phys and virt was done in configure*/
	*dst_buffer = (void * )bd->host_virt;
	*len = bd->len;

	/* ipc_set_consumed_status needed to called by user*/
	/* as occupied and ci is not decremented */

	return IPC_SUCCESS;
}

int ipc_set_produced_status(uint32_t channel_id, ipc_t instance)
{
	UNUSED(channel_id);
	UNUSED(instance);

	return IPC_NOT_IMPLEMENTED;
}

int ipc_set_consumed_status(uint32_t channel_id, ipc_t instance)
{
	ipc_userspace_t *ipc_priv = instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;
	ipc_br_md_t *md;
	uint32_t occupied, ring_size, pi, ci;

	if (!ipc_instance || !ipc_instance->initialized)
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;

	ch = &(ipc_instance->ch_list[channel_id]);

	if (!ipc_is_channel_configured(channel_id, ipc_priv))
		return IPC_CH_INVALID;
	
	md = &(ch->br_msg_desc.md);

	occupied = md->occupied;

	ci = md->ci;
	pi = md->pi;
	ring_size = md->ring_size;
	if ((ci - pi) == 0)
		return IPC_CH_EMPTY;

	pr_debug("%s enter: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n",
			__func__, pi, ci, occupied, ring_size);

	occupied -= 1;
	ci = (ci + 1) % ring_size;

	md->occupied = occupied;
	md->ci = ci;

	pr_debug("%s exit: pi: %u, ci: %u, occupied: %u, ring size: %u\r\n",
			__func__, pi, ci, occupied, ring_size);

	return IPC_SUCCESS;
}

/* TODO: Implement below API for Geul */
int ipc_chk_recv_status(uint64_t *bmask, ipc_t instance)
{
	UNUSED(bmask);
	UNUSED(instance);

	return IPC_NOT_IMPLEMENTED;
}

int ipc_shutdown(ipc_t ipc)
{
	int i;
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)ipc;

	/* close dev/geulipc */
	close(ipc_priv->dev_ipc);
	close(ipc_priv->dev_mem);

	/* free memory */
	for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++)
		free(ipc_priv->channels[i]);

	/* free ipc */
	free(ipc_priv);
	return IPC_SUCCESS;
}

ipc_t ipc_host_init(uint32_t instance_id,
		struct rte_mempool *rtemempool[MAX_MEM_POOL_COUNT],
		mem_range_t hugepgstart, int *err)
{
	ipc_userspace_t *ipc_priv;
	int ret, dev_ipc, dev_mem;
	ipc_metadata_t *ipc_md;
	struct gul_hif *mhif;

	ipc_priv = malloc(sizeof(ipc_userspace_t));
	if (ipc_priv == NULL) {
		ipc_fill_errorcode(err, IPC_MEM_INVALID);
		return NULL;
	}
	memset(ipc_priv, 0, sizeof(ipc_userspace_t));
	
	
	dev_ipc = open_devipc();
	if (dev_ipc < 0) {
		ipc_fill_errorcode(err, IPC_OPEN_FAIL);
		return NULL;
	}

	dev_mem = open_devmem();
	if (dev_mem < 0) {
		ipc_fill_errorcode(err, IPC_OPEN_FAIL);
		return NULL;
	}

	ipc_priv->instance_id = instance_id;
	ipc_priv->dev_ipc = dev_ipc;
	ipc_priv->dev_mem = dev_mem;

	ipc_priv->sys_map.hugepg_start.host_phys = hugepgstart.host_phys;
	ipc_priv->sys_map.hugepg_start.host_phys = hugepgstart.size;
	/* Send IOCTL to get system map */
	/* Send IOCTL to put hugepg_start map */
	ret = ioctl(dev_ipc, IOCTL_GUL_IPC_GET_SYS_MAP, &ipc_priv->sys_map);
	 if (ret) {
		ipc_fill_errorcode(err, IPC_IOCTL_FAIL);
		return NULL;

	}

	ipc_priv->mhif_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.mhif_start.size, (PROT_READ | \
			PROT_WRITE), MAP_SHARED, dev_mem, \
			ipc_priv->sys_map.mhif_start.host_phys);     \
	if (ipc_priv->mhif_start.host_vaddr == MAP_FAILED) {
		 perror("MAP failed:");
		ipc_fill_errorcode(err, IPC_MMAP_FAIL);
		return NULL;
	}
	
	ipc_priv->peb_start.host_vaddr =
		mmap(0, ipc_priv->sys_map.peb_start.size, (PROT_READ | \
			PROT_WRITE), MAP_SHARED, dev_mem, \
			ipc_priv->sys_map.peb_start.host_phys);     \
	if (ipc_priv->peb_start.host_vaddr == MAP_FAILED) {
		perror("MAP failed:");
		ipc_fill_errorcode(err, IPC_MMAP_FAIL);
		return NULL;
	}

	ipc_priv->hugepg_start.host_phys = hugepgstart.host_phys;
	ipc_priv->hugepg_start.host_vaddr = hugepgstart.host_vaddr;
	ipc_priv->hugepg_start.size = ipc_priv->sys_map.hugepg_start.size;
	ipc_priv->hugepg_start.modem_phys = ipc_priv->sys_map.hugepg_start.modem_phys;


	/*These handle to be used create dpdk pool of 2K 16k and 128k */ 
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_2K] = rtemempool[0]; 
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_16K] = rtemempool[1]; 
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_128K] = rtemempool[2]; 
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_SH_BUF] = rtemempool[3]; 
	ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_R2] = rtemempool[4]; 
	

	mhif = (struct gul_hif *)ipc_priv->mhif_start.host_vaddr;
	/* offset is from start of PEB */
	ipc_md = (ipc_metadata_t *)((uint64_t)ipc_priv->peb_start.host_vaddr + mhif->ipc_regs.ipc_mdata_offset);

	if (sizeof(ipc_metadata_t) !=
			mhif->ipc_regs.ipc_mdata_size) {
		ipc_fill_errorcode(err, IPC_MD_SZ_MISS_MATCH);
		return NULL;
	}

	ipc_priv->instance = (ipc_instance_t *)(&ipc_md->instance_list[instance_id]);
#if 0
	ret = get_channels_info(ipc_priv, instance_id);
	if (ret) {
		if(!err)
			*err = ERROR_IOCTL;
		return NULL;
	}
#endif
#if TBD
	for (i = 0; i < IPC_MAX_CHANNEL_COUNT; i++) {
		/* physical address is not needed as we get virtual directly */
		//chvpaddr_arr[instance_id][i].host_phys = __get_channel_paddr(i, ipc_priv);
		chvpaddr_arr[instance_id][i].vaddr = __get_channel_vaddr(i, ipc_priv);

		vaddr = malloc(sizeof(ipc_channel_us_t));
		if (vaddr == NULL) {
			ipc_fill_errorcode(err, IPC_MALLOC_FAIL);
			return NULL;
		}
		ipc_priv->channels[channel_id] = vaddr;
	}
#endif
	return ipc_priv;
}

int ipc_configure_channel(uint32_t channel_id, uint32_t depth, ipc_ch_type_t channel_type,
		uint32_t msg_size, ipc_cbfunc_t cbfunc, ipc_t instance)
{

	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	ipc_instance_t *ipc_instance = ipc_priv->instance;
	ipc_ch_t *ch;
	void *vaddr;
	uint32_t i = 0;
	int ret;
	if (cbfunc != NULL)
		ipc_priv->channels[channel_id]->cbfunc = cbfunc;
#if TBD
	/* Send IOCTL to send sig and channel id */
	ret = ioctl(dev_ipc, IOCTL_GUL_IPC_REGISTER_SIGNAL, struct chanel_id_sig);
	if (ret) {
		return IPC_IOCTL_FAIL;

	}
#endif
	if (!ipc_priv->instance || !ipc_instance->initialized)
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;

	if (depth > IPC_MAX_DEPTH)
		return IPC_CH_INVALID;

	ch = &(ipc_instance->ch_list[channel_id]);

	if (ipc_is_channel_configured(channel_id, ipc_priv))
		return IPC_CH_INVALID;

	pr_debug("%s: channel: %u, depth: %u, type: %d, msg size: %u\r\n",
			__func__, channel_id, depth, channel_type, msg_size);

	/* Start init of channel */
	ch->ch_type = channel_type;
	if (cbfunc != NULL)
		ch->event_cb = cbfunc;
	ch->ch_id = channel_id;

	if (channel_type == IPC_CH_MSG) {
		ch->br_msg_desc.md.ring_size = depth;
		ch->br_msg_desc.md.occupied = 0;
		ch->br_msg_desc.md.pi = 0;
		ch->br_msg_desc.md.ci = 0;
		ch->br_msg_desc.md.msg_size = msg_size;
		ch->br_msg_desc.bd[i].len = 0; /* not sure use of this len */

		for (i = 0; i < depth; i++) {
			if (msg_size == SIZE_2K) {
				ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_2K], &vaddr);
				if (ret < 0)
					return IPC_HOST_BUF_ALLOC_FAIL;
			} else if (msg_size == SIZE_16K) {
				ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_16K], &vaddr);
				if (ret < 0)
					return IPC_HOST_BUF_ALLOC_FAIL;
			}
			ch->br_msg_desc.bd[i].modem_ptr = MODEM_V2P(vaddr);
			ch->br_msg_desc.bd[i].host_virt = (uint64_t)(vaddr);
			ch->br_msg_desc.bd[i].len = 0; /* not sure use of this len may be for CRC*/
		}
		ch->bl_initialized = 1;
	}

	if (channel_type == IPC_CH_PTR) {
		/* do_dpdk_alloc using rtemempool;
		and fill in ipc_sh_buf_t[];
		translate using hugepgstart and hugepgtart.modem
		*/
		/* Fill msg */
		ch->br_msg_desc.md.ring_size = depth;
		ch->br_msg_desc.md.occupied = 0;
		ch->br_msg_desc.md.pi = 0;
		ch->br_msg_desc.md.ci = 0;
		ch->br_msg_desc.md.msg_size = sizeof(ipc_sh_buf_t);
		ch->br_msg_desc.bd[i].len = 0; /* should be same as ipc_sh_buf_t always*/

		/* Fill bl */
		ch->br_bl_desc.md.ring_size = depth;
		ch->br_bl_desc.md.occupied = 0;
		ch->br_bl_desc.md.pi = 0;
		ch->br_bl_desc.md.ci = 0;
		ch->br_bl_desc.md.msg_size = msg_size; /*  128K */
		for (i = 0; i < depth; i++) {
			/* Fill bl ring */
			ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_128K], &vaddr);
			if (ret < 0)
				return IPC_HOST_BUF_ALLOC_FAIL;

			ch->br_bl_desc.bd[i].mod_phys = MODEM_V2P(vaddr);
			ch->br_bl_desc.bd[i].host_virt = (uint64_t)(vaddr);
			ch->br_bl_desc.bd[i].host_phys = HOST_V2P(vaddr); /* Should be unused */
			/* ch->br_bl_desc.bd[i].buf_size should be unused */
			/* ch->br_bl_desc.bd[i].data_size to be filled by producer */
			/* ch->br_bl_desc.bd[i].cookie = 0; */ /*unused as of now*/

			/* Fill msg ring */
			ret = rte_mempool_get(ipc_priv->rtemempool[IPC_HOST_BUF_POOLSZ_SH_BUF], &vaddr);
			if (ret < 0)
				return IPC_HOST_BUF_ALLOC_FAIL;

			ch->br_msg_desc.bd[i].modem_ptr = MODEM_V2P(vaddr);
			ch->br_msg_desc.bd[i].host_virt = (uint64_t)(vaddr);
			ch->br_msg_desc.bd[i].host_phy = HOST_V2P(vaddr); /* Should be used to fetch ipc_sh_buf_t*/
		}
		ch->br_bl_desc.md.pi = depth;  /* as depth */
		ch->bl_initialized = 1;
	}

	ipc_mark_channel_as_configured(channel_id, ipc_priv->instance);
	return IPC_SUCCESS;

}
#if TBD
/**************** Internal API ************************/
#if 0 /*AK not needed */
/*
 * @get_channels_info
 *
 * Read number of channels and max msg size from sh_ctrl_area
 *
 * Type: Internal function
 */

int get_ipc_inst(ipc_userspace_t *ipc_priv, uint32_t inst_id)
{
	int ret = IPC_SUCCESS;
	ENTER();

	os_het_control_t *sh_ctrl =  ipc_priv->sh_ctrl_area.vaddr;
	os_het_ipc_t *ipc = IPC_CH_VADDR(sh_ctrl->ipc)
				+ sizeof(os_het_ipc_t)*inst_id;
	if (!ipc) {
		ret = -1;
		goto end;
	}
	if (ipc->num_ipc_channels > MAX_IPC_CHANNELS) {
		ret = -1;
		goto end;
	}

	/* ipc_channels is 64 bits but, area of hugetlb/DDR will always
	* less than 4GB(B4),for 913x it is only 2GB, so the value is
	* always in 32 bits, that is why bitwise and with 0xFFFFFFFF
	*/
	if ((ipc->ipc_channels & 0xFFFFFFFF) == 0) {
		ret = -ERR_INCORRECT_RAT_MODE;
		goto end;
	}

	ipc_priv->max_channels = ipc->num_ipc_channels;
	ipc_priv->max_depth = ipc->ipc_max_bd_size;
	ipc_priv->ipc_inst = ipc;
end:
	EXIT(ret);
	return ret;
}

int get_channels_info(ipc_userspace_t *ipc_priv, uint32_t inst_id)
{
	return get_ipc_inst(ipc_priv, inst_id);
}
#endif

/*
 * @get_channel_paddr
 *
 * Returns the phyical address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static unsigned long __get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv)
{
	unsigned long		phys_addr;
	ipc_instance_t *ipc = (ipc_instance_t *)ipc_priv->instance;
	ipc_ch_t *ch = &(ipc->ch_list[channel_id]);
	
	if (!ipc || !(ipc->initialized))
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
		return IPC_CH_INVALID;

#if TBD /* AK not complete */
	phys_addr = (unsigned long)ipc->ipc_channels +
		sizeof(os_het_ipc_channel_t)*channel_id;
	EXIT(phys_addr);
	return phys_addr;
#endif
}
/*
 * @get_channel_vaddr
 *
 * Returns the virtual address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static void *__get_channel_vaddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv)
{
#if 0
	void *vaddr;
#endif
	ipc_userspace_t *ipc_priv = (ipc_userspace_t *)instance;
	ipc_instance_t *ipc = ipc_priv->instance;
	ipc_ch_t *ch = &(ipc->ch_list[channel_id]);

	if (!ipc || !(ipc->initialized))
		return IPC_INSTANCE_INVALID;

	if (channel_id >= IPC_MAX_CHANNEL_COUNT)
	return IPC_CH_INVALID;

	ch = &(ipc->ch_list[channel_id]);

	if (!ipc || !(ipc->initialized))
		return IPC_INSTANCE_INVALID;


//	vaddr = IPC_CH_VADDR(get_channel_paddr(channel_id, ipc_priv));

	return ch;
}
/*
 * @get_channel_paddr
 *
 * Returns the phyical address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static unsigned long get_channel_paddr(uint32_t channel_id,
		ipc_userspace_t *ipc_priv)
{
	return chvpaddr_arr[ipc_priv->instance_id][channel_id].host_phys;
}

/*
 * @get_channel_vaddr
 *
 * Returns the virtual address of the channel data structure in the
 * share control area.
 *
 * Type: Internal function
 */
static void *get_channel_vaddr(uint32_t channel_id, ipc_userspace_t *ipc_priv)
{
	return chvpaddr_arr[ipc_priv->instance_id][channel_id].vaddr;
}
#endif
