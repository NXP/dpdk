/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#ifndef _RTE_LSX_PCIEP_BUS_H_
#define _RTE_LSX_PCIEP_BUS_H_

/**
 * @file
 *
 * RTE LSINIC_VDEV Bus Interface
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/vfio.h>

#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_dev.h>
#include <rte_bus.h>
#include <rte_tailq.h>
#include <rte_memzone.h>
#include <rte_pci.h>

struct rte_lsx_pciep_driver;
struct rte_lsx_pciep_device;
struct rte_lsx_pciep_bus;

#define PCIE_MAX_VF_NUM 64

#define LSX_PCIEP_NXP_NAME_PREFIX "lsxep_nxp"
#define LSX_PCIEP_VIRT_NAME_PREFIX "lsxep_virt"

/* lsinic Device and Driver lists for LSINIC_VDEV bus */
TAILQ_HEAD(rte_lsx_pciep_device_list, rte_lsx_pciep_device);
TAILQ_HEAD(rte_lsx_pciep_driver_list, rte_lsx_pciep_driver);

enum rte_lsx_pciep_type {
	LSX_PCIEP_UNKNOWN,
	LSX_PCIEP_ETH,
};

/* definition according to platform */
enum PEX_TYPE {
	PEX_UNKNOWN,
	PEX_LX2160_REV1,
	PEX_LX2160_REV2,
	PEX_LS208X,
};

enum lsx_pcie_pf_idx {
	PF0_IDX = 0,
	PF1_IDX = 1,
	PF_MAX_NB = 2
};

#define LSX_PCIEP_DONT_INT		(0)
#define LSX_PCIEP_MSIX_INT		(1)
#define LSX_PCIEP_MMSI_INT		(2)

/* Not include MSIX bar.*/
#define LSX_PCIEP_INBOUND_MIN_BAR_SIZE (4096)

#define CFG_1M_SIZE		(1024 * 1024ULL)
#define CFG_1G_SIZE		(1024 * CFG_1M_SIZE)

#define CFG_2G_SIZE		(2 * CFG_1G_SIZE)
#define CFG_4G_SIZE		(4 * CFG_1G_SIZE)
#define CFG_8G_SIZE		(8 * CFG_1G_SIZE)
#define CFG_12G_SIZE	(12 * CFG_1G_SIZE)
#define CFG_16G_SIZE	(16 * CFG_1G_SIZE)
#define CFG_32G_SIZE	(32 * CFG_1G_SIZE)
#define CFG_1T_SIZE		(1024 * CFG_1G_SIZE)

/**
 * A structure describing a PCIe EP device for each PF or VF.
 */
struct rte_lsx_pciep_device {
	TAILQ_ENTRY(rte_lsx_pciep_device) next; /**< Next probed device. */
	struct rte_device device;           /**< Inherit core device */
	struct rte_eth_dev *eth_dev;        /**< ethernet device */
	enum rte_lsx_pciep_type dev_type;   /**< Device Type */
	struct rte_lsx_pciep_driver *driver;    /**< Associated driver */
	int pcie_id;
	int pf;
	int vf;
	int is_vf;
	uint64_t ob_map_bus_base;
	uint64_t ob_orig_bus_base;
	uint64_t ob_phy_base;
	uint8_t *ob_virt_base;
	uint64_t ob_win_size;
	uint32_t ob_win_idx;
	int ob_win_init_flag;

	/* MSI/MSIx information */
	int msix_read_once;
	uint64_t msix_addr[32];
	uint32_t msix_data[32];

	/* MSI/MSIx window setting */
	uint64_t msix_bus_base;
	uint64_t msix_phy_base;
	uint8_t *msix_virt_base;
	uint64_t msix_win_size;
	int msix_win_init_flag;

	/* RBP window setting */
	uint64_t rbp_win_size;
	int rbp_win_init_flag;

	uint8_t *virt_addr[PCI_MAX_RESOURCE];
	char name[RTE_DEV_NAME_MAX_LEN];
	uint32_t mmsi_flag;
	uint32_t init_flag;
	int (*chk_eth_status)(struct rte_eth_dev *dev);
};

typedef int (*rte_lsx_pciep_probe_t)(struct rte_lsx_pciep_driver *lsinic_drv,
				 struct rte_lsx_pciep_device *lsinic_dev);
typedef int (*rte_lsx_pciep_remove_t)(struct rte_lsx_pciep_device *lsinic_dev);


/**
 * A structure describing a LSINIC_VDEV driver.
 */
struct rte_lsx_pciep_driver {
	TAILQ_ENTRY(rte_lsx_pciep_driver) next; /**< Next in list. */
	struct rte_driver driver;           /**< Inherit core driver. */
	enum rte_lsx_pciep_type drv_type;   /**< Driver Type */

	/**< PCIEP bus reference */
	struct rte_lsx_pciep_bus *lsx_pciep_bus;
	uint32_t drv_flags;                 /**< Flags for device.*/
	char name[RTE_DEV_NAME_MAX_LEN];
	rte_lsx_pciep_probe_t probe;
	rte_lsx_pciep_remove_t remove;
};

/*
 * PCIEP bus
 */
struct rte_lsx_pciep_bus {
	struct rte_bus bus;     /**< Generic Bus object */
	struct rte_lsx_pciep_device_list device_list;
				/**< LSINIC Device list */
	struct rte_lsx_pciep_driver_list driver_list;
				/**< LSINIC Driver list */
	int device_count;
				/**< Optional: Count of devices on bus */
};

#define RTE_DEV_TO_LSX_PCIEP_CONST(ptr) \
	container_of(ptr, const struct rte_lsx_pciep_device, device)

int lsx_pciep_pf_available(enum lsx_pcie_pf_idx idx);
int lsx_pciep_vf_number(enum lsx_pcie_pf_idx idx);
enum PEX_TYPE
lsx_pciep_type_get(uint8_t pciep_idx);
int
lsx_pciep_hw_rbp_get(uint8_t pciep_idx);
int
lsx_pciep_hw_sim_get(uint8_t pciep_idx);
int
lsx_pciep_hw_vio_get(uint8_t pciep_idx,
	uint8_t pf_idx);

int lsx_pciep_ctl_rbp_enable(uint8_t pcie_idx);
int lsx_pciep_sim(void);
int lsx_pciep_virtio(void);
enum PEX_TYPE lsx_pciep_get_type(void);
struct rte_lsx_pciep_device *lsx_pciep_first_dev(void);

void *
lsx_pciep_set_ob_win(struct rte_lsx_pciep_device *ep_dev,
	uint64_t pci_addr, uint64_t size);
void
lsx_pciep_set_sim_ob_win(struct rte_lsx_pciep_device *ep_dev,
	uint64_t vir_offset);

void
lsx_pciep_msix_init(struct rte_lsx_pciep_device *ep_dev);
uint64_t
lsx_pciep_msix_get_vaddr(struct rte_lsx_pciep_device *ep_dev,
	uint32_t vector);
uint32_t
lsx_pciep_msix_get_cmd(struct rte_lsx_pciep_device *ep_dev,
	uint32_t vector);
void lsx_pciep_msix_cmd_send(uint64_t addr, uint32_t cmd);

uint16_t
lsx_pciep_ctl_get_device_id(uint8_t pcie_idx,
	enum lsx_pcie_pf_idx pf_idx);

int
lsx_pciep_set_ib_win(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx, uint64_t size);

int
lsx_pciep_set_ib_win_mz(struct rte_lsx_pciep_device *ep_dev,
	uint8_t bar_idx, const struct rte_memzone *mz, int vf_isolate);

int
lsx_pciep_sim_dev_map_inbound(struct rte_lsx_pciep_device *ep_dev);

int
lsx_pciep_ctl_dev_set(uint16_t vendor_id,
	uint16_t device_id, uint16_t class_id,
	uint8_t pcie_id, uint8_t pf);

/**
 * Register a PCIEP bus driver.
 *
 * @param driver
 *   A pointer to a rte_lsx_pciep_driver structure describing the driver
 *   to be registered.
 */
void rte_lsx_pciep_driver_register(struct rte_lsx_pciep_driver *driver);

/**
 * Unregister a PCIEP bus driver.
 *
 * @param driver
 *   A pointer to a rte_lsx_pciep_driver structure describing the driver
 *   to be unregistered.
 */
void rte_lsx_pciep_driver_unregister(struct rte_lsx_pciep_driver *driver);

/** Helper for PCIEP bus device registration from driver instance */
#define RTE_PMD_REGISTER_LSX_PCIEP(nm, lsinic_drv) \
RTE_INIT(lsinicinitfn_ ##nm); \
static void lsinicinitfn_ ##nm(void) \
{\
	(lsinic_drv).driver.name = RTE_STR(nm);\
	rte_lsx_pciep_driver_register(&lsinic_drv); \
} \
RTE_PMD_EXPORT_NAME(nm, __COUNTER__)

#define LSX_PCIEP_BUS_LOG(level, fmt, args...) \
	RTE_LOG(level, EAL, "lsx_pciep:" fmt "\n", ##args)

#define LSX_PCIEP_BUS_INFO(fmt, args...) \
	LSX_PCIEP_BUS_LOG(INFO, fmt, ## args)
#define LSX_PCIEP_BUS_ERR(fmt, args...) \
	LSX_PCIEP_BUS_LOG(ERR, fmt, ## args)
#define LSX_PCIEP_BUS_WARN(fmt, args...) \
	LSX_PCIEP_BUS_LOG(WARNING, fmt, ## args)

#ifdef __cplusplus
}
#endif
#endif /* _RTE_LSX_PCIEP_BUS_H_ */
