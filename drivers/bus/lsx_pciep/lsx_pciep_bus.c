/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019-2021 NXP
 */

#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>
#include <rte_devargs.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_byteorder.h>
#include <rte_memzone.h>
#include <rte_log.h>
#include <rte_kvargs.h>
#include <fsl_qbman_portal.h>
#include <compat.h>
#include <rte_fslmc.h>
#include <rte_string_fns.h>

#include "lsx_pciep_dev.h"

#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#define PAGE_MASK   (~(PAGE_SIZE - 1))

#define LSX_PCIEP_BUS_NAME	lsx_pciep

static uint32_t s_pf0_enable = 1;
static uint32_t s_pf1_enable = 1;
static uint32_t s_pf0_vfnum;
static uint32_t s_pf1_vfnum;

static int s_ep_sim;
static int s_ep_virtio;

static int s_pcie_black_list_num;
static int s_pcie_black_list[LSX_MAX_PCIE_NB];
static int s_pcie_sim_list_num;
static int s_pcie_sim_list[LSX_MAX_PCIE_NB];

int lsx_pciep_pf_available(enum lsx_pcie_pf_idx idx)
{
	if (idx == PF0_IDX)
		return s_pf0_enable;

	if (idx == PF1_IDX)
		return s_pf1_enable;

	return 0;
}

int lsx_pciep_vf_number(enum lsx_pcie_pf_idx idx)
{
	if (idx == PF0_IDX)
		return s_pf0_vfnum;

	if (idx == PF1_IDX)
		return s_pf1_vfnum;

	return 0;
}

int lsx_pciep_sim(void)
{
	return s_ep_sim;
}

int lsx_pciep_virtio(void)
{
	return s_ep_virtio;
}

static struct rte_lsx_pciep_bus lsx_pciep_bus;

static int
lsx_pciep_compare_devname(struct rte_lsx_pciep_device *dev1,
		      struct rte_lsx_pciep_device *dev2)
{
	int comp = 0;

	if (!strncmp(dev1->name, dev2->name, RTE_DEV_NAME_MAX_LEN))
		comp = 1;

	if (dev1->pcie_id == dev2->pcie_id &&
		dev1->pf == dev2->pf &&
		!dev1->is_vf && !dev2->is_vf)
		comp = 1;

	if (dev1->pcie_id == dev2->pcie_id &&
		dev1->pf == dev2->pf &&
		dev1->vf == dev2->vf && dev1->is_vf && dev2->is_vf)
		comp = 1;

	return comp;
}

static void
lsx_pciep_insert_device_list(struct rte_lsx_pciep_device *newdev)
{
	int comp, inserted = 0;
	struct rte_lsx_pciep_device *dev = NULL;
	struct rte_lsx_pciep_device *tdev = NULL;

	TAILQ_FOREACH_SAFE(dev, &lsx_pciep_bus.device_list, next, tdev) {
		comp = lsx_pciep_compare_devname(newdev, dev);
		if (comp) {
			inserted = 1;
			break;
		}
	}

	if (!inserted)
		TAILQ_INSERT_TAIL(&lsx_pciep_bus.device_list,
		newdev, next);
}

static struct rte_device *
lsx_pciep_find_device(const struct rte_device *start, rte_dev_cmp_t cmp,
		      const void *data)
{
	struct rte_lsx_pciep_device *dev;

	TAILQ_FOREACH(dev, &lsx_pciep_bus.device_list, next) {
		if (start && &dev->device == start) {
			start = NULL;  /* starting point found */
			continue;
		}

		if (cmp(&dev->device, data) == 0)
			return &dev->device;
	}

	return NULL;
}

/* Create all the PF and VF device(s) of the PCIe controller.*/
static int lsx_pciep_create_dev(uint8_t pcie_idx)
{
	struct rte_lsx_pciep_device *ep_dev;
	struct lsx_pciep_ctl_dev *ctl_dev;
	uint32_t i;

	ctl_dev = lsx_pciep_ctl_get_dev(pcie_idx);
	if (!ctl_dev)
		return -ENODEV;

	if (!ctl_dev->ep_enable)
		return -ENODEV;

	if (s_pf0_enable) {
		ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
		if (!ep_dev) {
			LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
				__func__, __LINE__);

			return -ENOMEM;
		}

		memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

		ep_dev->pf = PF0_IDX;
		ep_dev->is_vf = 0;

		if (lsx_pciep_virtio())
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_VIRT_NAME_PREFIX "_%d_pf0",
				ctl_dev->index);
		else
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
				LSX_PCIEP_NXP_NAME_PREFIX "_%d_pf0",
				ctl_dev->index);

		ep_dev->pcie_id = ctl_dev->index;

		ep_dev->device.name = ep_dev->name;

		lsx_pciep_insert_device_list(ep_dev);
	}

	if (s_pf1_enable) {
		ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
		if (!ep_dev) {
			LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
				__func__, __LINE__);

			return -ENOMEM;
		}

		memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

		ep_dev->pf = PF1_IDX;
		ep_dev->is_vf = 0;

		if (lsx_pciep_virtio())
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_VIRT_NAME_PREFIX "_%d_pf1",
					ctl_dev->index);
		else
			snprintf(ep_dev->name, RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_NXP_NAME_PREFIX "_%d_pf1",
					ctl_dev->index);

		ep_dev->pcie_id = ctl_dev->index;

		ep_dev->device.name = ep_dev->name;

		lsx_pciep_insert_device_list(ep_dev);
	}

	if (s_pf0_enable) {
		for (i = 0; i < s_pf0_vfnum; i++) {
			ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
			if (!ep_dev) {
				LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
					__func__, __LINE__);

				return -ENOMEM;
			}

			memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

			ep_dev->pf = PF0_IDX;
			ep_dev->is_vf = 1;
			ep_dev->vf = i;

			if (lsx_pciep_virtio())
				snprintf(ep_dev->name,
					RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_VIRT_NAME_PREFIX
					"_%d_pf0_vf%d",
					ctl_dev->index, i);
			else
				snprintf(ep_dev->name,
					RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_NXP_NAME_PREFIX
					"_%d_pf0_vf%d",
					ctl_dev->index, i);

			ep_dev->pcie_id = ctl_dev->index;

			ep_dev->device.name = ep_dev->name;

			lsx_pciep_insert_device_list(ep_dev);
		}
	}

	if (s_pf1_enable) {
		for (i = 0; i < s_pf1_vfnum; i++) {
			ep_dev = calloc(1, sizeof(struct rte_lsx_pciep_device));
			if (!ep_dev) {
				LSX_PCIEP_BUS_ERR("%s line:%d Out of memory",
					__func__, __LINE__);

				return -ENOMEM;
			}

			memset(ep_dev, 0, sizeof(struct rte_lsx_pciep_device));

			ep_dev->pf = PF1_IDX;
			ep_dev->is_vf = 1;
			ep_dev->vf = i;

			if (lsx_pciep_virtio())
				snprintf(ep_dev->name,
					RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_VIRT_NAME_PREFIX
					"_%d_pf1_vf%d",
					ctl_dev->index, i);
			else
				snprintf(ep_dev->name,
					RTE_DEV_NAME_MAX_LEN,
					LSX_PCIEP_NXP_NAME_PREFIX
					"_%d_pf1_vf%d",
					ctl_dev->index, i);

			ep_dev->pcie_id = ctl_dev->index;

			ep_dev->device.name = ep_dev->name;

			lsx_pciep_insert_device_list(ep_dev);
		}
	}

	return 0;
}

void *lsx_pciep_map_region(uint64_t addr, size_t len)
{
	int fd;
	void *tmp;
	uint64_t start;
	uint64_t offset;

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		LSX_PCIEP_BUS_ERR("Fail to open /dev/mem\n");
		return NULL;
	}

	start = addr & PAGE_MASK;
	offset = addr - start;
	len = len & PAGE_MASK;
	if (len < (size_t)PAGE_SIZE)
		len = PAGE_SIZE;

	tmp = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, start);

	close(fd);

	if (tmp != MAP_FAILED)
		return (uint8_t *)tmp + offset;
	else
		return NULL;
}

static int
lsx_pciep_parse_env_variable(void)
{
	char *penv = NULL;
	int rbp_enable = LSX_PCIEP_QDMA_RBP_SUPPORT;
	enum lsx_share_ob share_ob = LSX_PCIEP_OB_PER_FUN;
	int arg_num, i, j;
	char *args[32];

	penv = getenv("LSINIC_PF0");
	if (penv)
		s_pf0_enable = atoi(penv);

	penv = getenv("LSINIC_PF1");
	if (penv)
		s_pf1_enable = atoi(penv);

	penv = getenv("LSINIC_PF0_VF");
	if (penv)
		s_pf0_vfnum = atoi(penv);
	if (s_pf0_vfnum > PCIE_MAX_VF_NUM)
		s_pf0_vfnum = PCIE_MAX_VF_NUM;

	penv = getenv("LSINIC_PF1_VF");
	if (penv)
		s_pf1_vfnum = atoi(penv);
	if (s_pf1_vfnum > PCIE_MAX_VF_NUM)
		s_pf1_vfnum = PCIE_MAX_VF_NUM;

	penv = getenv("LSINIC_EP_SIM");
	if (penv)
		s_ep_sim = atoi(penv);

	penv = getenv("LSINIC_EP_VIRTIO");
	if (penv)
		s_ep_virtio = atoi(penv);

	LSX_PCIEP_BUS_INFO("pf0_en:%d pf1_en:%d pf0_vfnum:%d pf1_vfnum:%d",
		s_pf0_enable, s_pf1_enable, s_pf0_vfnum, s_pf1_vfnum);

	penv = getenv("LSINIC_RBP_DISABLE");
	if ((penv && atoi(penv) > 0) || s_ep_sim)
		rbp_enable = 0;

	penv = getenv("LSINIC_PRIMARY_SHARE_OUTBOUND");
	if (penv && atoi(penv) > 0 && !rbp_enable)
		share_ob = LSX_PCIEP_OB_PRIMARY_SHARE;

	penv = getenv("LSINIC_SECONDARY_SHARE_OUTBOUND");
	if (penv && atoi(penv) > 0 && !rbp_enable)
		share_ob = LSX_PCIEP_OB_SECONDARY_SHARE;

	penv = getenv("LSINIC_PCIE_BLACK_LIST");
	if (penv) {
		arg_num = rte_strsplit(penv, strlen(penv), args, 32, ',');
		if (arg_num > 0) {
			for (i = 0; i < arg_num; i++)
				s_pcie_black_list[i] = atoi(args[i]);
			s_pcie_black_list_num = arg_num;
		}
		if (s_ep_sim && s_pcie_black_list_num) {
			int filtered;

			for (j = 0; j < LSX_MAX_PCIE_NB; j++) {
				filtered = 0;
				for (i = 0; i < s_pcie_black_list_num; i++) {
					if (j == s_pcie_black_list[i]) {
						filtered = 1;
						break;
					}
				}
				if (!filtered) {
					s_pcie_sim_list[s_pcie_sim_list_num] = j;
					s_pcie_sim_list_num++;
				}
			}
		}
	}

	lsx_pciep_ctl_set_all_devs(s_pf0_enable,
		s_pf1_enable, s_pf0_vfnum, s_pf1_vfnum,
		rbp_enable, share_ob);

	return 0;
}

int lsx_pciep_id_filtered(int id)
{
	int i;

	if (!s_pcie_black_list_num)
		return false;
	for (i = 0; i < s_pcie_black_list_num; i++) {
		if (id == s_pcie_black_list[i])
			return true;
	}
	return false;
}

int lsx_pciep_sim_dev_add(void)
{
	struct lsx_pciep_ctl_dev *ctldev;
	int i;

	if (!s_pcie_sim_list_num) {
		ctldev = lsx_pciep_ctl_get_dev(LSX_PCIE_SIM_IDX);
		RTE_ASSERT(ctldev);
		ctldev->ep_enable = 1;
		ctldev->sim = 1;
		ctldev->index = LSX_PCIE_SIM_IDX;
		LSX_PCIEP_BUS_INFO("iNIC Simulator PCIe(%d) EP added.",
			ctldev->index);

		return 1;
	}

	for (i = 0; i < s_pcie_sim_list_num; i++) {
		ctldev = lsx_pciep_ctl_get_dev(s_pcie_sim_list[i]);
		RTE_ASSERT(ctldev);
		ctldev->ep_enable = 1;
		ctldev->sim = 1;
		ctldev->index = s_pcie_sim_list[i];
		LSX_PCIEP_BUS_INFO("iNIC Simulator PCIe(%d) EP added.",
			ctldev->index);
	}

	return s_pcie_sim_list_num;
}

static int
lsx_pciep_scan(void)
{
	uint8_t pcie_idx = 0;
	int ret;

	ret = lsx_pciep_parse_env_variable();
	if (ret)
		return ret;

	ret = lsx_pciep_init();
	if (ret)
		return ret;

	while (1) {
		if (!lsx_pciep_ctl_idx_validated(pcie_idx))
			break;
		ret = lsx_pciep_create_dev(pcie_idx);
		if (!ret)
			LSX_PCIEP_BUS_INFO("EP device on PEX%d", pcie_idx);
		pcie_idx++;
	}

	return 0;
}


static int
lsx_pciep_match(struct rte_lsx_pciep_driver *ep_drv,
		struct rte_lsx_pciep_device *ep_dev)
{
	int ret = 1;
	static int s_cnt;

	if (!strncmp(ep_drv->name, ep_dev->name,
			strlen(LSX_PCIEP_NXP_NAME_PREFIX) - 1))
		ret = 0;

	if (!strncmp(ep_drv->name, ep_dev->name,
			strlen(LSX_PCIEP_VIRT_NAME_PREFIX) - 1))
		ret = 0;

	if (strstr(ep_dev->name, "_vf"))
		ret = 0;

	if (s_cnt > RTE_MAX_ETHPORTS)
		return 1;

	s_cnt++;
	return ret;
}

struct rte_lsx_pciep_device *
lsx_pciep_first_dev(void)
{
	return (struct rte_lsx_pciep_device *)
			TAILQ_FIRST(&lsx_pciep_bus.device_list);
}

static int
lsx_pciep_probe(void)
{
	int ret = 0;
	struct rte_lsx_pciep_device *dev;
	struct rte_lsx_pciep_driver *drv;

	if (TAILQ_EMPTY(&lsx_pciep_bus.device_list))
		return 0;

	TAILQ_FOREACH(dev, &lsx_pciep_bus.device_list, next) {
		TAILQ_FOREACH(drv, &lsx_pciep_bus.driver_list, next) {
			ret = lsx_pciep_match(drv, dev);
			if (ret)
				continue;

			lsx_pciep_ctl_init_win(dev->pcie_id);

			if (!drv->probe)
				continue;

			ret = drv->probe(drv, dev);
			if (ret)
				LSX_PCIEP_BUS_LOG(ERR, "Unable to probe.\n");
			break;  /* note this  */
		}
	}

	return 0;
}

static int
lsx_pciep_parse(const char *name, void *out_name)
{
	int i, j;

	LSX_PCIEP_BUS_INFO("PCIe EP bus parse name %s", name);

	/* Check for lsxep_nxp_2_pf0 style */

	for (i = 0; i < LSX_MAX_PCIE_NB; i++) {
		for (j = 0; j < PF_MAX_NB; j++) {
			char tmp_name[32];

			snprintf(tmp_name, 16, "lsxep_nxp_%d_pf%d", i, j);
			if (strcmp(tmp_name, name) == 0) {
				if (out_name)
					strcpy(out_name, name);
				return 0;
			}
		}
	}

	return -EINVAL;
}

static void *
lsx_pciep_dev_iterate(const void *start, const char *str,
	const struct rte_dev_iterator *it __rte_unused)
{
	const struct rte_lsx_pciep_device *dstart;
	struct rte_lsx_pciep_device *dev;
	char *dup, *dev_name = NULL;

	/* Expectation is that device would be name=device_name */
	if (strncmp(str, "name=", 5) != 0) {
		LSX_PCIEP_BUS_ERR("Invalid device string (%s)\n", str);
		return NULL;
	}

	/* Now that name=device_name format is available, split */
	dup = strdup(str);
	dev_name = dup + strlen("name=");

	if (start != NULL) {
		dstart = RTE_DEV_TO_LSX_PCIEP_CONST(start);
		dev = TAILQ_NEXT(dstart, next);
	} else {
		dev = TAILQ_FIRST(&lsx_pciep_bus.device_list);
	}

	while (dev != NULL) {
		if (strcmp(dev->device.name, dev_name) == 0) {
			free(dup);
			return &dev->device;
		}
		dev = TAILQ_NEXT(dev, next);
	}

	free(dup);
	return NULL;
}

static struct rte_lsx_pciep_bus lsx_pciep_bus = {
	.bus = {
		.scan = lsx_pciep_scan,
		.probe = lsx_pciep_probe,
		.parse = lsx_pciep_parse,
		.dev_iterate = lsx_pciep_dev_iterate,
		.find_device = lsx_pciep_find_device,
	},
	.device_list = TAILQ_HEAD_INITIALIZER(lsx_pciep_bus.device_list),
	.driver_list = TAILQ_HEAD_INITIALIZER(lsx_pciep_bus.driver_list),
};

/* register a lsinic_vdev bus based lsinic driver */
void
rte_lsx_pciep_driver_register(struct rte_lsx_pciep_driver *driver)
{
	RTE_VERIFY(driver);

	TAILQ_INSERT_TAIL(&lsx_pciep_bus.driver_list, driver, next);
	/* Update Bus references */
	driver->lsx_pciep_bus = &lsx_pciep_bus;
}

/* un-register a lsinic_vdev bus based lsinic driver */
void
rte_lsx_pciep_driver_unregister(struct rte_lsx_pciep_driver *driver)
{
	struct rte_lsx_pciep_bus *bus;

	bus = driver->lsx_pciep_bus;

	TAILQ_REMOVE(&bus->driver_list, driver, next);
	/* Update Bus references */
	driver->lsx_pciep_bus = NULL;
}

RTE_REGISTER_BUS(LSX_PCIEP_BUS_NAME, lsx_pciep_bus.bus);
