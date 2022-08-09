/* SPDX-License-Identifier: GPL-2.0
 *
 *   Copyright 2022 NXP
 *
 */

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <asm/tlbflush.h>
#include "kpage_ncache.h"


#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "[kpg_nc] " fmt

bool TKT340553_SW_WORKAROUND = 1;
int nc_mask = 0x44, mair_idx;
static bool dev_open = false;

/* Page Table levels */
pgd_t *pgd;
p4d_t *p4d;
pud_t *pud;
pmd_t *pmd;
pte_t *pte;

typedef struct tlb_info {
  struct vm_area_struct* vma;
  unsigned long pg_addr;
} tlb_info_t;


static int
kpg_nc_dev_open(struct inode *inode, struct file *file)
{
	/* Device busy? */
	if (dev_open)
		return -EBUSY;

	dev_open = 1;
	return 0;
}

static int
kpg_nc_dev_release(struct inode *inode, struct file *file)
{
	/* Reset device */
	dev_open = 0;
	return 0;
}

void
tlb_update(void* info)
{
  tlb_info_t* data = (tlb_info_t*) info;
  flush_tlb_page(data->vma, data->pg_addr);
}

static int
kpg_nc_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  switch (ioctl_num) {
    case KPG_NC_IOCTL_UPDATE:
    {
		size_t pg_addr = 0;
		struct task_struct *task;
		struct vm_area_struct *vma;
		tlb_info_t info;
		struct mm_struct *md;
		pmd_t pmd_val;
		int attr_idx;

		pr_info("Got IOCTL KPG_NC_IOCTL_UPDATE\n");
        raw_copy_from_user(&pg_addr, (void*)ioctl_param, sizeof(pg_addr));
		if (!pg_addr) {
			pr_err("Invalid page addr\n");
			return -1;
		}
		/* Get Memory Descriptor */
		task = current;
		if (task->mm)
			md = task->mm;
		else
			md = task->active_mm;
		if(!md){
			pr_err("Memory Descriptor for current process not found.\n");
			return -1;
		}
		mmap_write_lock(md);
		
		pgd = pgd_offset(md, pg_addr);
		p4d = p4d_offset(pgd, pg_addr);
		pud = pud_offset(p4d, pg_addr);
		pmd = pmd_offset(pud, pg_addr);
		pte = pte_offset_map(pmd, pg_addr);

		pmd_val.pmd = pmd->pmd;
		pr_info("-----------------------------\n");
		pr_info("Page addr: 0x%lX\n", pg_addr);
		pr_info("PGD = 0x%llX\n", pgd->pgd);
		//pr_info("P4D = 0x%llX\n", *p4d);
		pr_info("PUD = 0x%llX\n", pud->pud);
		pr_info("PMD = 0x%llX\n", pmd->pmd);
		pr_info("PTE = 0x%llX\n", pte->pte);
		pr_info("-----------------------------\n");
		attr_idx = (int)(pmd_val.pmd >> 2) & 7;
		pr_info("Current: PMD = 0x%llX, MAIRi = %d\n", pmd_val.pmd, attr_idx);

		/* Apply new attribute */
		if (attr_idx != mair_idx) {
			pmd_val.pmd &= ~0x1c;
			pmd_val.pmd |= (mair_idx & 7) << 2;
			set_pmd(pmd, pmd_val);
			pr_info("Updated: PMD = 0x%llX, MAIRi = %d\n",
							pmd_val.pmd, (int)(pmd_val.pmd >> 2) & 7);

			/* Invalidate TLB for each CPU */
			vma = find_vma(md, pg_addr);
			if (vma == NULL) {
				pr_err("Invalid VMA: Not able to invalidate TLB.\n");
				return -1;
			}
			info.vma = vma;
			info.pg_addr = pg_addr;
			on_each_cpu(tlb_update, &info, 1);
		} else
			pr_info("Page is already non-cacheable\n");

		mmap_write_unlock(md);

        return 0;
    }
    default:
		pr_warn("Unsupported IOCTL 0x%X num\n", ioctl_num);
        return -1;
  }

  return 0;
}

static const struct file_operations kpg_nc_fops = {
	.owner = THIS_MODULE,
	.open = kpg_nc_dev_open,
	.release = kpg_nc_dev_release,
	.unlocked_ioctl = (void *)kpg_nc_ioctl,
	.compat_ioctl = NULL,
};

static struct miscdevice kpg_nc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = KPG_NC_DEVICE_NAME,
	.fops = &kpg_nc_fops,
//    .mode = S_IRWXUGO,
};


static int
__init kpg_nc_init(void)
{
	int ret;
	uint64_t mair;
	int i, attr;

	/* Register device */
	ret = misc_register(&kpg_nc_dev);
	if (ret != 0) {
		pr_err("Failed registering device with %d\n", ret);
		return -ENXIO;
	}

	/* Get supported Memory Attributes */
    asm volatile ("mrs %0, mair_el1\n" : "=r"(mair));
	pr_info("MAIR = 0x%llX\n", mair);
#if 0
	mair = 0x4004FFFFF;
	nc_mask = 0x4F;
    asm volatile ("msr mair_el1, %0\n" : : "r"(mair));
	pr_info("NEW MAIR = 0x%llX\n", mair);
#endif
	/* check for NC attribute */
    for (i = 0; i < 8; i++) {
		attr = (int)(mair >> (i * 8)) & 0xFF;
		if ((attr & nc_mask) == nc_mask)
			mair_idx = i;

		pr_info("ATTR-%d = 0x%02X\n", i, attr);
	}

	if (mair_idx)
		pr_info("NC attribute found at %d\n", mair_idx);
	else{
		pr_err("NC attribute not found\n");
		return -EEXIST;
	}

	pr_info("Successfully loaded.\n");
	return 0;
}

static void
__exit kpg_nc_exit(void)
{
  misc_deregister(&kpg_nc_dev);
  
  pr_info("Unloaded\n");
}

module_init(kpg_nc_init);
module_exit(kpg_nc_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Sachin Saxena");
MODULE_DESCRIPTION("Update a page mapping to Non-cacheable");
