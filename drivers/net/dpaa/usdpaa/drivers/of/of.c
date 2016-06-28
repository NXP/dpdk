/* Copyright (c) 2010 - 2012 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <usdpaa/of.h>
#include <internal/of.h>

#define OF_DEFAULT_NA 1
#define OF_DEFAULT_NS 1

/* The API presents the "struct device_node" type, so we embed that in something
 * that can be converted back to a corresponding dir/file node. */
struct dt_node {
	struct device_node node;
	int is_file; /* FALSE==dir, TRUE==file */
	struct list_head list; /* within parent's "subdirs" or "files" */
};

/* Types we use to represent directories and files */
struct dt_file;
struct dt_dir {
	struct dt_node node;
	struct list_head subdirs;
	struct list_head files;
	struct list_head linear; /* post-processed "flat" list */
	struct dt_dir *parent;
	/* We tag particular property files during the linear pass */
	struct dt_file *compatible;
	struct dt_file *status;
	struct dt_file *lphandle;
	struct dt_file *a_cells;
	struct dt_file *s_cells;
	struct dt_file *reg;
};
#define BUF_MAX 256
struct dt_file {
	struct dt_node node;
	struct dt_dir *parent;
	ssize_t len;
	/* Annoying type, but only good way to ensure alignment. */
	uint64_t buf[BUF_MAX >> 3];
};

static const struct dt_dir *node2dir(const struct device_node *n)
{
	const struct dt_node *dn = container_of(n, struct dt_node, node);
	const struct dt_dir *d = container_of(dn, struct dt_dir, node);
	assert(!dn->is_file);
	return d;
}

static int alive;
static struct dt_dir root_dir;
static const char *base_dir;
static LIST_HEAD(linear);

static int my_open_dir(const char *relative_path, struct dirent ***d)
{
	int ret;
	char full_path[PATH_MAX];

	snprintf(full_path, PATH_MAX, "%s/%s", base_dir, relative_path);
	ret = scandir(full_path, d, 0, versionsort);
	if (ret < 0) {
		fprintf(stderr, "Failed to open directory %s\n", full_path);
		perror("scandir");
	}
	return ret;
}

static void my_close_dir(struct dirent **d, int num)
{
	while (num--)
		free(d[num]);
	free(d);
}

static int my_open_file(const char *relative_path)
{
	int ret;
	char full_path[PATH_MAX];
	snprintf(full_path, PATH_MAX, "%s/%s", base_dir, relative_path);
	ret = open(full_path, O_RDONLY);
	if (ret < 0) {
		fprintf(stderr, "Failed to open file %s\n", full_path);
		perror("open");
	}
	return ret;
}

static void process_file(struct dirent *dent, struct dt_dir *parent)
{
	int fd;
	struct dt_file *f = malloc(sizeof(*f));
	if (!f) {
		perror("malloc");
		return;
	}
	f->node.is_file = 1;
	snprintf(f->node.node.name, NAME_MAX, "%s", dent->d_name);
	snprintf(f->node.node.full_name, PATH_MAX, "%s/%s",
		parent->node.node.full_name, dent->d_name);
	f->parent = parent;
	fd = my_open_file(f->node.node.full_name);
	if (fd < 0) {
		free(f);
		return;
	}
	f->len = read(fd, f->buf, BUF_MAX);
	close(fd);
	if (f->len < 0) {
		free(f);
		return;
	}
	list_add_tail(&f->node.list, &parent->files);
}

/* process_dir() calls iterate_dir(), but the latter will also call the former
 * when recursing into sub-directories, so a predeclaration is needed. */
static int process_dir(const char *relative_path, struct dt_dir *dt);

static int iterate_dir(struct dirent **d, int num, struct dt_dir *dt)
{
	int loop;
	/* Iterate the directory contents */
	for (loop = 0; loop < num; loop++) {
		struct dt_dir *subdir;
		int ret;
		/* Ignore dot files of all types (especially "..") */
		if (d[loop]->d_name[0] == '.')
			continue;
		switch (d[loop]->d_type) {
		case DT_REG:
			process_file(d[loop], dt);
			break;
		case DT_DIR:
			subdir = malloc(sizeof(*subdir));
			if (!subdir) {
				perror("malloc");
				return -ENOMEM;
			}
			snprintf(subdir->node.node.name, NAME_MAX, "%s",
				d[loop]->d_name);
			snprintf(subdir->node.node.full_name, PATH_MAX, "%s/%s",
				dt->node.node.full_name, d[loop]->d_name);
			subdir->parent = dt;
			ret = process_dir(subdir->node.node.full_name, subdir);
			if (ret)
				/* NOTE: we leak 'subdir' here, but to fix that
				 * requires support for unwinding... */
				return ret;
			list_add_tail(&subdir->node.list, &dt->subdirs);
			break;
		default:
			fprintf(stderr, "Ignoring invalid dt entry %s/%s\n",
				dt->node.node.full_name, d[loop]->d_name);
		}
	}
	return 0;
}

static int process_dir(const char *relative_path, struct dt_dir *dt)
{
	struct dirent **d;
	int ret, num;

	dt->node.is_file = 0;
	INIT_LIST_HEAD(&dt->subdirs);
	INIT_LIST_HEAD(&dt->files);
	ret = my_open_dir(relative_path, &d);
	if (ret < 0)
		return ret;
	num = ret;
	ret = iterate_dir(d, num, dt);
	my_close_dir(d, num);
	return (ret < 0) ? ret : 0;
}

static void linear_dir(struct dt_dir *d)
{
	struct dt_file *f;
	struct dt_dir *dd;
	d->compatible = NULL;
	d->status = NULL;
	d->lphandle = NULL;
	d->a_cells = NULL;
	d->s_cells = NULL;
	d->reg = NULL;
	list_for_each_entry(f, &d->files, node.list) {
		if (!strcmp(f->node.node.name, "compatible")) {
			if (d->compatible)
				fprintf(stderr, "Duplicate compatible in %s!\n",
					d->node.node.full_name);
			d->compatible = f;
		} else if (!strcmp(f->node.node.name, "status")) {
			if (d->status)
				fprintf(stderr, "Duplicate status in %s!\n",
					d->node.node.full_name);
			d->status = f;
		} else if (!strcmp(f->node.node.name, "linux,phandle")) {
			if (d->lphandle)
				fprintf(stderr, "Duplicate lphandle in %s!\n",
					d->node.node.full_name);
			d->lphandle = f;
		} else if (!strcmp(f->node.node.name, "#address-cells")) {
			if (d->a_cells)
				fprintf(stderr, "Duplicate a_cells in %s!\n",
					d->node.node.full_name);
			d->a_cells = f;
		} else if (!strcmp(f->node.node.name, "#size-cells")) {
			if (d->s_cells)
				fprintf(stderr, "Duplicate s_cells in %s!\n",
					d->node.node.full_name);
			d->s_cells = f;
		} else if (!strcmp(f->node.node.name, "reg")) {
			if (d->reg)
				fprintf(stderr, "Duplicate reg in %s!\n",
					d->node.node.full_name);
			d->reg = f;
		}
	}
	list_for_each_entry(dd, &d->subdirs, node.list) {
		list_add_tail(&dd->linear, &linear);
		linear_dir(dd);
	}
}

int of_init_path(const char *dt_path)
{
	int ret;

	base_dir = dt_path;
	WARN_ON(alive, "Double-init of device-tree driver!");
	/* Prepare root node (the remaining fields are set in process_dir()) */
	root_dir.node.node.name[0] = '\0';
	root_dir.node.node.full_name[0] = '\0';
	INIT_LIST_HEAD(&root_dir.node.list);
	root_dir.parent = NULL;
	/* Kick things off... */
	ret = process_dir("", &root_dir);
	if (ret)
		return ret;
	/* Now make a flat, linear list of directories */
	linear_dir(&root_dir);
	alive = 1;
	return 0;
}

static void destroy_dir(struct dt_dir *d)
{
	struct dt_file *f, *tmpf;
	struct dt_dir *dd, *tmpd;
	list_for_each_entry_safe(f, tmpf, &d->files, node.list) {
		list_del(&f->node.list);
		free(f);
	}
	list_for_each_entry_safe(dd, tmpd, &d->subdirs, node.list) {
		destroy_dir(dd);
		list_del(&dd->node.list);
		free(dd);
	}
}

void of_finish(void)
{
	WARN_ON(!alive, "Double-finish of device-tree driver!");
	destroy_dir(&root_dir);
	INIT_LIST_HEAD(&linear);
	alive = 0;
}

static void print_dir(struct dt_dir *d)
{
	struct dt_file *f;
	struct dt_dir *dd;
	list_for_each_entry(f, &d->files, node.list)
		printf("%s\n", f->node.node.full_name);
	list_for_each_entry(dd, &d->subdirs, node.list)
		print_dir(dd);
}

void of_print(void)
{
	print_dir(&root_dir);
}

static const struct dt_dir *next_linear(const struct dt_dir *f)
{
	if (f->linear.next == &linear)
		return NULL;
	return list_entry(f->linear.next, struct dt_dir, linear);
}

static int check_compatible(const struct dt_file *f, const char *compatible)
{
	const char *c = (char *)f->buf;
	unsigned int len, remains = f->len;
	while (remains) {
		len = strlen(c);
		if (!strcmp(c, compatible))
			return 1;

		if (remains < len + 1)
			break;

		c += (len + 1);
		remains -= (len + 1);
	}
	return 0;
}

const struct device_node *of_find_compatible_node(
					const struct device_node *from,
					const char *type __always_unused,
					const char *compatible)
{
	const struct dt_dir *d;
	WARN_ON(!alive, "Device-tree driver not initialised");
	if (list_empty(&linear))
		return NULL;
	if (!from)
		d = list_entry(linear.next, struct dt_dir, linear);
	else
		d = node2dir(from);
	for (d = next_linear(d); d && (!d->compatible ||
			!check_compatible(d->compatible, compatible));
			d = next_linear(d))
		;
	if (d)
		return &d->node.node;
	return NULL;
}

const void *of_get_property(const struct device_node *from, const char *name,
				size_t *lenp)
{
	const struct dt_dir *d;
	const struct dt_file *f;
	WARN_ON(!alive, "Device-tree driver not initialised");
	d = node2dir(from);
	list_for_each_entry(f, &d->files, node.list)
		if (!strcmp(f->node.node.name, name)) {
			if (lenp)
				*lenp = f->len;
			return f->buf;
		}
	return NULL;
}

bool of_device_is_available(const struct device_node *dev_node)
{
	const struct dt_dir *d;
	WARN_ON(!alive, "Device-tree driver not initialised");
	d = node2dir(dev_node);
	if (!d->status)
		return true;
	if (!strcmp((char *)d->status->buf, "okay"))
		return true;
	if (!strcmp((char *)d->status->buf, "ok"))
		return true;
	return false;
}

const struct device_node *of_find_node_by_phandle(phandle ph)
{
	const struct dt_dir *d;
	WARN_ON(!alive, "Device-tree driver not initialised");
	list_for_each_entry(d, &linear, linear)
		if (d->lphandle && (d->lphandle->len == 4) &&
				!memcmp(d->lphandle->buf, &ph, 4))
			return &d->node.node;
	return NULL;
}

const struct device_node *of_get_parent(const struct device_node *dev_node)
{
	const struct dt_dir *d;
	WARN_ON(!alive, "Device-tree driver not initialised");
	if (!dev_node)
		return NULL;
	d = node2dir(dev_node);
	if (!d->parent)
		return NULL;
	return &d->parent->node.node;
}

const struct device_node *of_get_next_child(const struct device_node *dev_node,
					    const struct device_node *prev)
{
	const struct dt_dir *p, *c;
	WARN_ON(!alive, "Device-tree driver not initialised");
	if (!dev_node)
		return NULL;
	p = node2dir(dev_node);
	if (prev) {
		c = node2dir(prev);
		WARN_ON(c->parent != p, "Parent/child mismatch");
		if (c->parent != p)
			return NULL;
		if (c->node.list.next == &p->subdirs)
			/* prev was the last child */
			return NULL;
		c = list_entry(c->node.list.next, struct dt_dir, node.list);
		return &c->node.node;
	}
	/* Return first child */
	if (list_empty(&p->subdirs))
		return NULL;
	c = list_entry(p->subdirs.next, struct dt_dir, node.list);
	return &c->node.node;
}

uint32_t of_n_addr_cells(const struct device_node *dev_node)
{
	const struct dt_dir *d;
	WARN_ON(!alive, "Device-tree driver not initialised");
	if (!dev_node)
		return OF_DEFAULT_NA;
	d = node2dir(dev_node);
	while ((d = d->parent))
		if (d->a_cells) {
			unsigned char *buf =
				(unsigned char *)&d->a_cells->buf[0];
			assert(d->a_cells->len == 4);
			return ((uint32_t)buf[0] << 24) |
				((uint32_t)buf[1] << 16) |
				((uint32_t)buf[2] << 8) |
				(uint32_t)buf[3];
		}
	return OF_DEFAULT_NA;
}

uint32_t of_n_size_cells(const struct device_node *dev_node)
{
	const struct dt_dir *d;
	WARN_ON(!alive, "Device-tree driver not initialised");
	if (!dev_node)
		return OF_DEFAULT_NA;
	d = node2dir(dev_node);
	while ((d = d->parent))
		if (d->s_cells) {
			unsigned char *buf =
				(unsigned char *)&d->s_cells->buf[0];
			assert(d->s_cells->len == 4);
			return ((uint32_t)buf[0] << 24) |
				((uint32_t)buf[1] << 16) |
				((uint32_t)buf[2] << 8) |
				(uint32_t)buf[3];
		}
	return OF_DEFAULT_NS;
}

const uint32_t *of_get_address(const struct device_node *dev_node, size_t idx,
				uint64_t *size, uint32_t *flags)
{
	const struct dt_dir *d;
	const unsigned char *buf;
	uint32_t na = of_n_addr_cells(dev_node);
	uint32_t ns = of_n_size_cells(dev_node);
	if (!dev_node)
		d = &root_dir;
	else
		d = node2dir(dev_node);
	if (!d->reg)
		return NULL;
	assert(d->reg->len % ((na + ns) * 4) == 0);
	assert(d->reg->len / ((na + ns) * 4) > idx);
	buf = (const unsigned char *)&d->reg->buf[0];
	buf += (na + ns) * idx * 4;
	if (size)
		for (*size = 0; ns > 0; ns--, na++)
			*size = (*size << 32) +
				(((uint32_t)buf[4 * na] << 24) |
				((uint32_t)buf[4 * na + 1] << 16) |
				((uint32_t)buf[4 * na + 2] << 8) |
				(uint32_t)buf[4 * na + 3]);
	return (const uint32_t *)buf;
}

uint64_t of_translate_address(const struct device_node *dev_node,
			      const uint32_t *addr)
{
	uint64_t phys_addr, tmp_addr;
	const struct device_node *parent;
	const uint32_t *ranges;
	size_t rlen;
	uint32_t na, pna;

	WARN_ON(!alive, "Device-tree driver not initialised");
	assert(dev_node != NULL);

	na = of_n_addr_cells(dev_node);
	phys_addr = of_read_number(addr, na);

	dev_node = of_get_parent(dev_node);
	if (!dev_node)
		return 0;
	else if (node2dir(dev_node) == &root_dir)
		return phys_addr;

	do {
		pna = of_n_addr_cells(dev_node);
		parent = of_get_parent(dev_node);
		if (!parent)
			return 0;

		ranges = of_get_property(dev_node, "ranges", &rlen);
		/* "ranges" property is missing. Translation breaks */
		if (!ranges)
			return 0;
		/* "ranges" property is empty. Do 1:1 translation */
		else if (rlen == 0)
			continue;
		else
			tmp_addr = of_read_number(ranges + na, pna);

		na = pna;
		dev_node = parent;
		phys_addr += tmp_addr;
	} while (node2dir(parent) != &root_dir);

	return phys_addr;
}

bool of_device_is_compatible(const struct device_node *dev_node,
				const char *compatible)
{
	const struct dt_dir *d;
	WARN_ON(!alive, "Device-tree driver not initialised");
	if (!dev_node)
		d = &root_dir;
	else
		d = node2dir(dev_node);
	if (d->compatible && check_compatible(d->compatible, compatible))
		return true;
	return false;
}

struct device_node *of_find_node_with_property(struct device_node *from,
	const char *prop_name)
{
	const struct dt_dir *d;
	const struct dt_file *f;

	WARN_ON(!alive, "Device-tree driver not initialised");
	if (list_empty(&linear))
		return NULL;
	if (!from)
		d = list_entry(linear.next, struct dt_dir, linear);
	else
		d = node2dir(from);

	for (d = next_linear(d); d; d = next_linear(d)) {
		list_for_each_entry(f, &d->files, node.list)
			if (!strcmp(f->node.node.name, prop_name))
				return (struct device_node *)&d->node.node;
	}
	return NULL;
}
