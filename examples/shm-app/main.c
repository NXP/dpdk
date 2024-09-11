/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <strings.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <signal.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_string_fns.h>
#include <rte_hexdump.h>

/* Maximum long option length for option parsing. */
#define MAX_LONG_OPT_SZ 64

static volatile int force_quit;
static int app_mode;

#define SOCKET_NAME "/tmp/high-phy-du.socket"

// a struct to be read and written
struct shared_file_data {
	int memfd;
	uint64_t phyaddr;
	uint64_t memsz;
	uint64_t offset;
	uint64_t pagesz;
	uint64_t server_pid;
};

struct data_msg{
	uint64_t fd_size;
	rte_iova_t iova;
	uint64_t pg_size;
	uint64_t offset;
};

/* Parse the argument given in the command line of the application */
static int
parse_config(int argc, char **argv)
{
	int opt;
	int option_index;
	static struct option long_option[] = {
		{"client", optional_argument, NULL, 0},
		{NULL, 0, 0, 0}
	};

	if (argc == 1)
		return 0;

	/* Parse command line */
	opt = getopt_long(argc, argv, "p", long_option, &option_index);
	if (opt == 0) {
		/* client mode */
			if (!strncmp(long_option[option_index].name, "client",
					MAX_LONG_OPT_SZ))
				app_mode = 1;
	}
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = 1;
	}
}

static int
recv_fd(int from, struct shared_file_data *p)
{
	int fd = 0;
	size_t cmsglen = CMSG_LEN(sizeof(fd));
	struct cmsghdr *cmhdr = malloc(cmsglen);
	struct data_msg data_message;

	if (cmhdr == NULL) {
		printf("Malloc error\n");
		return -1;
	}

	struct iovec iov = {
		.iov_base = (void *)&data_message,
		.iov_len = sizeof(data_message)
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmhdr,
		.msg_controllen = cmsglen,
	};
	if (recvmsg(from, &msg, 0) != (int)iov.iov_len) {
		printf("recvmsg error %s\n", strerror(errno));
		return -1;
	}
	if (msg.msg_controllen != cmsglen) {
		printf("Error with fd on message received\n");
		return -1;
	}
	fd = *(int *)CMSG_DATA(cmhdr);

	free(cmhdr);

	p->offset = data_message.offset;
	p->memsz = data_message.fd_size;
	p->phyaddr = data_message.iova;
	p->pagesz = data_message.pg_size;
	p->memfd = fd;

	return fd;
}

static int
send_fd(int to, int fd, struct shared_file_data *p)
{
	struct iovec iov = {0};
	struct msghdr msg = {0};
	size_t cmsglen = CMSG_LEN(sizeof(fd));
	struct cmsghdr *cmhdr = malloc(cmsglen);
	int ret = 0;

	struct data_msg data_message = {p->memsz,
					p->phyaddr,
					p->pagesz,
					p->offset};
	if (cmhdr == NULL)
		return -1;
	iov.iov_base = (void *)&data_message;
	iov.iov_len = sizeof(data_message);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	cmhdr->cmsg_level = SOL_SOCKET;
	cmhdr->cmsg_type = SCM_RIGHTS;
	cmhdr->cmsg_len = cmsglen;
	msg.msg_control = cmhdr;
	msg.msg_controllen = cmsglen;
	*(int *)CMSG_DATA(cmhdr) = fd;

	if (sendmsg(to, &msg, 0) != (int)iov.iov_len) {
		printf("Error sending message to client, %s\n", strerror(errno));
		ret = -1;
	}
	free(cmhdr);
	return ret;
}

static
int client_ipc_socket(struct shared_file_data *p)
{
	int                 ret;
	int                 data_socket;
	struct sockaddr_un  addr;

	/* Create local socket. */
	data_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (data_socket == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&addr, 0, sizeof(addr));

	/* Connect socket to socket address. */

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);

	ret = connect(data_socket, (const struct sockaddr *) &addr, sizeof(addr));
	if (ret == -1) {
		fprintf(stderr, "The server is down.\n");
		exit(EXIT_FAILURE);
	}

	ret = recv_fd(data_socket,p);
	if (ret == -1) {
		fprintf(stderr, "Unable to read\n");
		exit(EXIT_FAILURE);
	}

	/* Close socket. */
	close(data_socket);

	return 0;
}

static void *
server_socket_thread(void *param)
{
	int data_socket;
	int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	struct shared_file_data *p = (struct shared_file_data *)param;

	if (sock < 0) {
		printf("Error creating socket\n");
		return NULL;
	}

	struct sockaddr_un sun = {.sun_family = AF_UNIX};

	strlcpy(sun.sun_path, SOCKET_NAME, sizeof(sun.sun_path));
	printf("Attempting socket bind to path '%s'\n", sun.sun_path);

	if (bind(sock, (void *) &sun, sizeof(sun)) < 0) {
		printf("Error binding socket: %s\n", strerror(errno));
		close(sock);
		return NULL; /* if unlink failed, this will be -EADDRINUSE as above */
	}

	if (listen(sock, 1) < 0) {
		printf("Error calling listen for socket: %s\n", strerror(errno));
		unlink(sun.sun_path);
		close(sock);
		return NULL;
	}
	printf("Socket %s listening ok\n", sun.sun_path);

	/* a server traditionally listens indefinitely */
		data_socket = accept(sock, NULL, NULL);
		if (data_socket == -1) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
		printf("Sending data\n");
		send_fd(data_socket, p->memfd, p);

	close(data_socket);
	unlink(sun.sun_path);
	close(sock); /* break connection */
	return NULL;

}

static void *main_data_loop(void *arg)
{
	cpu_set_t cpuset;
	int ret,i,j=0x11111111, sample=20;
	
	uint64_t *data = arg;
	
	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	printf("affinity  thread to cpu 0 %s\r\n",
		ret ? "failed" : "success");

	while (!force_quit) {
		sleep(1);

		if (app_mode) {
			rte_hexdump(stderr, NULL, data, sample);
		} else {
			for (i = 0, j+=1; i < sample; i++) {
				data[i] = j;
			}
			//rte_hexdump(stderr, NULL, data, sample);
		}
	}

	return arg;
}

static int
pagesz_flags(uint64_t page_sz)
{
	/* as per mmap() manpage, all page sizes are log2 of page size
	 * shifted by MAP_HUGE_SHIFT
	 */
	int log2 = rte_log2_u64(page_sz);

	return (log2 << MAP_HUGE_SHIFT);
}

int
main(int argc, char **argv)
{
	int ret, status;
	pthread_t pid;
	char s[PATH_MAX];
	uint32_t mz_size = 64*1024*1024;
	const struct rte_memzone *mz;
	const struct rte_memseg *ms;
	int flags;
	void * addr;

	struct shared_file_data mydata= {};

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	force_quit = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = parse_config(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid argument\n");

	if (app_mode) {
		int pagesz_flag;

		client_ipc_socket(&mydata);

		printf("\n RCVD : iova=0x%lx fd = %d off = 0x%lx\n",
			mydata.phyaddr, mydata.memfd, mydata.offset);
		
		if (mydata.memfd < 0 || mydata.memsz <= 0 || mydata.memsz % (1 << 21) != 0) {
			printf("Error getting memfd and size\n");
			return -1;
		}
		flags = MAP_SHARED | MAP_HUGETLB;
		pagesz_flag = pagesz_flags(mydata.pagesz);
		flags = flags | pagesz_flag;

		addr = mmap(NULL, mydata.memsz,
				PROT_READ|PROT_WRITE, flags,
				mydata.memfd, 0);
		if (addr == MAP_FAILED) {
			printf("Error with mmap\n");
			rte_errno = errno;
			return -1;
		}
		printf("\n CLIENT: iova=0x%lx vaddr=%p fd = %d off = %ld\n",
			mydata.phyaddr, addr, 
			mydata.memfd, mydata.offset);
		addr = (void *)((uint64_t)addr +  mydata.offset);
	} else {
		uint64_t offset;
		pthread_t listen_thread;

		snprintf(s, sizeof(s), "fapi_shared");
		mz = rte_memzone_reserve_aligned(s, mz_size, rte_socket_id(),
				RTE_MEMZONE_1GB |
				RTE_MEMZONE_SIZE_HINT_ONLY |
				RTE_MEMZONE_IOVA_CONTIG, (1*1024*1024*1024));
		if (mz == NULL) {
			printf("Failed to allocate fapi memory aligned\n");
			mz = rte_memzone_reserve(s, mz_size, rte_socket_id(),
				RTE_MEMZONE_1GB |
				RTE_MEMZONE_SIZE_HINT_ONLY |
				RTE_MEMZONE_IOVA_CONTIG);
			if (mz == NULL) {
				printf("Failed to allocate fapi shared memory\n");
				rte_errno = ENOMEM;
				return -1;
			}	
		}
		addr = mz->addr;
		ms = rte_mem_virt2memseg(mz->addr, NULL);
		mydata.memfd = rte_memseg_get_fd(ms);
		ret = rte_memseg_get_fd_offset(ms, &offset);

		mydata.offset = mz->iova - ms->iova;
		mydata.pagesz = ms->hugepage_sz;
		mydata.phyaddr = ms->iova;
		mydata.memsz = mz_size;
		mydata.server_pid = getpid();

		/*thread to pass memory FD to the client */
		pthread_create(&listen_thread, NULL, server_socket_thread, &mydata);
		pthread_detach(listen_thread);

		printf("\n SERVER: iova=0x%lx vaddr=%p fd = %d off = 0x%lx page=0x%lx\n",
			ms->iova, addr, 
			mydata.memfd, mydata.offset, mydata.pagesz);
	}
	rte_memzone_dump(stdout);
	rte_dump_physmem_layout(stdout);

	status = pthread_create(&pid, NULL, main_data_loop, addr);
	if (status != 0) {
		fprintf(stderr, "pthread_create() failed [status: %d]\n", status);
		return 0;
	}
	status = pthread_join(pid, NULL);
	if (status != 0) {
		fprintf(stderr, "pthread_join() failed [status: %d]\n", status);
	}
	printf("exit\n");

	ret = rte_eal_cleanup();
	if (ret)
		printf("Error from rte_eal_cleanup(), %d\n", ret);

	return 0;
}
