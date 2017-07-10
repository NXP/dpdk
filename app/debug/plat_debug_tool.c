/*
 * Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file        plat_debug_tool.c
 *
 * @brief       DPAA2 platform specific debugging tool.
 *
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ?                 \
			    strrchr((file_name), '/') + 1 : (file_name))
#define BPOOL_START_OBJ_ID 15
#define DPSECI_START_OBJ_ID 18
#define MAX_OBJ_ID 20
#define SA_STATS_OBJ_ID MAX_OBJ_ID
#define ALL_DUMP (MAX_OBJ_ID + 1)
#define DEFAULT_PLAT_DEBUG_PORT 10000

typedef struct ipc_msg {
	uint16_t obj_id;
	uint8_t cmd;
	uint8_t buffer_len;
	char buffer[64];
} ipc_msg_t;

typedef struct parse_msg {
	ipc_msg_t msg;
	in_addr_t addr;
}parse_msg_t;

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
		"Usage: %s OPTIONS\n"
		"  E.g. %s -d dpni.1 -o 0 -c 0 -i 192.168.10.10\n"
		"\n"
		"Mandatory OPTIONS:\n"
		"  -d, --device		Device name like dpni.1, dpbp.1\n"
		"			Note: Not required for object ID 20\n"
		"			      (will be ignored if given)\n"
		"\n"
		"  -o, --obj_id		all: All dump for device\n"
		"			0:   Dpni Stats\n"
		"			1:   Dpni Attributes\n"
		"			2:   Dpni Link State\n"
		"			3:   Dpni Max Frame Length\n"
		"			4:   Dpni MTU\n"
		"			5:   L3 chksum hardware offload (enable/disable)\n"
		"			6:   L4 chksum hardware offload (enable/disable)\n"
		"			7:   Dpni Primary Mac Addr\n"
		"			8:   Congestion Group Id for FQs\n"
		"			9:   Scheduling Priority for FQs\n"
		"			10:  Tail Drop Threashold for FQs\n"
		"			11:  FQ Context\n"
		"			12:  FQ State\n"
		"			13:  Qbman frame count\n"
		"			14:  Qbman byte count\n"
		"			15:  Qbman has free buffers or not\n"
		"			16:  Qbman buffer pool is depleted or not\n"
		"			17:  Number of free buffers in qbman\n"
		"			18:  DPseci Attributes\n"
		"			19:  DPseci counters\n"
		"			20:  Per SA stats (TODO)\n"
		"\n"
		"  -c, --command		0:   get\n"
		"			1:   reset\n"
		"			2:   set\n"
		"\n"
		"  -i, --dest_ip        Destination IP address of debug server"
		"			e.g. 192.168.10.10\n"
		"\n"
		"  -h, --help            Display help and exit.\n"
		"\n", NO_PATH(progname), NO_PATH(progname)
	      );
}

static void parse_args(int argc, char *argv[], parse_msg_t *p_msg)
{
	int opt, len = 0;
	int long_index;
	static struct option longopts[] = {
		{"device name", required_argument, NULL, 'd'},
		{"object identifier", required_argument, NULL, 'o'},
		{"command", required_argument, NULL, 'c'},
		{"dest_ip", required_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "d:o:c:i:h",
				  longopts, &long_index);

		if (opt == -1)
			break;  /* No more options */

		switch (opt) {
		case 'd':
			memcpy(p_msg->msg.buffer, optarg, strlen(optarg) + 1);
			break;
		case 'o':
			if (!(strcmp(optarg, "all")))
				p_msg->msg.obj_id = ALL_DUMP;
			else
				p_msg->msg.obj_id = (uint16_t)atoi(optarg);
			break;
		case 'c':
			p_msg->msg.cmd = (uint8_t)atoi(optarg);
			break;
		case 'i':
			p_msg->addr = inet_addr(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	/** Validating the arguments **/
	if (p_msg->msg.obj_id < SA_STATS_OBJ_ID) {
		if (!(p_msg->msg.buffer[0])) {
				printf("-d option is mandatory for obj_id = %d\n", p_msg->msg.obj_id);
				exit(EXIT_SUCCESS);
		}
		switch (p_msg->msg.obj_id) {
			case 1 ... (BPOOL_START_OBJ_ID - 1):
				len = strlen("dpni");
				if (strncmp(p_msg->msg.buffer, "dpni", len)) {
					printf("-d option should have a valid dpni for obj_id = %d\n", p_msg->msg.obj_id);
					exit(EXIT_SUCCESS);
				}
				break;
			case BPOOL_START_OBJ_ID ... (DPSECI_START_OBJ_ID - 1):
				len = strlen("dpbp");
				if (strncmp(p_msg->msg.buffer, "dpbp", len)) {
					printf("-d option should have a valid dpbp for obj_id = %d\n", p_msg->msg.obj_id);
					exit(EXIT_SUCCESS);
				}
				break;
			case DPSECI_START_OBJ_ID ... (SA_STATS_OBJ_ID - 1):
				len = strlen("dpseci");
				if (strncmp(p_msg->msg.buffer, "dpseci", len)) {
					printf("-d option should have a valid dpseci for obj_id = %d\n", p_msg->msg.obj_id);
					exit(EXIT_SUCCESS);
				}
		}
	} else if (p_msg->msg.obj_id > ALL_DUMP) {
		printf("Invalid obj_id = %d\n", p_msg->msg.obj_id);
		exit(EXIT_SUCCESS);
	}
	optind = 1;
}

int main(int argc, char *argv[])
{
	int client_socket;
	struct sockaddr_in server_addr;
	socklen_t addr_size;
	uint16_t port_no = DEFAULT_PLAT_DEBUG_PORT;
	char *port;
	uint32_t i, start_pos, end_pos;
	parse_msg_t *p_msg = calloc(1, sizeof(*p_msg));

	if (!p_msg) {
		printf("Failed to allocate memory\n");
		return -1;
	}

	p_msg->addr = htonl(INADDR_ANY);
	port = getenv("PLAT_DEBUG_PORT");

	if (port != NULL)
		port_no = atoi(port);

	parse_args(argc, argv, p_msg);

	client_socket = socket(AF_INET, SOCK_DGRAM, 0);
	memset((char *)&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port_no);
	server_addr.sin_addr.s_addr = p_msg->addr;
	addr_size = sizeof(server_addr);
	p_msg->msg.buffer_len = strlen(p_msg->msg.buffer);

	if (p_msg->msg.obj_id != ALL_DUMP)
		sendto(client_socket, &p_msg->msg, 1024, 0,
			(struct sockaddr *)&server_addr,
			addr_size);
	else {
		if (!(strncmp(p_msg->msg.buffer, "dpni", strlen("dpni")))) {
			start_pos = 0;
			end_pos = BPOOL_START_OBJ_ID;
		} else if (!(strncmp(p_msg->msg.buffer, "dpbp", strlen("dpbp")))) {
			start_pos = BPOOL_START_OBJ_ID;
			end_pos = DPSECI_START_OBJ_ID;
		} else if (!(strncmp(p_msg->msg.buffer, "dpseci", strlen("dpseci")))) {
			start_pos = DPSECI_START_OBJ_ID;
			end_pos = SA_STATS_OBJ_ID;
		} else {
			start_pos = SA_STATS_OBJ_ID;
			end_pos = ALL_DUMP;
		}
		for (i = start_pos; i < end_pos; i++) {
			p_msg->msg.obj_id = i;
			sendto(client_socket, &p_msg->msg, 1024, 0,
				(struct sockaddr *)&server_addr,
				addr_size);
		}
	}

	free(p_msg);
	return 0;
}
