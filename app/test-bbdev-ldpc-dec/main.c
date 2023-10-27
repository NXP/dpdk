/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2023 NXP
 */

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_bbuf.h>
#include <rte_hexdump.h>
#include <rte_pmd_bbdev_la12xx.h>

#define VALUE_DELIMITER ","
#define ENTRY_DELIMITER "="
#define BBDEV_IPC_QUEUE 0
#define VSPA_IPC_QUEUE 1
#define PRACH_VSPA_IPC_QUEUE 2
#define MAX_QUEUES 3
#define GET_SOCKET(socket_id) (((socket_id) == SOCKET_ID_ANY) ? 0 : (socket_id))
#define FECA_BLOCKS 4

struct rte_mempool *mp_ldpc_dec_op, *mp_vspa_op, *mp_vspa_op_prach, *mp_bbuf_pool_in, *mp_bbuf_pool_out, *mp_prach_ctx, *mp_bbuf_pool_prach;
uint8_t dev_id;
int bbuf_burst = 1, vspa_burst = 1, vspa_burst_prach = 4, prach_num_ops = 1;

struct prach_bbuf_ctx {
	struct rte_bbuf *ant0;
	struct rte_bbuf *ant1;
	struct rte_bbuf *out_vspa_prach;
	struct rte_bbuf *vdata_prach;
};

struct ldpc_dec_vector {
	enum rte_bbdev_op_type op_type;
	int expected_status;
        uint64_t mask;
	uint16_t core_mask;
	int network_order;
	struct rte_bbdev_op_ldpc_dec ldpc_dec;
};

struct ldpc_dec_vector vector;
uint32_t idata_length = 0, odata_length = 0;
uint32_t *idata = NULL, *odata = NULL;
uint64_t prach_enq_count = 0, prach_deq_count = 0;

static struct test_params {
        unsigned int num_tests;
        unsigned int num_ops;
        unsigned int burst_sz;
        unsigned int prach_num_ops;
        unsigned int num_lcores;
        unsigned int num_seg;
        unsigned int buf_size;
        char test_vector_filename[PATH_MAX];
        unsigned int vector_count;
        unsigned int reset;
        bool init_device;
} test_params;

#define MAX_BURST 8U
#define MAX_OPS 16U
#define DEFAULT_BURST 4U
#define DEFAULT_OPS 64U
#define DEFAULT_ITER 6U
#define BBUF_MAX_SEGS 256
#define BBUF_POOL_ELEM_SIZE     (RTE_BBUF_HEADROOM + 1024)
#define DEFAULT_BBUF_SEGS 1

static int
parse_args(int argc, char **argv, struct test_params *tp)
{
        int opt, option_index;

        static struct option lgopts[] = {
                { "num-ops", 1, 0, 'n' },
                { "burst-size", 1, 0, 'b' },
                { "prach num-ops", 1, 0, 'p' },
                { "test-vector", 1, 0, 'v' },
                { "lcores", 1, 0, 'l' },
                { "buf-size", 1, 0, 's' },
                { "init-device", 0, 0, 'i'},
                { "help", 0, 0, 'h' },
                { NULL,  0, 0, 0 }
        };

        while ((opt = getopt_long(argc, argv, "hin:b:p:v:l:s:", lgopts,
                        &option_index)) != EOF)
                switch (opt) {
                case 'n':
			if (strlen(optarg) == 0) {
				printf("Num of operations is not provided");
				return -1;
			}
                        tp->num_ops = strtol(optarg, NULL, 10);
                        break;
                case 'b':
			if (strlen(optarg) == 0) {
				printf("burst size is not provided");
				return -1;
			}
                        tp->burst_sz = strtol(optarg, NULL, 10);
                        break;
                case 'p':
			if (strlen(optarg) == 0) {
				printf("prach num ops is not provided");
				return -1;
			}
                        tp->prach_num_ops = strtol(optarg, NULL, 10);
                        break;
                case 'v':
                        tp->vector_count = 1;
			if (strlen(optarg) == 0) {
				printf("filename is not provided");
				return -1;
			}
                        snprintf(tp->test_vector_filename,
                                        sizeof(tp->test_vector_filename),
                                        "%s", optarg);
                        break;
                case 'l':
			if (strlen(optarg) == 0) {
				printf("num lcore is not provided");
				return -1;
			}
                        tp->num_lcores = strtol(optarg, NULL, 10);
			if (tp->num_lcores <= RTE_MAX_LCORE) {
				printf("Num of lcores mustn't be greater than max cores");
				return -1;
			}
                        break;
                case 's':
			if (strlen(optarg) == 0) {
				printf("buf size is not provided");
				return -1;
			}
                        tp->buf_size = RTE_BBUF_HEADROOM + strtol(optarg, NULL, 10);
                        break;
                case 'h':
                        return 0;
                default:
			printf("ERROR: Unknown option: -%c\n", opt);
                        return -1;
                }

        if (tp->num_ops == 0) {
                printf(
                        "WARNING: Num of operations was not provided or was set 0. Set to default (%u)\n",
                        DEFAULT_OPS);
                tp->num_ops = DEFAULT_OPS;
        }
        if (tp->burst_sz == 0) {
                printf(
                        "WARNING: Burst size was not provided or was set 0. Set to default (%u)\n",
                        DEFAULT_BURST);
                tp->burst_sz = DEFAULT_BURST;
        }
        if (tp->num_lcores == 0) {
                printf(
                        "WARNING: Num of lcores was not provided or was set 0. Set to value from RTE config (%u)\n",
                        rte_lcore_count());
                tp->num_lcores = rte_lcore_count();
        }
        if (tp->buf_size == 0) {
                printf(
                        "WARNING: Buffer size was not provided or was set 0. Set to default (%u)\n",
                        BBUF_POOL_ELEM_SIZE);
                tp->buf_size = BBUF_POOL_ELEM_SIZE;
        }
        if (tp->num_seg == 0) {
                printf(
                        "WARNING: Number of segments was not provided or was set 0. Set to default (%u)\n",
                        DEFAULT_BBUF_SEGS);
                tp->num_seg = DEFAULT_BBUF_SEGS;
        }
	if (tp->burst_sz > tp->num_ops) {
		printf("Burst size (%u) mustn't be greater than num ops (%u)",
                        tp->burst_sz, tp->num_ops);
		return -1;
	}

        return 0;
}

static bool
starts_with(const char *str, const char *pre)
{
        return strncmp(pre, str, strlen(pre)) == 0;
}

/* trim leading and trailing spaces */
static void
trim_space(char *str)
{
        char *start, *end;

        for (start = str; *start; start++) {
                if (!isspace((unsigned char) start[0]))
                        break;
        }

        for (end = start + strlen(start); end > start + 1; end--) {
                if (!isspace((unsigned char) end[-1]))
                        break;
        }

        *end = 0;

        /* Shift from "start" to the beginning of the string */
        if (start > str)
                memmove(str, start, (end - start) + 1);
}

/* tokenization test values separated by a comma */
static int
parse_values(char *tokens, uint32_t **data, uint32_t *data_length,
             int network_order)
{
        uint32_t n_tokens = 0;
        uint32_t data_size = 32;

        uint32_t *values, *values_resized;
        char *tok, *error = NULL;

        tok = strtok(tokens, VALUE_DELIMITER);
        if (tok == NULL)
                return -1;

        values = (uint32_t *)
                        rte_zmalloc(NULL, sizeof(uint32_t) * data_size, 0);
        if (values == NULL)
                return -1;

        while (tok != NULL) {
                values_resized = NULL;

                if (n_tokens >= data_size) {
                        data_size *= 2;

                        values_resized = (uint32_t *) rte_realloc(values,
                                sizeof(uint32_t) * data_size, 0);
                        if (values_resized == NULL) {
                                rte_free(values);
                                return -1;
			}
                        values = values_resized;
                }

                values[n_tokens] = (uint32_t) strtoul(tok, &error, 0);

                if ((error == NULL) || (*error != '\0')) {
                        printf("Failed with convert '%s'\n", tok);
                        rte_free(values);
                        return -1;
                }

                *data_length = *data_length + (strlen(tok) - strlen("0x"))/2;
                if (network_order) {
                        /* TODO: Check if 3 byte length is also required */
                        if ((strlen(tok) - strlen("0x"))/2 == 4) {
                                values[n_tokens] = rte_cpu_to_be_32(values[n_tokens]);
                        } else if ((strlen(tok) - strlen("0x"))/2 == 3) {
                                values[n_tokens] <<= 8;
                                values[n_tokens] = rte_cpu_to_be_32(values[n_tokens]);
                        } else if ((strlen(tok) - strlen("0x"))/2 == 2) {
                                values[n_tokens] = rte_cpu_to_be_16(values[n_tokens]);
                        }
                }

                tok = strtok(NULL, VALUE_DELIMITER);
                if (tok == NULL)
                        break;

                n_tokens++;
        }
	values_resized = (uint32_t *) rte_realloc(values,
                sizeof(uint32_t) * (n_tokens + 1), 0);

        if (values_resized == NULL) {
                rte_free(values);
                return -1;
        }

        *data = values_resized;

        return 0;
}

/* checks the type of key and assigns data */
static int
parse_entry(char *entry, struct ldpc_dec_vector *vector)
{
        int ret = 0;
        char *token, *key_token, *err = NULL;

        if (entry == NULL) {
                printf("Expected entry value\n");
                return -1;
        }

        /* get key */
        token = strtok(entry, ENTRY_DELIMITER);
        key_token = token;
        /* get values for key */
        token = strtok(NULL, ENTRY_DELIMITER);

        if (key_token == NULL || token == NULL) {
                printf("Expected 'key = values' but was '%.40s'..\n", entry);
                return -1;
        }
        trim_space(key_token);

        struct rte_bbdev_op_ldpc_dec *ldpc_dec = &vector->ldpc_dec;

        if (starts_with(key_token, "input"))
		ret = parse_values(token, &idata, &idata_length,
                        vector->network_order);
        else if (starts_with(key_token, "output"))
		ret = parse_values(token, &odata, &odata_length,
                        vector->network_order);
        else if (!strcmp(key_token, "e")) {
                ldpc_dec->cb_params.e = (uint32_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "ea")) {
                ldpc_dec->tb_params.ea = (uint32_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "eb")) {
                ldpc_dec->tb_params.eb = (uint32_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "c")) {
                ldpc_dec->tb_params.c = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "cab")) {
                ldpc_dec->tb_params.cab = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "rv_index")) {
                ldpc_dec->rv_index = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "n_cb")) {
                ldpc_dec->n_cb = (uint16_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "r")) {
                ldpc_dec->tb_params.r = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "q_m")) {
                ldpc_dec->q_m = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "basegraph")) {
                ldpc_dec->basegraph = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "z_c")) {
                ldpc_dec->z_c = (uint16_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "n_filler")) {
                ldpc_dec->n_filler = (uint16_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "expected_iter_count")) {
                ldpc_dec->iter_count = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "iter_max")) {
                ldpc_dec->iter_max = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "code_block_mode")) {
                ldpc_dec->code_block_mode = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "op_flags")) {
		 if (!strcmp(token, "RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP"))
                        ldpc_dec->op_flags = RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP;
        } else if (!strcmp(key_token, "expected_status")) {
		if (!strcmp(token, "OK")) {
			vector->expected_status = true;
		}
        } else if (!strcmp(key_token, "network_order")) {
                vector->network_order = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "en_scramble")) {
                ldpc_dec->en_scramble = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "q")) {
                ldpc_dec->q = (uint8_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "n_id")) {
                ldpc_dec->n_id = (uint16_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        } else if (!strcmp(key_token, "n_rnti")) {
                ldpc_dec->n_rnti = (uint16_t) strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
        }

	return ret;
}

static int
bbdev_vector_process(void)
{
	int ret = 0;
        size_t len = 0;

        FILE *fp = NULL;
        char *line = NULL;
        char *entry = NULL;

	if (strcmp(test_params.test_vector_filename, "") != 0) {
        	fp = fopen(test_params.test_vector_filename, "r");
        	if (fp == NULL) {
                	printf("File %s does not exist\n", test_params.test_vector_filename);
      	        	return -1;
        	}
	} else {
        	fp = fopen("./input_vector.data", "r");
        	if (fp == NULL) {
                	printf("File ./input_vector.data does not exist\n");
      	        	return -1;
        	}
	}

        while (getline(&line, &len, fp) != -1) {
		/* ignore comments and new lines */
                if (line[0] == '#' || line[0] == '/' || line[0] == '\n'
                        || line[0] == '\r')
                        continue;

                trim_space(line);
		/* buffer for multiline */
                entry = realloc(entry, strlen(line) + 1);
                if (entry == NULL) {
                        printf("Fail to realloc %zu bytes\n", strlen(line) + 1);
                        ret = -ENOMEM;
                        goto exit;
                }

                strcpy(entry, line);

                /* check if entry ends with , or = */
                if (entry[strlen(entry) - 1] == ','
                        || entry[strlen(entry) - 1] == '=') {
                        while (getline(&line, &len, fp) != -1) {
                                trim_space(line);

                                /* extend entry about length of new line */
                                char *entry_extended = realloc(entry,
                                                strlen(line) +
                                                strlen(entry) + 1);
				if (entry_extended == NULL) {
                                        printf("Fail to allocate %zu bytes\n",
                                                        strlen(line) +
                                                        strlen(entry) + 1);
                                        ret = -ENOMEM;
                                        goto exit;
                                }

                                entry = entry_extended;
                                /* entry has been allocated accordingly */
                                strcpy(&entry[strlen(entry)], line);

                                if (entry[strlen(entry) - 1] != ',')
                                        break;
                        }
                }
                ret = parse_entry(entry, &vector);
                if (ret != 0) {
                        printf("An error occurred while parsing!\n");
                        goto exit;
                }
	}
exit:
        fclose(fp);
        free(line);
        free(entry);

        return ret;
}

static int prach_enq(int burst)
{
	struct rte_pmd_la12xx_op *vops_enq_prach[MAX_OPS];
	struct prach_bbuf_ctx *vops_ctx_prach[MAX_OPS];
	struct rte_bbuf *ant0_prach[MAX_OPS], *ant1_prach[MAX_OPS], *out_vspa_prach[MAX_OPS], *vdata_prach[MAX_OPS];
	int ret;

	/* PRACH allocation and submission */
	/*********************/
	/* allocate VSPA op for prach */
	ret = rte_mempool_get_bulk(mp_vspa_op_prach, (void **)vops_enq_prach, burst);
	if (ret) {
		printf("vspa op prach buffer allocate failed\n");
		return -1;
	}
	/* allocate control buffer for prach */
	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_prach, &vdata_prach[0], burst);
        if (unlikely(ret < 0)) {
		printf("bbuf allocate control fails\n");
                return ret;
	}
	/* Allocate prach out buffer */
	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_prach, &out_vspa_prach[0], burst);
        if (unlikely(ret < 0)) {
		printf("bbuf allocate out prach fails\n");
                return ret;
	}
	/* Allocate prach in buffer */
	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_prach, &ant0_prach[0], burst);
        if (unlikely(ret < 0)) {
		printf("bbuf allocate ANT0 prach fails\n");
                return ret;
	}
	/* Allocate prach in buffer */
	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_prach, &ant1_prach[0], burst);
        if (unlikely(ret < 0)) {
		printf("bbuf allocate ANT1 fails\n");
                return ret;
	}
	/* Allocate prach ctx buffer*/
	ret = rte_mempool_get_bulk(mp_prach_ctx, (void **)vops_ctx_prach, burst);
	if (ret) {
		printf("vspa ctx buffer allocate failed\n");
		return -1;
	}

	for (int i = 0; i < burst; i++) {
        	vops_enq_prach[i]->vspa_params.input.is_direct_mem = 0;
		rte_memcpy(rte_bbuf_mtod(vdata_prach[i], char *), (char *)idata, 100);
        	vops_enq_prach[i]->vspa_params.input.bdata = (void *)vdata_prach[i];
      		vops_enq_prach[i]->vspa_params.input.length = 100;
        	vops_enq_prach[i]->vspa_params.output.is_direct_mem = 0;
        	vops_enq_prach[i]->vspa_params.output.bdata = out_vspa_prach[i];
	
		/* copying only 64 data */
		rte_memcpy(rte_bbuf_mtod(ant0_prach[i], char *), (char *)idata, 516);
		ant0_prach[i]->data_len = 516;
		ant0_prach[i]->pkt_len = 516;
		rte_memcpy(rte_bbuf_mtod(ant1_prach[i], char *), (char *)idata, 64);
		ant1_prach[i]->data_len = 64;
		ant1_prach[i]->pkt_len = 64;
		/* Antena 0 */
		vops_enq_prach[i]->vspa_params.extra_data[0] = rte_pmd_get_la12xx_mapaddr(dev_id, rte_bbuf_mtod(ant0_prach[i], char *));
		vops_enq_prach[i]->vspa_params.extra_data[1] = ant0_prach[i]->data_len;
		/* Antenna 1 */
		vops_enq_prach[i]->vspa_params.extra_data[2] = rte_pmd_get_la12xx_mapaddr(dev_id, rte_bbuf_mtod(ant1_prach[i], char *));
		vops_enq_prach[i]->vspa_params.extra_data[3] = ant1_prach[i]->data_len;
		/* populate ctx */
		struct prach_bbuf_ctx *vctx = vops_ctx_prach[i];
		vctx->ant0 = ant0_prach[i];
		vctx->ant1 = ant1_prach[i];
		vctx->out_vspa_prach = out_vspa_prach[i];
		vctx->vdata_prach = vdata_prach[i];
		vops_enq_prach[i]->opaque_data = (void *)vctx;
	}
       	ret = rte_pmd_la12xx_enqueue_ops(dev_id,
                                         PRACH_VSPA_IPC_QUEUE, &vops_enq_prach[0], vspa_burst);
        if (ret == 0) {
               printf("failed to enqueue vspa prach op\n");
               return -1;
        }


	return ret;
	/****************************************************/
}

static int prach_deq(void)
{
        struct rte_pmd_la12xx_op *vops_deq_prach[MAX_OPS];
	int ret;

	ret = rte_pmd_la12xx_dequeue_ops(dev_id,
                                        PRACH_VSPA_IPC_QUEUE, &vops_deq_prach[0], 4);
	if(ret) {
		for (int i = 0; i < ret; i++) {
#if 0
			/* Dump each op */
			rte_hexdump(stdout, "PRACH output buffer", rte_bbuf_mtod((struct rte_mbuf *)vops_deq_prach[i]->vspa_params.output.bdata, char *) , vops_deq_prach[i]->vspa_params.output.length);
        		rte_hexdump(stdout, "PRACH Control data", (char *)&(vops_deq_prach[i]->vspa_params.extra_data[0]), 32);
#endif			
			if (memcmp(rte_bbuf_mtod((struct rte_mbuf *)vops_deq_prach[i]->vspa_params.output.bdata, char *), idata,
					       ((struct rte_mbuf *)vops_deq_prach[i]->vspa_params.output.bdata)->pkt_len) != 0) {
				printf("Mem compare failed for PRACH\n");
			} else {
				printf("Mem compare PASSED for PRACH\n");
			}
			/* free each op */
			struct prach_bbuf_ctx *vctx = (struct prach_bbuf_ctx *)vops_deq_prach[i]->opaque_data;
			

			rte_bbuf_free(vctx->ant0);
        		rte_bbuf_free(vctx->ant1);
        		rte_bbuf_free(vctx->out_vspa_prach);
        		rte_bbuf_free(vctx->vdata_prach);

        		rte_mempool_put_bulk(mp_vspa_op_prach, (void **)&vops_deq_prach[0], 1);
        		rte_mempool_put(mp_prach_ctx, vctx);
		}
	}
	return ret;
}

static int
ldpc_dec_bbdev_process(int burst)
{
	int ret;
	struct rte_bbdev_dec_op *ops_enq[MAX_OPS];
	struct rte_bbdev_dec_op *ops_deq[MAX_OPS];
	int ret_vspa = 0;
	struct rte_pmd_la12xx_op *vops_enq[MAX_OPS];
        struct rte_pmd_la12xx_op *vops_deq[MAX_OPS];
	struct rte_bbuf *in[MAX_OPS], *out[MAX_OPS], *out_vspa[MAX_OPS], *vdata[MAX_OPS];

	/* allocate e200 ldpc dec ops */
	ret = rte_bbdev_dec_op_alloc_bulk(mp_ldpc_dec_op, ops_enq, burst);
	if (ret) {
		printf("op buffer allocate failed\n");
		return -1;
	}
	/* allocate VSPA op , only 1 op per burst */
	ret = rte_mempool_get_bulk(mp_vspa_op, (void **)vops_enq, vspa_burst);
	if (ret) {
		printf("vspa op buffer allocate failed\n");
		return -1;
	}
	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_in, &vdata[0], vspa_burst);
        if (unlikely(ret < 0))
                return ret;

	/* Allocating only 2 input buffers 1 for antena0 and 2nd for antena1,
	 * Will divide the data among these 2 buffers */ 
	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_in, &in[0], vspa_burst * 2);
	if (ret) {
		printf("in bbuf alloc failed\n");
		return -1;
	}

	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_out, &out[0], burst);
	if (ret) {
		printf("out bbuf alloc failed\n");
		return -1;
	}

	/*vspa control addr  only 1 op per burst*/
	ret = rte_bbuf_alloc_bulk(mp_bbuf_pool_out, &out_vspa[0], vspa_burst);
	if (ret) {
		printf("out vspa dummy bbuf alloc failed\n");
		return -1;
	}
	/*filling op */
	struct rte_bbdev_op_ldpc_dec *ldpc_dec = &vector.ldpc_dec;

        for (int i = 0; i < burst; ++i) {
                if (ldpc_dec->code_block_mode == 0) {
                        ops_enq[i]->ldpc_dec.tb_params.ea =
                                        ldpc_dec->tb_params.ea;
                        ops_enq[i]->ldpc_dec.tb_params.eb =
                                        ldpc_dec->tb_params.eb;
                        ops_enq[i]->ldpc_dec.tb_params.c =
                                        ldpc_dec->tb_params.c;
                        ops_enq[i]->ldpc_dec.tb_params.cab =
                                        ldpc_dec->tb_params.cab;
                        ops_enq[i]->ldpc_dec.tb_params.r =
                                        ldpc_dec->tb_params.r;
                } else {
                        ops_enq[i]->ldpc_dec.cb_params.e = ldpc_dec->cb_params.e;
                }

                ops_enq[i]->ldpc_dec.basegraph = ldpc_dec->basegraph;
                ops_enq[i]->ldpc_dec.z_c = ldpc_dec->z_c;
                ops_enq[i]->ldpc_dec.q_m = ldpc_dec->q_m;
                ops_enq[i]->ldpc_dec.n_filler = ldpc_dec->n_filler;
                ops_enq[i]->ldpc_dec.n_cb = ldpc_dec->n_cb;
                ops_enq[i]->ldpc_dec.iter_max = ldpc_dec->iter_max;
                ops_enq[i]->ldpc_dec.rv_index = ldpc_dec->rv_index;
                ops_enq[i]->ldpc_dec.op_flags = ldpc_dec->op_flags;
                ops_enq[i]->ldpc_dec.en_scramble = ldpc_dec->en_scramble;
                ops_enq[i]->ldpc_dec.q = ldpc_dec->q;
                ops_enq[i]->ldpc_dec.n_id = ldpc_dec->n_id;
                ops_enq[i]->ldpc_dec.n_rnti = ldpc_dec->n_rnti;
                ops_enq[i]->ldpc_dec.code_block_mode = ldpc_dec->code_block_mode;

                ops_enq[i]->ldpc_dec.hard_output.is_direct_mem = 0;
                ops_enq[i]->ldpc_dec.hard_output.bdata = out[i];
		ops_enq[i]->feca_id = i;
	}
	/* filling only 1 vspa ops*/
        vops_enq[0]->vspa_params.input.is_direct_mem = 0;
	/* Filling only 4 bytes i.e number of users (control data)*/
	*((int *)rte_bbuf_mtod(vdata[0],int *)) = burst;
        vops_enq[0]->vspa_params.input.bdata = (void *)vdata[0];
        vops_enq[0]->vspa_params.input.length = 4;
        /* filling empty out addr for output data from VSPA, if any */
        vops_enq[0]->vspa_params.output.is_direct_mem = 0;
        vops_enq[0]->vspa_params.output.bdata = out_vspa[0];
	
	/* Dividing and filling the data in 2 input buffers */
	unsigned int offset = idata_length / 2;
	rte_memcpy(rte_bbuf_mtod(in[0], char *), (char *)idata, offset);
	in[0]->data_len = offset;
	in[0]->pkt_len = offset;
	rte_memcpy(rte_bbuf_mtod(in[1], char *), (char *)idata + offset, idata_length - offset);
	in[1]->data_len = idata_length - offset;
	in[1]->pkt_len = idata_length - offset;
	/* Antena 0 */
	vops_enq[0]->vspa_params.extra_data[0] = rte_pmd_get_la12xx_mapaddr(dev_id, rte_bbuf_mtod(in[0], char *));
	vops_enq[0]->vspa_params.extra_data[1] = in[0]->data_len;
	/* Antenna 1 */
	vops_enq[0]->vspa_params.extra_data[2] = rte_pmd_get_la12xx_mapaddr(dev_id, rte_bbuf_mtod(in[1], char *));
	vops_enq[0]->vspa_params.extra_data[3] = in[1]->data_len;
#if 0
	   /* filling feca_id/userid/opid  for VSPA data*/
//	vops_enq[0]->vspa_params.extra_data[0] = i;
#endif

	ret = rte_bbdev_enqueue_ldpc_dec_ops(dev_id,
                                        BBDEV_IPC_QUEUE, &ops_enq[0], burst);
	if (ret == 0) {
		printf("failed to enqueue\n");
		return -1;
	}

       ret = rte_pmd_la12xx_enqueue_ops(dev_id,
                                        VSPA_IPC_QUEUE, &vops_enq[0], vspa_burst);
       if (ret == 0) {
               printf("failed to enqueue vspa op\n");
               return -1;
       }

        ret = 0;
	ret_vspa = 0;
        ret_vspa = rte_pmd_la12xx_dequeue_ops(dev_id,
                                        VSPA_IPC_QUEUE, &vops_deq[0], vspa_burst);

	ret = rte_bbdev_dequeue_ldpc_dec_ops(dev_id,
				BBDEV_IPC_QUEUE, &ops_deq[0], burst);
       while (ret != burst || ret_vspa != vspa_burst) {
               if (ret != burst) {
		ret += rte_bbdev_dequeue_ldpc_dec_ops(dev_id,
                                        BBDEV_IPC_QUEUE, &ops_deq[ret], burst);
	       }
               if (ret_vspa != vspa_burst) {
                       ret_vspa += rte_pmd_la12xx_dequeue_ops(dev_id,
                                        VSPA_IPC_QUEUE, &vops_deq[ret_vspa], vspa_burst);
               }
	}
	printf("Dequeue ldpc dec ret = %d and vspa ret = %d\n\r", ret, ret_vspa);
	
	for (int i =0; i< burst; i++) {
		struct rte_bbuf *b = ops_deq[i]->ldpc_dec.hard_output.bdata;

		b->data_len = b->pkt_len;
		if (memcmp(rte_bbuf_mtod(b, char *), odata,  b->pkt_len) != 0) {
			printf("Mem compare failed for op = %d\n", i);
		} else {
			printf("Mem compare PASSED for op = %d\n", i);
		}
#if 0
		printf("Decoded data of index = %d\n", i);
		rte_pktmbuf_dump(stdout, b,  b->pkt_len);
#endif
	}
#if 0
        rte_hexdump(stdout, "output buffer", rte_bbuf_mtod((struct rte_mbuf *)vops_deq[0]->vspa_params.output.bdata, char *) , vops_enq[0]->vspa_params.output.length);
	rte_hexdump(stdout, "RSSI/TA output", (char *)&vops_enq[0]->vspa_params.extra_data[0], 4);

#endif
	/* free buffers */
	rte_bbuf_free_bulk(&out_vspa[0], vspa_burst);
	rte_bbuf_free_bulk(&in[0], vspa_burst * 2);
	rte_bbuf_free_bulk(&out[0], burst);
	rte_bbuf_free_bulk(&vdata[0], vspa_burst);

	rte_mempool_put_bulk(mp_vspa_op, (void **)vops_enq, vspa_burst);
	rte_bbdev_dec_op_free_bulk(ops_enq, burst);
	printf("done ret = %d\n", ret);

	return 0;
}

static int
bbdev_process(__rte_unused void *dummy)
{
	int nops, ret;

	nops = test_params.num_ops;

	if (nops != 0) {
		while (nops > bbuf_burst) {
			ldpc_dec_bbdev_process(bbuf_burst);
			nops -= bbuf_burst;
		}
		if (nops) {
			bbuf_burst = nops;
			ldpc_dec_bbdev_process(bbuf_burst);
		}
	} else {
		ldpc_dec_bbdev_process(bbuf_burst);
	}

	printf("PRACH ops = %d\n", prach_num_ops);
	while (prach_num_ops) {
		/* sending one by one, can be update to multiple */
		ret = prach_enq(1);
		if (ret < 0) {
			printf("PRACH Enqueue Failed");
			return -1;
		}
		prach_enq_count += ret;
		prach_num_ops -= ret;
		do {
			ret = prach_deq();
		} while (!ret);
		prach_deq_count += ret;
	}
	printf("PRACH enq count = %lu and deq count = %lu\n", prach_enq_count, prach_deq_count);

	return 1;
}

static void
prach_ctx_init(__rte_unused struct rte_mempool *mempool,
                __rte_unused void *arg, void *element,
                __rte_unused unsigned int n)
{
	struct prach_bbuf_ctx *ctx = element;

        memset(ctx, 0, sizeof(struct prach_bbuf_ctx));
}

int
main(int argc, char **argv)
{
        int ret;
	struct rte_bbdev_info info;
	unsigned int nb_queues;
	int socket_id;

        /* Init EAL */
        ret = rte_eal_init(argc, argv);
        if (ret < 0) {
		printf("eal init failed\n");
		return 1;
	}
        argc -= ret;
        argv += ret;

	memset(&test_params, 0, sizeof(struct ldpc_dec_vector));
        /* Parse application arguments (after the EAL ones) */
        ret = parse_args(argc, argv, &test_params);
        if (ret < 0) {
		printf("Parse error\n");
                return 1;
        }

	if (test_params.burst_sz != 0)
		bbuf_burst = test_params.burst_sz;

	if (test_params.prach_num_ops != 0)
		prach_num_ops = test_params.prach_num_ops;

	if (bbuf_burst > FECA_BLOCKS) {
		printf("Burst cannot be more than %d\n", FECA_BLOCKS);
		return -1;
	}
	ret = bbdev_vector_process();
	if (ret) {
		printf("vector process error\n");
		return -1;
	}
	RTE_BBDEV_FOREACH(dev_id) {
		struct rte_bbdev_queue_conf qconf;

                rte_bbdev_info_get(dev_id, &info);
		/* check capability and continue for non-matched device */
		nb_queues = MAX_QUEUES; /* LDPC_DEC and 2 VSPA_IPC */
		/* setup device */
		ret = rte_bbdev_setup_queues(dev_id, nb_queues, info.socket_id);
		if (ret < 0) {
		        printf("rte_bbdev_setup_queues(%u, %u, %d) ret %i\n",
                                dev_id, nb_queues, info.socket_id, ret);
			return -1;
		}

		/* setup device queues */
	        qconf.socket = info.socket_id;
		qconf.queue_size = info.drv.default_queue_conf.queue_size;
		qconf.priority = 0;
		qconf.deferred_start = 0;
		qconf.raw_queue_conf.conf_enable = 1;
		qconf.raw_queue_conf.modem_core_id = 0;

		qconf.op_type = RTE_BBDEV_OP_LDPC_DEC;
		ret = rte_bbdev_queue_configure(dev_id, BBDEV_IPC_QUEUE, &qconf);
                if (ret != 0) {
                        printf("Allocated all queues (id=%u) at prio%u on dev%u\n",
                                        BBDEV_IPC_QUEUE, qconf.priority, dev_id);
			return -1;
		}
		/* VSPA queue for PUSCH */
		qconf.op_type = RTE_BBDEV_OP_LA12XX_VSPA;
		/* Maximum 8 VSPA cores */
		qconf.raw_queue_conf.modem_core_id = 0;
		ret = rte_bbdev_queue_configure(dev_id, VSPA_IPC_QUEUE, &qconf);
                if (ret != 0) {
                        printf("Allocated all queues (id=%u) at prio%u on dev%u\n",
                                        VSPA_IPC_QUEUE, qconf.priority, dev_id);
			return -1;
		}
		/* VSPA queue for PRACH */
		qconf.op_type = RTE_BBDEV_OP_LA12XX_VSPA;
		/* Maximum 8 VSPA cores */
		qconf.raw_queue_conf.modem_core_id = 1;
		ret = rte_bbdev_queue_configure(dev_id, PRACH_VSPA_IPC_QUEUE, &qconf);
                if (ret != 0) {
                        printf("Allocated all queues (id=%u) at prio%u on dev%u\n",
                                        PRACH_VSPA_IPC_QUEUE, qconf.priority, dev_id);
			return -1;
		}

		/* assigning la12xx core to BBDEV IPC queue */
		uint16_t queue_ids[MAX_QUEUES];
	        uint16_t core_ids[MAX_QUEUES];

		queue_ids[0] = BBDEV_IPC_QUEUE;
		core_ids[0] = 2;
		ret = rte_pmd_la12xx_queue_core_config(dev_id, queue_ids, core_ids, 1);
		if (ret) {
			printf("Failed to assign e200 core\n");
			return -1;
		}
		ret = rte_bbdev_start(dev_id);
		if (ret) {
			printf("BBDEV start failed\n");
			return -1;
		}
		break;
	}
	socket_id = GET_SOCKET(info.socket_id);

	int op_type = RTE_BBDEV_OP_LA12XX_VSPA;
	/* VSPA op pool for PUSCH*/
	mp_vspa_op = rte_mempool_create("vspa_op_pool", 64,
                                sizeof(struct rte_pmd_la12xx_op),
                                MAX_OPS,
                                sizeof(struct rte_bbdev_op_pool_private),
                                NULL, NULL, rte_pmd_la12xx_op_init, &op_type,
                                socket_id, 0);
	if (mp_vspa_op == NULL) {
		printf("VSPA pool op creation failed\n");
		return -1;
	}
	/***********************************************/
	/* VSPA op pool for PRACH*/
	mp_vspa_op_prach = rte_mempool_create("vspa_op_pool_prach", 64,
                                sizeof(struct rte_pmd_la12xx_op),
                                MAX_OPS,
                                sizeof(struct rte_bbdev_op_pool_private),
                                NULL, NULL, rte_pmd_la12xx_op_init, &op_type,
                                socket_id, 0);
	if (mp_vspa_op_prach == NULL) {
		printf("VSPA pool op pPRACH creation failed\n");
		return -1;
	}
	/* PRACH context pool */
	mp_prach_ctx = rte_mempool_create("vspa_op_pool_prach_ctx", 64,
                                sizeof(struct prach_bbuf_ctx),
                                MAX_OPS, 64,
                                NULL, NULL, prach_ctx_init, NULL,
                                socket_id, 0);
	if (mp_prach_ctx == NULL) {
		printf("VSPA ctx pool op pPRACH creation failed\n");
		return -1;
	}
	/***********************************************/
	op_type = RTE_BBDEV_OP_LDPC_DEC;
	/* e200 op pool */
	mp_ldpc_dec_op = rte_bbdev_op_pool_create("ldpc_dec_op_pool", op_type,
                                MAX_OPS, 8, socket_id);
	if (mp_ldpc_dec_op == NULL) {
		printf("LDPC DEC pool op creation failed\n");
		return -1;
	}

	int bbuf_size;
	if (test_params.buf_size != 0)
		bbuf_size = test_params.buf_size;
	else
		bbuf_size = 8192;

	/* in data pool  to be */
        mp_bbuf_pool_in = rte_bbuf_pool_create("bbuf_pool_in", MAX_OPS * 3, 0, 0,
                        bbuf_size + RTE_BBUF_HEADROOM, socket_id);

	if (mp_bbuf_pool_in == NULL) {
		printf("mp_bbuf_pool_in is failed to create\n");
		return -1;
	}
        mp_bbuf_pool_out = rte_bbuf_pool_create("bbuf_pool_out", MAX_OPS * 2, 0, 0,
                        bbuf_size + RTE_BBUF_HEADROOM, socket_id);

	if (mp_bbuf_pool_out == NULL) {
		printf("mp_bbuf_pool_out is failed to create\n");
		return -1;
	}

	/* VSPA PRACH pool */
        mp_bbuf_pool_prach = rte_bbuf_pool_create("bbuf_pool_prach", MAX_OPS, 0, 0,
                        bbuf_size + RTE_BBUF_HEADROOM, socket_id);

	if (mp_bbuf_pool_prach == NULL) {
		printf("mp_bbuf_pool_prach is failed to create\n");
		return -1;
	}

	unsigned lcore_id;
	/* data path */
	rte_eal_mp_remote_launch(bbdev_process, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                if (rte_eal_wait_lcore(lcore_id) < 0) {
                        return -1;
                }
        }
	return 0;
}
