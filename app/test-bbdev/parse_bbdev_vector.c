/* * SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2026 NXP
 *
 */

/*
 * parse_bbdev_vector.c
 *
 * DPDK bbdev test vector parser + expected size calculator.
 *
 * Supported vector descriptor formats:
 *   key=value
 *   key=\nvalue
 *   key = value
 *
 * Supported LDPC vector types (common naming in test vectors):
 *   SD: LDPC Decode TB-mode (code_block_mode=0 + tb_params ea/eb/c/r/cab)
 *   CD: LDPC Decode CB-mode (code_block_mode=1 + cb_params e)
 *   SE: LDPC Encode TB-mode (code_block_mode=0 + tb_params ea/eb/c/r/cab)
 *   CE: LDPC Encode CB-mode (code_block_mode=1 + cb_params e)
 *
 * The tool:
 *  - Counts provided bytes for each inputX/outputX (32-bit hex words -> bytes=words*4)
 *  - Parses descriptor fields (including multi-line values)
 *  - Computes expected sizes for LDPC encode/decode in CB/TB modes.
 *
 * Notes on expected size assumptions:
 *  - Decode input is treated as LLR stream (int8), so expected input bytes = number of LLRs.
 *    (Also prints int16 alternative = 2x.)
 *  - Encode input/output are treated as packed hard bits, so expected bytes = ceil(bits/8).
 *  - If output/input are stored as 32-bit words in the file, vectors may pad to 4-byte.
 *    The tool prints both byte and word-aligned requirements.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -std=c11 -o parse_bbdev_vector parse_bbdev_vector.c
 *
 * Usage:
 *   ./parse_bbdev_vector <vector_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

/* ---------- helpers ---------- */
static char *ltrim(char *s) { while (*s && isspace((unsigned char)*s)) s++; return s; }
static void rtrim_inplace(char *s) { size_t n=strlen(s); while (n>0 && isspace((unsigned char)s[n-1])) { s[n-1]='\0'; n--; } }
static void trim_inplace(char *s) { char *p=ltrim(s); if (p!=s) memmove(s,p,strlen(p)+1); rtrim_inplace(s); }
static int starts_with(const char *s, const char *pfx) { return strncmp(s,pfx,strlen(pfx))==0; }
static int is_ident_start(int c) { return isalpha(c) || c=='_'; }
static int is_ident_char(int c) { return isalnum(c) || c=='_'; }
static long ceil_div_long(long a, long b) { return (a + b - 1) / b; }

static int parse_long_auto(const char *s, long *out) {
    char *end=NULL;
    long v=strtol(s,&end,0);
    if (end==s) return 0;
    *out=v;
    return 1;
}

static int parse_hex_u32_token(const char *s, size_t n, size_t *consumed, uint32_t *out) {
    size_t i=0;
    while (i<n && isspace((unsigned char)s[i])) i++;
    if (i+2>=n) return 0;
    if (!(s[i]=='0' && (s[i+1]=='x' || s[i+1]=='X'))) return 0;
    i += 2;

    uint32_t v=0;
    int digits=0;
    while (i<n) {
        unsigned char c=(unsigned char)s[i];
        int d;
        if (c>='0' && c<='9') d=c-'0';
        else if (c>='a' && c<='f') d=10+(c-'a');
        else if (c>='A' && c<='F') d=10+(c-'A');
        else break;
        v=(v<<4) | (uint32_t)d;
        i++; digits++;
        if (digits>=8) break;
    }
    if (digits==0) return 0;
    *out=v;
    *consumed=i;
    return 1;
}

/* ---------- descriptor params ---------- */

typedef struct {
    /* Common fields used in vectors */
    long basegraph;            int have_basegraph;
    long z_c;                  int have_zc;
    long n_cb;                 int have_ncb;
    long q_m;                  int have_qm;
    long n_filler;             int have_nfiller;

    /* TB params */
    long ea;                   int have_ea;
    long eb;                   int have_eb;
    long c;                    int have_c;
    long r;                    int have_r;
    long cab;                  int have_cab;

    /* CB param */
    long e;                    int have_e;   /* Rate matching output sequence length in bits (or LLRs) */

    /* Decode specific */
    long iter_max;             int have_itermax;
    long expected_iter_count;  int have_expiter;

    /* Other fields (printed but not used for expected size currently) */
    long rv_index;             int have_rv;
    long en_scramble;          int have_enscr;
    long q;                    int have_q;
    long n_id;                 int have_nid;
    long n_rnti;               int have_nrnti;
    long code_block_mode;      int have_cbmode; /* 0 TB, 1 CB */

    char op_flags[512];        int have_opflags;
    char expected_status[128]; int have_expstatus;

    /* Derived from flags */
    int crc24b_drop;
    int crc24b_attach;
} params_t;

static void params_init(params_t *p) { memset(p,0,sizeof(*p)); }

static void update_flag_derivatives(params_t *p) {
    if (!p->have_opflags) return;
    if (strstr(p->op_flags, "RTE_BBDEV_LDPC_CRC_TYPE_24B_DROP")) p->crc24b_drop = 1;
    if (strstr(p->op_flags, "RTE_BBDEV_LDPC_CRC_24B_ATTACH")) p->crc24b_attach = 1;
}

static void assign_kv(params_t *p, const char *key_in, const char *val_in) {
    char key[128];
    char val[512];
    strncpy(key,key_in,sizeof(key)-1); key[sizeof(key)-1]=0;
    strncpy(val,val_in,sizeof(val)-1); val[sizeof(val)-1]=0;
    trim_inplace(key);
    trim_inplace(val);

    long num;

    /* numeric keys */
    if (strcmp(key,"basegraph")==0 && parse_long_auto(val,&num)) { p->basegraph=num; p->have_basegraph=1; return; }
    if (strcmp(key,"z_c")==0 && parse_long_auto(val,&num)) { p->z_c=num; p->have_zc=1; return; }
    if (strcmp(key,"n_cb")==0 && parse_long_auto(val,&num)) { p->n_cb=num; p->have_ncb=1; return; }
    if (strcmp(key,"q_m")==0 && parse_long_auto(val,&num)) { p->q_m=num; p->have_qm=1; return; }
    if (strcmp(key,"n_filler")==0 && parse_long_auto(val,&num)) { p->n_filler=num; p->have_nfiller=1; return; }

    if (strcmp(key,"ea")==0 && parse_long_auto(val,&num)) { p->ea=num; p->have_ea=1; return; }
    if (strcmp(key,"eb")==0 && parse_long_auto(val,&num)) { p->eb=num; p->have_eb=1; return; }
    if (strcmp(key,"c")==0 && parse_long_auto(val,&num)) { p->c=num; p->have_c=1; return; }
    if (strcmp(key,"r")==0 && parse_long_auto(val,&num)) { p->r=num; p->have_r=1; return; }
    if (strcmp(key,"cab")==0 && parse_long_auto(val,&num)) { p->cab=num; p->have_cab=1; return; }

    if (strcmp(key,"e")==0 && parse_long_auto(val,&num)) { p->e=num; p->have_e=1; return; }

    if (strcmp(key,"iter_max")==0 && parse_long_auto(val,&num)) { p->iter_max=num; p->have_itermax=1; return; }
    if (strcmp(key,"expected_iter_count")==0 && parse_long_auto(val,&num)) { p->expected_iter_count=num; p->have_expiter=1; return; }

    if (strcmp(key,"rv_index")==0 && parse_long_auto(val,&num)) { p->rv_index=num; p->have_rv=1; return; }
    if (strcmp(key,"en_scramble")==0 && parse_long_auto(val,&num)) { p->en_scramble=num; p->have_enscr=1; return; }
    if (strcmp(key,"q")==0 && parse_long_auto(val,&num)) { p->q=num; p->have_q=1; return; }
    if (strcmp(key,"n_id")==0 && parse_long_auto(val,&num)) { p->n_id=num; p->have_nid=1; return; }
    if (strcmp(key,"n_rnti")==0 && parse_long_auto(val,&num)) { p->n_rnti=num; p->have_nrnti=1; return; }
    if (strcmp(key,"code_block_mode")==0 && parse_long_auto(val,&num)) { p->code_block_mode=num; p->have_cbmode=1; return; }

    /* strings */
    if (strcmp(key,"op_flags")==0) {
        strncpy(p->op_flags,val,sizeof(p->op_flags)-1);
        p->op_flags[sizeof(p->op_flags)-1]=0;
        p->have_opflags=1;
        update_flag_derivatives(p);
        return;
    }
    if (strcmp(key,"expected_status")==0) {
        strncpy(p->expected_status,val,sizeof(p->expected_status)-1);
        p->expected_status[sizeof(p->expected_status)-1]=0;
        p->have_expstatus=1;
        return;
    }
}

static void print_params(const params_t *p) {
    printf("\n[params] Parsed fields:\n");
    if (p->have_basegraph) printf("  basegraph=%ld\n", p->basegraph);
    if (p->have_zc) printf("  z_c=%ld\n", p->z_c);
    if (p->have_ncb) printf("  n_cb=%ld\n", p->n_cb);
    if (p->have_qm) printf("  q_m=%ld\n", p->q_m);
    if (p->have_nfiller) printf("  n_filler=%ld\n", p->n_filler);

    if (p->have_ea) printf("  ea=%ld\n", p->ea);
    if (p->have_eb) printf("  eb=%ld\n", p->eb);
    if (p->have_c) printf("  c=%ld\n", p->c);
    if (p->have_r) printf("  r=%ld\n", p->r);
    if (p->have_cab) printf("  cab=%ld\n", p->cab);
    if (p->have_e) printf("  e=%ld\n", p->e);

    if (p->have_itermax) printf("  iter_max=%ld\n", p->iter_max);
    if (p->have_expiter) printf("  expected_iter_count=%ld\n", p->expected_iter_count);

    if (p->have_rv) printf("  rv_index=%ld\n", p->rv_index);
    if (p->have_enscr) printf("  en_scramble=%ld\n", p->en_scramble);
    if (p->have_q) printf("  q=%ld\n", p->q);
    if (p->have_nid) printf("  n_id=%ld\n", p->n_id);
    if (p->have_nrnti) printf("  n_rnti=%ld\n", p->n_rnti);
    if (p->have_cbmode) printf("  code_block_mode=%ld\n", p->code_block_mode);

    if (p->have_opflags) printf("  op_flags=%s\n", p->op_flags);
    if (p->crc24b_drop) printf("  (derived) crc24b_drop=yes\n");
    if (p->crc24b_attach) printf("  (derived) crc24b_attach=yes\n");
    if (p->have_expstatus) printf("  expected_status=%s\n", p->expected_status);
}

/* ---------- expected sizing for LDPC SD/SE/CD/CE ---------- */

typedef enum {
    OP_UNKNOWN=0,
    OP_LDPC_DEC=1,
    OP_LDPC_ENC=2
} op_kind_t;

typedef struct {
    op_kind_t kind;
    int tb_mode; /* 1 TB, 0 CB */
} op_type_t;

static op_type_t infer_op_type(const params_t *p) {
    op_type_t t; t.kind = OP_UNKNOWN; t.tb_mode = 0;

    /* Heuristic:
     * - If iter_max present -> decode
     * - Else if expected_iter_count present -> decode
     * - Else if op_flags has CRC_TYPE_* -> likely decode
     * - Else assume encode
     */
    if (p->have_itermax || p->have_expiter || (p->have_opflags && strstr(p->op_flags, "CRC_TYPE_")))
        t.kind = OP_LDPC_DEC;
    else
        t.kind = OP_LDPC_ENC;

    /* TB vs CB:
     * Prefer explicit code_block_mode if present (0 TB, 1 CB)
     * else infer: if ea/eb/c present -> TB, else CB.
     */
    if (p->have_cbmode)
        t.tb_mode = (p->code_block_mode == 0);
    else
        t.tb_mode = (p->have_ea && p->have_eb && p->have_c && p->have_r && p->have_cab);

    return t;
}

static int derive_KN(const params_t *p, long *K_bits, long *N_bits) {
    *K_bits = *N_bits = 0;
    if (!(p->have_basegraph && p->have_zc)) return 0;

    long K_cols = (p->basegraph == 1) ? 22 : (p->basegraph == 2 ? 10 : 0);
    long N_cols = (p->basegraph == 1) ? 66 : (p->basegraph == 2 ? 50 : 0);
    if (K_cols == 0 || N_cols == 0 || p->z_c <= 0) return 0;

    *K_bits = K_cols * p->z_c;
    *N_bits = N_cols * p->z_c;
    return 1;
}

static long expected_tb_E_total(const params_t *p) {
    if (!(p->have_ea && p->have_eb && p->have_c && p->have_r && p->have_cab)) return 0;
    long E=0;
    for (long k=0; k<p->c; k++) {
        long cb_index = p->r + k;
        E += (cb_index < p->cab) ? p->ea : p->eb;
    }
    return E;
}

static void print_expected_sizes(const params_t *p, size_t provided_in_bytes, size_t provided_out_bytes) {
    long K_bits=0, N_bits=0;
    if (!derive_KN(p, &K_bits, &N_bits)) {
        printf("\n[expected] Not enough params to derive K/N (need basegraph and z_c).\n");
        return;
    }

    op_type_t t = infer_op_type(p);

    printf("\n[expected] Derived from basegraph=%ld z_c=%ld: K=%ld bits, N=%ld bits\n",
           p->basegraph, p->z_c, K_bits, N_bits);

    if (p->have_ncb && p->n_cb > 0 && p->n_cb != N_bits) {
        printf("[expected] WARNING: n_cb in file=%ld but derived N=%ld; check basegraph/z_c/n_cb.\n", p->n_cb, N_bits);
    }

    /* Output hard bits per CB: (K - n_filler) and optional CRC drop */
    long Kp_bits = K_bits - (p->have_nfiller ? p->n_filler : 0); /* K' = K - fillers */
    if (Kp_bits < 0) Kp_bits = 0;

    /* For decode, if CRC drop enabled, output excludes CRC24B */
    long dec_out_bits_per_cb = Kp_bits - (p->crc24b_drop ? 24 : 0);
    if (dec_out_bits_per_cb < 0) dec_out_bits_per_cb = 0;

    /* For encode input, if CRC attach enabled, input excludes CRC bits */
    long enc_in_bits_per_cb = Kp_bits - (p->crc24b_attach ? 24 : 0);
    if (enc_in_bits_per_cb < 0) enc_in_bits_per_cb = 0;

    /* Expected sizes depend on op kind and CB/TB mode */
    long exp_in_bytes_int8 = 0;      /* for decode LLR int8 */
    long exp_in_bytes_int16 = 0;     /* for decode LLR int16 */
    long exp_out_bytes = 0;          /* for hard bits packed */
    const char *name = "UNKNOWN";

    if (t.kind == OP_LDPC_DEC) {
        name = t.tb_mode ? "LDPC Decode TB (SD)" : "LDPC Decode CB (CD)";

        if (t.tb_mode) {
            long E_total = expected_tb_E_total(p);
            exp_in_bytes_int8 = E_total;
            exp_in_bytes_int16 = 2 * E_total;
            /* Output is concatenation of c CB outputs */
            long out_bytes_per_cb = ceil_div_long(dec_out_bits_per_cb, 8);
            exp_out_bytes = out_bytes_per_cb * (p->have_c ? p->c : 0);
        } else {
            /* CB-mode: if cb param e exists, treat input as E LLRs; else fall back to N bits (VCB) */
            long E = p->have_e ? p->e : N_bits;
            exp_in_bytes_int8 = E;
            exp_in_bytes_int16 = 2 * E;
            exp_out_bytes = ceil_div_long(dec_out_bits_per_cb, 8);
        }

    } else if (t.kind == OP_LDPC_ENC) {
        name = t.tb_mode ? "LDPC Encode TB (SE)" : "LDPC Encode CB (CE)";

        if (t.tb_mode) {
            long E_total = expected_tb_E_total(p);
            /* Encode input: packed bits for each CB */
            long in_bytes_per_cb = ceil_div_long(enc_in_bits_per_cb, 8);
            long c = p->have_c ? p->c : 0;
            exp_in_bytes_int8 = in_bytes_per_cb * c; /* use this as packed-bits byte count */
            exp_in_bytes_int16 = 0;
            /* Encode output: packed rate-matched bits */
            exp_out_bytes = ceil_div_long(E_total, 8);
        } else {
            long E = p->have_e ? p->e : 0;
            exp_in_bytes_int8 = ceil_div_long(enc_in_bits_per_cb, 8);
            exp_in_bytes_int16 = 0;
            exp_out_bytes = (E > 0) ? ceil_div_long(E, 8) : 0;
        }
    }

    printf("[expected] Inferred op: %s\n", name);

    if (t.kind == OP_LDPC_DEC) {
        printf("[expected] Input (LLR) bytes: int8=%ld, int16=%ld\n", exp_in_bytes_int8, exp_in_bytes_int16);
    } else {
        printf("[expected] Input (packed bits) bytes: %ld\n", exp_in_bytes_int8);
    }

    printf("[expected] Output (packed bits) bytes: %ld\n", exp_out_bytes);

    /* Also print word-aligned sizes for typical vector formatting */
    if (exp_in_bytes_int8 > 0) {
        long words_need = (long)ceil_div_long(exp_in_bytes_int8, 4);
        printf("[expected] Input word-aligned: %ld words (=%ld bytes if padded to 4B)\n", words_need, words_need*4);
    }
    if (exp_out_bytes > 0) {
        long words_need = (long)ceil_div_long(exp_out_bytes, 4);
        printf("[expected] Output word-aligned: %ld words (=%ld bytes if padded to 4B)\n", words_need, words_need*4);
    }

    /* Compare with provided totals */
    if (provided_in_bytes) {
        long diff = (long)provided_in_bytes - (long)exp_in_bytes_int8;
        printf("\n[compare] Provided input bytes (sum inputX words*4): %zu\n", provided_in_bytes);
        if (t.kind == OP_LDPC_DEC)
            printf("[compare] Expected input bytes (int8 LLR): %ld\n", exp_in_bytes_int8);
        else
            printf("[compare] Expected input bytes (packed bits): %ld\n", exp_in_bytes_int8);
        printf("[compare] Difference (provided - expected): %ld bytes\n", diff);
    }
    if (provided_out_bytes) {
        long diff = (long)provided_out_bytes - (long)exp_out_bytes;
        printf("\n[compare] Provided output bytes (sum outputX words*4): %zu\n", provided_out_bytes);
        printf("[compare] Expected output bytes: %ld\n", exp_out_bytes);
        printf("[compare] Difference (provided - expected): %ld bytes\n", diff);
    }
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <vector_file>\n", argv[0]);
        return 2;
    }

    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 2; }

    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (flen < 0) { fprintf(stderr, "ftell failed\n"); fclose(f); return 2; }

    char *buf = (char*)malloc((size_t)flen + 1);
    if (!buf) { fprintf(stderr, "malloc failed\n"); fclose(f); return 2; }

    size_t rd = fread(buf, 1, (size_t)flen, f);
    fclose(f);
    buf[rd] = '\0';

    /* Keep pristine copy for blob parsing */
    char *blob = (char*)malloc(rd + 1);
    if (!blob) { fprintf(stderr, "malloc failed\n"); free(buf); return 2; }
    memcpy(blob, buf, rd + 1);

    /* ---- Parse descriptor by splitting lines in buf ---- */
    params_t P; params_init(&P);

    size_t max_lines = 1;
    for (size_t i=0; i<rd; i++) if (buf[i]=='\n') max_lines++;
    char **lines = (char**)calloc(max_lines, sizeof(char*));
    if (!lines) { fprintf(stderr, "calloc failed\n"); free(blob); free(buf); return 2; }

    size_t nlines = 0;
    lines[nlines++] = buf;
    for (size_t i=0; i<rd; i++) {
        if (buf[i]=='\n') {
            buf[i]='\0';
            if (i+1<rd) lines[nlines++] = &buf[i+1];
        }
    }

    for (size_t li=0; li<nlines; li++) {
        char tmp[1024];
        strncpy(tmp, lines[li], sizeof(tmp)-1);
        tmp[sizeof(tmp)-1]=0;
        trim_inplace(tmp);
        if (tmp[0]=='\0' || tmp[0]=='#') continue;

        char *eq = strchr(tmp, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = tmp;
        char *val = eq + 1;
        trim_inplace(key);
        trim_inplace(val);

        if (val[0] == '\0') {
            /* key=\nvalue format */
            size_t lj = li + 1;
            while (lj < nlines) {
                char t2[1024];
                strncpy(t2, lines[lj], sizeof(t2)-1);
                t2[sizeof(t2)-1]=0;
                trim_inplace(t2);
                if (t2[0]=='\0' || t2[0]=='#') { lj++; continue; }
                assign_kv(&P, key, t2);
                break;
            }
        } else {
            assign_kv(&P, key, val);
        }
    }

    /* ---- Parse blobs in blob (with newlines) ---- */
    size_t total_in_bytes = 0, total_out_bytes = 0;

    size_t i = 0;
    while (i < rd) {
        if (is_ident_start((unsigned char)blob[i])) {
            size_t j=i;
            while (j<rd && is_ident_char((unsigned char)blob[j])) j++;

            size_t id_len = j - i;
            char ident[64];
            if (id_len >= sizeof(ident)) id_len = sizeof(ident)-1;
            memcpy(ident, &blob[i], id_len);
            ident[id_len]=0;

            int is_in = starts_with(ident, "input");
            int is_out = starts_with(ident, "output");

            if (is_in || is_out) {
                size_t k=j;
                while (k<rd && isspace((unsigned char)blob[k])) k++;
                if (k<rd && blob[k]=='=') {
                    k++;
                    size_t pos=k;
                    size_t words=0;
                    while (pos<rd) {
                        while (pos<rd && (isspace((unsigned char)blob[pos]) || blob[pos]==',')) pos++;
                        if (pos>=rd) break;

                        uint32_t v; size_t consumed=0;
                        if (!parse_hex_u32_token(&blob[pos], rd-pos, &consumed, &v)) break;
                        (void)v;
                        words++;
                        pos += consumed;
                    }
                    size_t bytes = words * 4;
                    printf("[%s] %s: words=%zu, bytes=%zu (words*4)\n", is_in?"input":"output", ident, words, bytes);
                    if (is_in) total_in_bytes += bytes; else total_out_bytes += bytes;
                    i = pos;
                    continue;
                }
            }
            i = j;
        } else {
            i++;
        }
    }

    print_params(&P);
    print_expected_sizes(&P, total_in_bytes, total_out_bytes);

    free(lines);
    free(blob);
    free(buf);
    return 0;
}
