/* Areion-256 / Areion-512 reduced rounds with AES-NI, and Lambda-set
 * sums of high order for P1 alone and for the SoEM22 core
 * T(u) = P1(u) ^ P2(u ^ delta).
 *
 *   ./integral kat                       check full rounds against kat.txt lines on stdin
 *   ./integral sum W R ORDER BLK EXTRA THREADS SEED [shift|pi]
 *       W = 256 | 512, R rounds, ORDER active bytes (diagonal of block
 *       BLK first, then EXTRA bytes of the next diagonal), prints the
 *       number of balanced output bytes for P1, P2 and T; the last
 *       argument selects the RC7 form of P2 (default shift, the library's), and
 *       AREION_RC7P1=pi switches P1 to the pi form of RC7. */
#include <immintrin.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "consts.h"

#define LANES 8

static __m128i rc1[15], rc2[15];

static inline void r256(__m128i *x0, __m128i *x1, int r, const __m128i *rc) {
	if ((r & 1) == 0) {
		__m128i t = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rc[r]), *x1);
		*x0 = _mm_aesenclast_si128(*x0, _mm_setzero_si128());
		*x1 = t;
	} else {
		__m128i t = _mm_aesenc_si128(_mm_aesenc_si128(*x1, rc[r]), *x0);
		*x1 = _mm_aesenclast_si128(*x1, _mm_setzero_si128());
		*x0 = t;
	}
}

static inline void r512(__m128i *x, int r, const __m128i *rc) {
	int o = r & 3;
	__m128i *a = &x[o], *b = &x[(o + 1) & 3], *c = &x[(o + 2) & 3], *d = &x[(o + 3) & 3];
	__m128i nb = _mm_aesenc_si128(*a, *b);
	__m128i nd = _mm_aesenc_si128(*c, *d);
	*a = _mm_aesenclast_si128(*a, _mm_setzero_si128());
	*c = _mm_aesenc_si128(_mm_aesenclast_si128(*c, rc[r]), _mm_setzero_si128());
	*b = nb;
	*d = nd;
}

static void perm(int w, unsigned char *s, int rounds, const __m128i *rc, int final_rot) {
	if (w == 256) {
		__m128i x0 = _mm_loadu_si128((void *)s), x1 = _mm_loadu_si128((void *)(s + 16));
		for (int r = 0; r < rounds; r++) r256(&x0, &x1, r, rc);
		_mm_storeu_si128((void *)s, x0);
		_mm_storeu_si128((void *)(s + 16), x1);
	} else {
		__m128i x[4];
		for (int i = 0; i < 4; i++) x[i] = _mm_loadu_si128((void *)(s + 16 * i));
		for (int r = 0; r < rounds; r++) r512(x, r, rc);
		if (final_rot) {
			__m128i t = x[0];
			x[0] = x[3]; x[3] = x[2]; x[2] = x[1]; x[1] = t;
		}
		for (int i = 0; i < 4; i++) _mm_storeu_si128((void *)(s + 16 * i), x[i]);
	}
}

static int hexval(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }
static void unhex(const char *h, unsigned char *o, int n) {
	for (int i = 0; i < n; i++) o[i] = hexval(h[2 * i]) << 4 | hexval(h[2 * i + 1]);
}

/* ---- Lambda-set sums ---- */
typedef struct {
	int w, rounds, order, nb;
	int pos[8];
	uint64_t lo, hi;
	unsigned char base[64], delta[64];
	unsigned char s1[64], s2[64];
} job_t;

static void *worker(void *arg) {
	job_t *j = arg;
	int nb = j->nb, nblk = nb / 16;
	__m128i acc1[4] = {0}, acc2[4] = {0};
	__m128i b1[4], b2[4];
	for (int k = 0; k < nblk; k++) {
		b1[k] = _mm_loadu_si128((void *)(j->base + 16 * k));
		b2[k] = _mm_xor_si128(b1[k], _mm_loadu_si128((void *)(j->delta + 16 * k)));
	}
	for (uint64_t v = j->lo; v < j->hi; v += LANES) {
		__m128i x[LANES][4], y[LANES][4];
		for (int l = 0; l < LANES; l++) {
			unsigned char buf[64];
			uint64_t val = v + l;
			for (int k = 0; k < nblk; k++) _mm_storeu_si128((void *)(buf + 16 * k), _mm_setzero_si128());
			for (int t = 0; t < j->order; t++) buf[j->pos[t]] = (unsigned char)(val >> (8 * t));
			for (int k = 0; k < nblk; k++) {
				__m128i m = _mm_loadu_si128((void *)(buf + 16 * k));
				x[l][k] = _mm_xor_si128(b1[k], m);
				y[l][k] = _mm_xor_si128(b2[k], m);
			}
		}
		/* active positions are zeroed in base, so base ^ m sets them to val */
		if (j->w == 256) {
			for (int r = 0; r < j->rounds; r++)
				for (int l = 0; l < LANES; l++) {
					r256(&x[l][0], &x[l][1], r, rc1);
					r256(&y[l][0], &y[l][1], r, rc2);
				}
		} else {
			for (int r = 0; r < j->rounds; r++)
				for (int l = 0; l < LANES; l++) {
					r512(x[l], r, rc1);
					r512(y[l], r, rc2);
				}
		}
		for (int l = 0; l < LANES; l++)
			for (int k = 0; k < nblk; k++) {
				acc1[k] = _mm_xor_si128(acc1[k], x[l][k]);
				acc2[k] = _mm_xor_si128(acc2[k], y[l][k]);
			}
	}
	for (int k = 0; k < nblk; k++) {
		_mm_storeu_si128((void *)(j->s1 + 16 * k), acc1[k]);
		_mm_storeu_si128((void *)(j->s2 + 16 * k), acc2[k]);
	}
	return NULL;
}

static uint64_t rng_state;
static uint64_t rnd(void) {
	rng_state += 0x9e3779b97f4a7c15ULL;
	uint64_t z = rng_state;
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

int main(int argc, char **argv) {
	for (int r = 0; r < 15; r++) {
		rc1[r] = _mm_loadu_si128((void *)RC1[r]);
		rc2[r] = _mm_loadu_si128((void *)RC2SH[r]);
	}
	if (argc >= 2 && strcmp(argv[1], "kat") == 0) {
		char w[8], hin[260], h1[260], h2[260];
		int ok = 1, n = 0;
		while (scanf("%7s %259s %259s %259s", w, hin, h1, h2) == 4) {
			int W = atoi(w), nb = W / 8;
			unsigned char in[64], o1[64], o2[64], s[64];
			unhex(hin, in, nb); unhex(h1, o1, nb); unhex(h2, o2, nb);
			memcpy(s, in, nb); perm(W, s, W == 256 ? 10 : 15, rc1, 1);
			ok &= memcmp(s, o1, nb) == 0;
			memcpy(s, in, nb); perm(W, s, W == 256 ? 10 : 15, rc2, 1);
			ok &= memcmp(s, o2, nb) == 0;
			n++;
		}
		printf("AES-NI permutations match the library on %d kat lines: %s\n", n, ok ? "yes" : "NO");
		return ok ? 0 : 1;
	}
	if (argc < 9) { fprintf(stderr, "usage\n"); return 2; }
	int pi = argc > 9 && strcmp(argv[9], "pi") == 0;
	if (pi)
		for (int r = 0; r < 15; r++) rc2[r] = _mm_loadu_si128((void *)RC2PI[r]);
	const char *p1form = getenv("AREION_RC7P1");
	int p1pi = p1form && strcmp(p1form, "pi") == 0;
	if (p1pi) rc1[7] = _mm_loadu_si128((void *)RC7P1PI); /* P1 word 7 in the pi form */
	job_t proto = {0};
	proto.w = atoi(argv[2]); proto.rounds = atoi(argv[3]); proto.order = atoi(argv[4]);
	int blk = atoi(argv[5]), extra = atoi(argv[6]), threads = atoi(argv[7]);
	rng_state = strtoull(argv[8], 0, 10);
	proto.nb = proto.w / 8;
	int diag_bytes = proto.order - extra;
	for (int k = 0; k < diag_bytes; k++) proto.pos[k] = 16 * blk + (5 * k) % 16;          /* diagonal 0 */
	for (int k = 0; k < extra; k++) proto.pos[diag_bytes + k] = 16 * blk + (4 + 5 * k) % 16; /* diagonal 1 */
	for (int i = 0; i < proto.nb; i++) { proto.base[i] = rnd(); proto.delta[i] = rnd(); }
	for (int t = 0; t < proto.order; t++) proto.base[proto.pos[t]] = 0;
	uint64_t total = 1ULL << (8 * proto.order);
	job_t *jobs = calloc(threads, sizeof(job_t));
	pthread_t *th = calloc(threads, sizeof(pthread_t));
	if (total % LANES) { fprintf(stderr, "set size must be a multiple of %d\n", LANES); return 2; }
	for (int t = 0; t < threads; t++) {
		jobs[t] = proto;
		uint64_t chunk = total / threads / LANES * LANES; /* LANES-aligned, no overlap */
		jobs[t].lo = chunk * t;
		jobs[t].hi = t == threads - 1 ? total : chunk * (t + 1);
		pthread_create(&th[t], NULL, worker, &jobs[t]);
	}
	unsigned char s1[64] = {0}, s2[64] = {0};
	for (int t = 0; t < threads; t++) {
		pthread_join(th[t], NULL);
		for (int i = 0; i < proto.nb; i++) { s1[i] ^= jobs[t].s1[i]; s2[i] ^= jobs[t].s2[i]; }
	}
	int z1 = 0, z2 = 0, zt = 0;
	for (int i = 0; i < proto.nb; i++) { z1 += s1[i] == 0; z2 += s2[i] == 0; zt += (s1[i] ^ s2[i]) == 0; }
	printf("Areion-%d r%d order %d (blk %d, %d extra)%s%s: balanced bytes P1 %d / %d, P2 %d / %d, P1(u)^P2(u^delta) %d / %d\n",
	       proto.w, proto.rounds, proto.order, blk, extra, pi ? " (P2 pi)" : "", p1pi ? " (P1 pi)" : "",
	       z1, proto.nb, z2, proto.nb, zt, proto.nb);
	return 0;
}
