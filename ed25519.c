#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "src/ed25519.h"
#include "src/sha512.h"

#include "src/ge.h"
#include "src/sc.h"

void printhex(const unsigned char * array, int bytes);
void hex_decode(unsigned char * buffer, size_t buflen, char * hex);
void Usage(void);
void library_test(void);
void creating_keys(int flg_r, int flg_k, int flg_K, char * filename);
void fetch_secret_key(unsigned char *public_key, unsigned char *private_key, char *hex_secret);
void hash_file(char * filename, unsigned char * hash_buf);
void process_file(int flg_h, char *hex_secret, char *hex_pub, char *hex_signature, char *filename);
#ifdef INCLUDE_KEYX
void do_add_scalar(char *hex_secret, char *hex_pub, char *hex_newkey_add);
void do_key_exchange(char *hex_secret, char *hex_pub);
#endif

char * program = "";

int main(int argc, char ** argv) {

    int ar, opton=1;
    char *p;
    int flg_H = 0, flg_t = 0, flg_r = 0, flg_h = 0, flg_s = 0, flg_p = 0,
	flg_v = 0, flg_k = 0, flg_K = 0;
    char * hex_secret = 0;
    char * hex_pub = 0;
    char * hex_signature = 0;
    char * hash_string = 0;
    char * filename = 0;
#ifdef INCLUDE_KEYX
    int flg_n = 0, flg_x = 0;
    char * hex_newkey_add = 0;
#endif

    program = argv[0];

    /* Traditional option processing. */
    for(ar = 1; ar < argc; ar++)
	if(opton && argv[ar][0] == '-' && argv[ar][1] != 0)
	    for(p = argv[ar]+1; *p; p++)
		switch(*p)
		{
		char ch, * ap;
		case '-': opton = 0; break;
		case 'r': flg_r = 1; break;
		case 'h': flg_h = 1; break;
		case 'k': flg_k = 1; break;
		case 'K': flg_K = 1; break;
#ifdef INCLUDE_KEYX
		case 'x': flg_x = 1; break;
#endif

		default:
		    ch = *p;
#ifdef TAIL_ALWAYS_ARG
		    if (p[1]) { ap = p+1; p=" "; }
#else
		    if (p==argv[ar]+1 && p[1] &&
			isascii(p[1]) && isxdigit(p[1]))
		    {
			ap = p+1; p=" ";
		    }
#endif
		    else {
			if (ar+1>=argc) Usage();
			ap = argv[++ar];
		    }
		    switch(ch) {
			case 'H': hash_string = ap; flg_H = 1; break;
			case 's': hex_secret = ap; flg_s = 1; break;
			case 'p': hex_pub = ap; flg_p = 1; break;
			case 'v': hex_signature = ap; flg_v = 1; break;
#ifdef INCLUDE_KEYX
			case 'n': hex_newkey_add = ap; flg_n = 1; break;
#endif
			default:  Usage();
		    }
		    break;
		}
	else if (!filename)
	    filename = argv[ar];
	else
	    Usage();

    if (flg_t + (flg_r|flg_k|flg_K) + flg_H + (flg_s|flg_v|flg_p|flg_h) != 1)
	Usage();

#ifdef INCLUDE_KEYX
    if (flg_n && (flg_x|flg_t|flg_r|flg_k|flg_K|flg_H|flg_h|flg_v) != 0)
	Usage();

    if (flg_x && (flg_n|flg_t|flg_r|flg_k|flg_K|flg_H|flg_h|flg_v) != 0)
	Usage();

    if (!flg_n && !flg_x && (flg_s|flg_v|flg_p) != 0) {
	if (flg_p + flg_s != 1) Usage();
	if (flg_p && !flg_v) Usage();
    }
#endif

    /* Creating keys */
    if ((flg_r|flg_k|flg_K) == 1)
	creating_keys(flg_r,flg_k,flg_K,filename);

    /* Hash a string */
    if (flg_H) {
	unsigned char hash_out[64];
	sha512((unsigned char *) hash_string, strlen(hash_string), hash_out);
	printhex(hash_out, sizeof(hash_out));
    }

    if (flg_h && !(flg_s|flg_v|flg_p) )
	hash_file(filename, 0);

#ifndef INCLUDE_KEYX
    if ( (flg_s|flg_v|flg_p) != 0 )
	process_file(flg_h, hex_secret, hex_pub, hex_signature, filename);
#endif

#ifdef INCLUDE_KEYX
    if ( (flg_s|flg_v|flg_p) && !flg_n && !flg_x)
	process_file(flg_h, hex_secret, hex_pub, hex_signature, filename);

    if (flg_n)
	do_add_scalar(hex_secret, hex_pub, hex_newkey_add);

    if (flg_x)
	do_key_exchange(hex_secret, hex_pub);
#endif

    return 0;
}

void printhex(const unsigned char * array, int bytes)
{
    int i;
    for(i=0; i<bytes; i++)
	printf("%02x", array[i]);
    printf("\n");
}

void hex_decode(unsigned char * buffer, size_t buflen, char * hex)
{
    int failed = 1;
    size_t i;
    if (strlen(hex) == buflen*2) {
	failed = 0;
	for(i=0; i<buflen; i++) {
	    char hex2[4], *ep;
	    int v;
	    hex2[0] = hex[i*2];
	    hex2[1] = hex[i*2+1];
	    hex2[2] = 0;
	    v = strtol(hex2, &ep, 16);
	    if (v < 0 || ep != hex2+2) {failed = 1; break; }
	    buffer[i] = v;
	}
    }

    if (failed) {
	unsigned char hash_out[64];
	fprintf(stderr, "Warning: Hashing incorrect hex string '%s'\n", hex);
	sha512((unsigned char *)hex, strlen(hex), hash_out);
	if (buflen > sizeof(hash_out)) memset(buffer, 0, buflen);
	memcpy(buffer, hash_out, buflen);
    }
}

/* Creating keys */
void
creating_keys(int flg_r, int flg_k, int flg_K, char * filename)
{
    unsigned char public_key[32], private_key[64], seed[32];

    if (flg_r && filename) Usage();
    if (!flg_r && !filename) Usage();

    if (flg_r) {
	ed25519_create_seed(seed);
	if (flg_k || flg_K) printf("SeedKey:   ");
	printhex(seed, sizeof(seed));
    } else
	memset(seed, 0, sizeof(seed));

    if ((flg_k || flg_K) && filename)
	hex_decode(seed, sizeof(seed), filename);

    if (flg_k || flg_K)
	ed25519_create_keypair(public_key, private_key, seed);

    if (flg_k) {
	if (flg_r || flg_K) printf("Public:    ");
	printhex(public_key, sizeof(public_key));
    }

    if (flg_K) {
	if (flg_r || flg_k) printf("Private:   ");
	printhex(private_key, sizeof(private_key));
    }
}

void
fetch_secret_key(unsigned char *public_key, unsigned char *private_key, char *hex_secret)
{
    unsigned char seed[32];
    if (strlen(hex_secret) == sizeof(seed)*2)
    {
	hex_decode(seed, sizeof(seed), hex_secret);
	ed25519_create_keypair(public_key, private_key, seed);
    }
    else
    {
	ge_p3 A;

	hex_decode(private_key, 64, hex_secret);

	/* Make sure this is a private key. */
	private_key[0] &= 248;
	private_key[31] &= 63;
	private_key[31] |= 64;

	/* Generate the public key from a private key ... */
	ge_scalarmult_base(&A, private_key);
	ge_p3_tobytes(public_key, &A);
    }
}

void hash_file(char * filename, unsigned char * hash_out)
{
    FILE * f;
    sha512_context ctx;
    int ret = 0, cc;
    unsigned char buffer[BUFSIZ];
    unsigned char *out, outb[64];

    if (hash_out) out = hash_out; else out = outb;

    if (!filename) f = stdin;
    else if( !(f = fopen(filename, "rb"))) {
	fprintf(stderr, "Cannot open file '%s'\n", filename);
	exit(1);
    }

    ret |= sha512_init(&ctx);

    while( (cc=fread(buffer, 1, sizeof(buffer), f)) > 0) {
	ret |= sha512_update(&ctx, buffer, cc);
    }
    if (cc < 0) {
	fprintf(stderr, "Read error for '%s'\n", filename);
	exit(1);
    }

    ret |= sha512_final(&ctx, out);

    if (ret) {
	fprintf(stderr, "SHA512 library failed\n");
	exit(1);
    }

    if(filename) fclose(f);
    f = NULL;

    if (hash_out == 0)
	printhex(outb, sizeof(outb));
}

void
process_file(int flg_h, char *hex_secret, char *hex_pub, char *hex_signature, char *filename)
{
    unsigned char * file_data = 0;
    size_t file_size = 0;

    /* Hashing a file */
    if (flg_h) {
	unsigned char hash_buf[64];
	hash_file(filename, hash_buf);

	file_size = sizeof(hash_buf);
	file_data = malloc(file_size);
	memcpy(file_data, hash_buf, file_size);
    }

    /* Read in the file */
    if (!flg_h)
    {
	size_t fmaxlen = 0;
	int ch, s=(filename&&strcmp(filename,"-"));
	FILE * f = s ?fopen(filename,"r"):stdin;

	if(!f) perror(filename); else
	while((ch=getc(f)) != EOF) {
		if (file_size >= fmaxlen) {
		    file_data = realloc(file_data, fmaxlen = (fmaxlen*2 + 1024));
		    if(!file_data) { perror(program); exit(1); }
		}
		file_data[file_size++] = ch;
	    }
	file_data = realloc(file_data, fmaxlen=file_size);
	if(s) fclose(f);
    }

    if (hex_secret)
    {
	unsigned char public_key[32], private_key[64];
	unsigned char signature[64];

	fetch_secret_key(public_key, private_key, hex_secret);

	ed25519_sign(signature, file_data, file_size, public_key, private_key);
	printhex(signature, sizeof(signature));
    }
    else
    {
	unsigned char public_key[32];
	unsigned char signature[64];

	hex_decode(signature, sizeof(signature), hex_signature);
	hex_decode(public_key, sizeof(public_key), hex_pub);

	if (ed25519_verify(signature, file_data, file_size, public_key)) {
	    printf("Valid signature\n");
	} else {
	    fprintf(stderr, "ERROR: Invalid signature\n");
	    exit(100);
	}
    }

    free(file_data);
}

#ifdef INCLUDE_KEYX
void
do_add_scalar(char *hex_secret, char *hex_pub, char *hex_newkey_add)
{
    unsigned char public_key[32], private_key[64], scalar[32];

    if (hex_secret) {
	fetch_secret_key(public_key, private_key, hex_secret);

	hex_decode(scalar, sizeof(scalar), hex_newkey_add);

	ed25519_add_scalar(public_key, private_key, scalar);

	printf("Private:   "); printhex(private_key, sizeof(private_key));
	printf("Public:    "); printhex(public_key, sizeof(public_key));
    }
    else
    {
	hex_decode(public_key, sizeof(public_key), hex_pub);
	hex_decode(scalar, sizeof(scalar), hex_newkey_add);
	ed25519_add_scalar(public_key, 0, scalar);
	printhex(public_key, sizeof(public_key));
    }
}

void
do_key_exchange(char *hex_secret, char *hex_pub)
{
    unsigned char public_key[32], private_key[64], other_public_key[32];
    unsigned char shared_secret[32];

    fetch_secret_key(public_key, private_key, hex_secret);
    hex_decode(other_public_key, sizeof(other_public_key), hex_pub);

    if (memcmp(public_key, other_public_key, sizeof(public_key)) == 0) {
	fprintf(stderr, "ERROR: Public key matches private key\n");
	exit(2);
    }

    ed25519_key_exchange(shared_secret, other_public_key, private_key);
    printhex(shared_secret, sizeof(shared_secret));
}
#endif

void
Usage()
{
    fprintf(stderr, "Usage: %s [options]\n", program);

    fprintf(stderr, "Options:\n");

    fprintf(stderr, "    -h FILE              # SHA512 of file's contents\n");
    fprintf(stderr, "    -H String            # SHA512 of string (no NL)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    -rk                  # Print matched private(seed) and public keys.\n");
    fprintf(stderr, "    -r                   # Print 32 random bytes in hex\n");
    fprintf(stderr, "    -k S..S              # Generate public key from seed key.\n");
    fprintf(stderr, "    -K S..S              # Generate private key from seed key.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    -s S..S FILE         # Create signature of file from seed key.\n");
    fprintf(stderr, "    -p X..X -v V..V FILE # Validate signature of file from public key.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    -h -s S..S FILE      # Create signature of SHA512 of FILE.\n");
    fprintf(stderr, "    -hpv X..X V..V FILE  # Validate signature of SHA512 of FILE.\n");
    fprintf(stderr, "\n");
#ifdef INCLUDE_KEYX
    fprintf(stderr, "    -xsp S..S X..X       # Generate key exchange secret with other public key\n");
    fprintf(stderr, "    -n Scalar            # Add nonce to Public or Private keys so the\n");
    fprintf(stderr, "                         # server can add randomness to client secret.\n");
#endif
    fprintf(stderr, "The S..S is the 64 hex digit secret seed key.\n");
    fprintf(stderr, "The S..S is the 128 hex digit private key.\n");
    fprintf(stderr, "The X..X is the 64 hex digit public key\n");
    fprintf(stderr, "The V..V is the 128 hex digit signature for validating.\n");

    exit(1);
}
