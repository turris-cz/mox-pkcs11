/*
 * Convert public key from Turris MOX rWTM format to SSH format
 *
 * Compile:
 *   gcc -O2 -o moxpk2sshpk moxpk2sshpk.c -lcrypto -Wall
 *
 * Usage:
 *   moxpk2sshpk
 * or
 *   moxpk2sshpk <ecdsa_public_key>
 *
 * Copyright 2021 by Marek Behun <marek.behun@nic.cz>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static const char *path_prefix_old = "/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/mox_";
static const char *path_prefix_new = "/sys/firmware/turris-mox-rwtm/";
static const char *path_prefix;

static int mox_sysfs_open(const char *file, int flags)
{
	char path[128];

	strcpy(path, path_prefix);
	strcat(path, file);

	return open(path, flags);
}

static void mox_sysfs_select_path_prefix(void)
{
	int fd;

	path_prefix = path_prefix_new;
	fd = mox_sysfs_open("pubkey", O_RDONLY);
	if (fd >= 0) {
		close(fd);
		return;
	}

	path_prefix = path_prefix_old;
}

static int mox_sysfs_read(const char *file, void *buf, int len)
{
	ssize_t rd;
	int fd;

	fd = mox_sysfs_open(file, O_RDONLY);
	if (fd < 0)
		return -1;

	rd = read(fd, buf, len);
	close(fd);

	if (rd < 0)
		return -1;

	return rd;
}

static const char *read_pubkey(void)
{
	static char pubkey[135];

	if (mox_sysfs_read("pubkey", pubkey, 135) != 135)
		return NULL;

	pubkey[134] = '\0';
	if (pubkey[0] != '0' || (pubkey[1] != '2' && pubkey[1] != '3'))
		return NULL;

	return pubkey;
}

static char *sshbuf_put_buf(char *dst, const char *buf, size_t len)
{
	uint32_t len_be32 = htobe32(len);

	memcpy(dst, &len_be32, sizeof(len_be32));
	dst += sizeof(len_be32);
	memcpy(dst, buf, len);
	dst += len;

	return dst;
}

static char *sshbuf_put_cstring(char *dst, const char *str)
{
	return sshbuf_put_buf(dst, str, strlen(str));
}

static void base64_encode(char *dst, const char *_src, int len)
{
	static const char b64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const uint8_t *src = (const uint8_t *)_src;

	while (len > 0) {
		*dst++ = b64[src[0] >> 2];
		if (len > 1) {
			*dst++ = b64[((src[0] & 0x3) << 4) | (src[1] >> 4)];
			if (len > 2) {
				*dst++ = b64[((src[1] & 0xf) << 2) | (src[2] >> 6)];
				*dst++ = b64[src[2] & 0x3f];
			} else {
				*dst++ = b64[((src[1] & 0xf) << 2)];
				*dst++ = '=';
			}
		} else {
			*dst++ = b64[((src[0] & 0x3) << 4)];
			*dst++ = '=';
			*dst++ = '=';
		}
		src += 3;
		len -= 3;
	}

	*dst++ = '\0';
}

static int print_pubkey_ssh(const char *pubkey)
{
	char buf[180], buf_b64[241], keybuf[133], *p;
	const EC_GROUP *group;
	EC_POINT *pub;
	BIGNUM *pub_x;
	EC_KEY *key;
	BN_CTX *ctx;

	if (strlen(pubkey) != 134 || pubkey[0] != '0' || (pubkey[1] != '2' && pubkey[1] != '3'))
		return -1;

	key = EC_KEY_new_by_curve_name(NID_secp521r1);
	if (!key)
		goto fail;

	group = EC_KEY_get0_group(key);

	ctx = BN_CTX_new();
	if (!ctx)
		goto fail_free_key;

	BN_CTX_start(ctx);
	pub_x = BN_CTX_get(ctx);
	if (!pub_x)
		goto fail_end_ctx;

	if (!BN_hex2bn(&pub_x, pubkey + 2))
		goto fail_end_ctx;

	pub = EC_POINT_new(group);
	if (!pub)
		goto fail_end_ctx;

	if (!EC_POINT_set_compressed_coordinates_GFp(group, pub, pub_x, pubkey[1] == '3', ctx))
		goto fail_free_pub;

	if (!EC_KEY_set_public_key(key, pub))
		goto fail_free_pub;

	if (EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL) != sizeof(keybuf))
		goto fail_free_pub;

	EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, (void *)keybuf, sizeof(keybuf), NULL);

	p = buf;
	p = sshbuf_put_cstring(p, "ecdsa-sha2-nistp521");
	p = sshbuf_put_cstring(p, "nistp521");
	p = sshbuf_put_buf(p, keybuf, sizeof(keybuf));

	base64_encode(buf_b64, buf, p - buf);
	printf("ecdsa-sha2-nistp521 %s\n", buf_b64);

	EC_POINT_free(pub);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_KEY_free(key);

	return 0;

fail_free_pub:
	EC_POINT_free(pub);
fail_end_ctx:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
fail_free_key:
	EC_KEY_free(key);
fail:
	return -1;
}

int main(int argc, char **argv)
{
	const char *pubkey;

	if (argc < 2) {
		mox_sysfs_select_path_prefix();
		pubkey = read_pubkey();
		if (!pubkey) {
			fprintf(stderr, "Cannot read public key from sysfs!\n");
			exit(EXIT_FAILURE);
		}
	} else {
		pubkey = argv[1];
	}

	if (print_pubkey_ssh(pubkey)) {
		fprintf(stderr, "Cannot convert public key \"%s\"!\n", pubkey);
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
