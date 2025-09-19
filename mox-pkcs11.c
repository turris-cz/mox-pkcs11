/*
 * Simple PKCS#11 provider - use ECDSA key burned into Turris MOX for ssh
 *
 * Compile:
 *   gcc -fPIC -O2 -o libmox-pkcs11.so mox-pkcs11.c -lcrypto -Wall -shared
 *
 * Export for authorized_keys:
 *   ssh-keygen -D /path/libmox-pkcs11.so -e
 *
 * Connect to host:
 *   ssh -o 'PKCS11Provider /path/libmox-pkcs11.so' user@host
 *
 * Copyright 2020 by Marek Behun <marek.behun@nic.cz>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <keyutils.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define CRYPTOKI_GNU
#include "pkcs11.h"

#define ARRAY_SIZE(a)		sizeof((a))/sizeof((a)[0])

static struct ck_function_list keyctl_fnc_list;
static struct ck_function_list sysfs_fnc_list;

struct session {
	int open;
	struct ck_attribute *find_templ;
	int find_templ_len;
	int find_pos;
};

static struct session sess;

static const char *path_prefixes[] = {
	"/sys/devices/platform/soc/soc:internal-regs@d0000000/soc:internal-regs@d0000000:crypto@0/mox_/",
	"/sys/firmware/turris-mox-rwtm/",
	"/sys/devices/platform/firmware:armada-3700-rwtm/",
	NULL,
};

static const char *path_prefix = NULL;
static key_serial_t keyctl_key_id;

static ck_object_class_t ck_pub_key_class = CKO_PUBLIC_KEY;
static ck_object_class_t ck_priv_key_class = CKO_PRIVATE_KEY;
static ck_key_type_t ck_ecdsa_key_type = CKK_ECDSA;
static unsigned char ck_true_val = 1;
static char ck_key_id[] = "rWTM OTP ECDSA key";

static struct ck_attribute pub_attrs[] = {
	{
		.type = CKA_CLASS,
		.value = &ck_pub_key_class,
		.value_len = sizeof(ck_pub_key_class),
	},
	{
		.type = CKA_KEY_TYPE,
		.value = &ck_ecdsa_key_type,
		.value_len = sizeof(ck_ecdsa_key_type),
	},
	{
		.type = CKA_ID,
		.value = &ck_key_id,
		.value_len = sizeof(ck_key_id),
	},
	{
		.type = CKA_EC_POINT,
	},
	{
		.type = CKA_EC_PARAMS,
	},
	{}
};

static struct ck_attribute priv_attrs[] = {
	{
		.type = CKA_CLASS,
		.value = &ck_priv_key_class,
		.value_len = sizeof(ck_priv_key_class),
	},
	{
		.type = CKA_KEY_TYPE,
		.value = &ck_ecdsa_key_type,
		.value_len = sizeof(ck_ecdsa_key_type),
	},
	{
		.type = CKA_ID,
		.value = &ck_key_id,
		.value_len = sizeof(ck_key_id),
	},
	{
		.type = CKA_SIGN,
		.value = &ck_true_val,
		.value_len = sizeof(ck_true_val),
	},
	{}
};

static struct ck_attribute *objects[] = {
	pub_attrs,
	priv_attrs,
};

static struct ck_token_info token_info = {
	.label = "CZ.NIC rWTM secure-firmware",
	.manufacturer_id = "CZ.NIC, z.s.p.o.",
	.model = "Turris MOX",
	.flags = CKF_PROTECTED_AUTHENTICATION_PATH | CKF_TOKEN_INITIALIZED,
	.firmware_version = {
		.major = 0,
		.minor = 1,
	}
};

static const char hex_asc[] = "0123456789abcdef";

static void bin2hex(char *hex, char *bin, size_t len)
{
	while (len--) {
		*hex++ = hex_asc[(*bin & 0xf0) >> 4];
		*hex++ = hex_asc[*bin++ & 0x0f];
	}
	*hex = '\0';
}

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

	for (const char **p = path_prefixes; *p; p++) {
		path_prefix = *p;
		fd = mox_sysfs_open("serial_number", O_RDONLY);
		if (fd >= 0) {
			close(fd);
			return;
		}
	}
	path_prefix = NULL;
	return;
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

static ck_rv_t sysfs_read_pubkey(char *pubkey)
{
	if (mox_sysfs_read("pubkey", pubkey, 135) != 135)
		return CKR_DEVICE_ERROR;

	pubkey[134] = '\0';
	if (pubkey[0] != '0' || (pubkey[1] != '2' && pubkey[1] != '3'))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}

static ck_rv_t keyctl_read_pubkey(char *pubkey_str, const char *board_sn)
{
	key_serial_t keyring_id;
	char key_desc[46], pubkey[68];

	keyring_id = find_key_by_type_and_desc("keyring", ".turris-signing-keys", 0);
	if (keyring_id == -1)
		return CKR_DEVICE_ERROR;

	snprintf(key_desc, 46, "Turris MOX SN %s rWTM ECDSA key", board_sn);

	keyctl_key_id = keyctl_search(keyring_id, "turris-signing-key", key_desc, 0);
	if (keyctl_key_id == -1)
		return CKR_DEVICE_ERROR;

	if (keyctl_read(keyctl_key_id, pubkey, 67) != 67) {
		return CKR_DEVICE_ERROR;
	}
	pubkey[67] = '\0';

	if (pubkey[0] != 2 && pubkey[0] != 3)
		return CKR_DEVICE_ERROR;

	/* convert to sysfs form for init_crypto() */
	bin2hex(pubkey_str, pubkey, 67);

	return CKR_OK;
}

static int init_crypto(const char *pubkey)
{
	EC_KEY *key;
	BN_CTX *ctx;
	EC_POINT *pub;
	BIGNUM *pub_x;
	unsigned char *des_pubkey;
	int des_pubkey_len;
	ASN1_OCTET_STRING *asn1_pubkey;
	const EC_GROUP *group;

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

	pub_attrs[4].value = NULL;
	pub_attrs[4].value_len = i2d_ECParameters(key, (unsigned char **)&pub_attrs[4].value);
	if (pub_attrs[4].value_len < 0)
		goto fail_free_pub;

	des_pubkey = NULL;
	des_pubkey_len = i2o_ECPublicKey(key, &des_pubkey);
	if (des_pubkey_len < 0)
		goto fail_free_ec_params;

	asn1_pubkey = ASN1_OCTET_STRING_new();
	if (!asn1_pubkey)
		goto fail_free_des_pubkey;
	if (!ASN1_OCTET_STRING_set(asn1_pubkey, des_pubkey, des_pubkey_len))
		goto fail_free_asn1_pubkey;

	pub_attrs[3].value = NULL;
	pub_attrs[3].value_len = i2d_ASN1_OCTET_STRING(asn1_pubkey, (unsigned char **)&pub_attrs[3].value);
	if (pub_attrs[3].value_len < 0)
		goto fail_free_asn1_pubkey;

	free(asn1_pubkey);
	free(des_pubkey);
	EC_POINT_free(pub);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_KEY_free(key);

	return 0;

fail_free_asn1_pubkey:
	free(asn1_pubkey);
fail_free_des_pubkey:
	free(des_pubkey);
fail_free_ec_params:
	free(pub_attrs[4].value);
fail_free_pub:
	EC_POINT_free(pub);
fail_end_ctx:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
fail_free_key:
	EC_KEY_free(key);
fail:
	pub_attrs[3].value = pub_attrs[4].value = NULL;
	pub_attrs[3].value_len = pub_attrs[4].value_len = 0;

	return -1;
}

static ck_rv_t keyctl_initialize(void *init_args)
{
	char buf[11];
	char board_sn[17];
	int res;

	char pubkey_str[135];

	if (mox_sysfs_read("serial_number", board_sn, 17) != 17)
		return CKR_DEVICE_ERROR;
	board_sn[16] = '\0';

	/* skip first zero so that we can push in terminating NUL byte */
	memcpy(token_info.serial_number, &board_sn[1], 15);
	token_info.serial_number[15] = '\0';

	res = mox_sysfs_read("board_version", buf, 10);
	if (res < 0)
		return CKR_DEVICE_ERROR;

	if (res > 0) {
		int board_version;
		buf[res] = '\0';

		errno = 0;
		sscanf(buf, "%d", &board_version);
		if (errno != 0)
			return CKR_DEVICE_ERROR;
		token_info.hardware_version.major = board_version;
	}

	res = keyctl_read_pubkey(pubkey_str, board_sn);
	if (res != CKR_OK)
		return res;

	if (init_crypto(pubkey_str))
		return CKR_FUNCTION_FAILED;

	sess.open = 0;

	return CKR_OK;
}

static ck_rv_t sysfs_initialize(void *init_args)
{
	char pubkey[135];
	char buf[17];
	int res;

	res = sysfs_read_pubkey(pubkey);
	if (res != CKR_OK)
		return res;

	if (mox_sysfs_read("serial_number", buf, 17) != 17)
		return CKR_DEVICE_ERROR;

	/* skip first zero so that we can push in terminating NUL byte */
	memcpy(token_info.serial_number, &buf[1], 15);
	token_info.serial_number[15] = '\0';

	res = mox_sysfs_read("board_version", buf, 10);
	if (res < 0)
		return CKR_DEVICE_ERROR;

	if (res > 0) {
		int board_version;
		buf[res] = '\0';

		errno = 0;
		sscanf(buf, "%d", &board_version);
		if (errno != 0)
			return CKR_DEVICE_ERROR;
		token_info.hardware_version.major = board_version;
	}

	if (init_crypto(pubkey))
		return CKR_FUNCTION_FAILED;

	sess.open = 0;

	return CKR_OK;
}

static ck_rv_t Finalize(void *reserved)
{
	free(pub_attrs[3].value);
	free(pub_attrs[4].value);
	pub_attrs[3].value = pub_attrs[4].value = NULL;
	pub_attrs[3].value_len = pub_attrs[4].value_len = 0;
	return CKR_OK;
}

static ck_rv_t GetInfo(struct ck_info *pinfo)
{
	static const struct ck_info info = {
		.cryptoki_version = {
			.major = CRYPTOKI_VERSION_MAJOR,
			.minor = CRYPTOKI_VERSION_MINOR,
		},
		.manufacturer_id = "CZ.NIC, z.s.p.o.",
		.flags = 0,
		.library_description = "Turris MOX ECDSA key lib",
		.library_version = {
			.major = 0,
			.minor = 1,
		},
	};

	if (pinfo)
		memcpy(pinfo, &info, sizeof(info));

	return CKR_OK;
}

ck_rv_t C_GetFunctionList(struct ck_function_list **pplist)
{
	mox_sysfs_select_path_prefix();
	if (path_prefix == NULL)
		return CKR_TOKEN_NOT_PRESENT;

	if (find_key_by_type_and_desc("keyring", ".turris-signing-keys", 0) != -1)
		*pplist = &keyctl_fnc_list;
	else
		*pplist = &sysfs_fnc_list; /* fallback */
	return CKR_OK;
}

static ck_rv_t GetSlotList(unsigned char token_present, ck_slot_id_t *slot_list,
			   unsigned long *count)
{
	if (slot_list)
		slot_list[0] = 1;
	if (count)
		*count = 1;

	return CKR_OK;
}

static ck_rv_t GetSlotInfo(ck_slot_id_t slot_id, struct ck_slot_info *pinfo)
{
	static const struct ck_slot_info info = {
		.slot_description = "CZ.NIC rWTM secure-firmware",
		.manufacturer_id = "CZ.NIC, z.s.p.o.",
		.flags = CKF_TOKEN_PRESENT,
		.hardware_version = {
			.major = 0,
			.minor = 1,
		},
		.firmware_version = {
			.major = 0,
			.minor = 1,
		}
	};

	if (slot_id != 1)
		return CKR_SLOT_ID_INVALID;

	if (pinfo)
		memcpy(pinfo, &info, sizeof(info));

	return CKR_OK;
}

static ck_rv_t GetTokenInfo(ck_slot_id_t slot_id, struct ck_token_info *pinfo)
{
	if (slot_id != 1)
		return CKR_SLOT_ID_INVALID;

	if (pinfo)
		memcpy(pinfo, &token_info, sizeof(token_info));

	return CKR_OK;
}

static ck_rv_t OpenSession(ck_slot_id_t slot_id, ck_flags_t flags,
			   void *application, ck_notify_t notify,
			   ck_session_handle_t *session)
{
	if (sess.open)
		return CKR_SESSION_COUNT;

	if (slot_id != 1)
		return CKR_SLOT_ID_INVALID;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	*session = 1;
	sess.open = 1;

	return CKR_OK;
}

static ck_rv_t CloseSession(ck_session_handle_t session)
{
	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	sess.open = 0;
	return CKR_OK;
}

static ck_rv_t FindObjectsInit(ck_session_handle_t session,
			       struct ck_attribute *templ,
			       unsigned long count)
{
	void *ptr;
	size_t to_alloc;
	int i;

	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess.find_templ)
		return CKR_OPERATION_ACTIVE;

	if (!templ)
		return CKR_ARGUMENTS_BAD;

	sess.find_templ = templ;
	sess.find_templ_len = count;
	sess.find_pos = 0;

	to_alloc = count * sizeof(*templ);
	for (i = 0; i < count; ++i)
		to_alloc += templ[i].value_len;

	sess.find_templ = malloc(to_alloc);
	if (!sess.find_templ)
		return CKR_HOST_MEMORY;

	ptr = &sess.find_templ[count];
	for (i = 0; i < count; ++i) {
		sess.find_templ[i].type = templ[i].type;
		sess.find_templ[i].value_len = templ[i].value_len;
		memcpy(ptr, templ[i].value, templ[i].value_len);
		sess.find_templ[i].value = ptr;
		ptr += templ[i].value_len;
	}


	return CKR_OK;
}

static ck_rv_t FindObjects(ck_session_handle_t session,
			   ck_object_handle_t *object,
			   unsigned long max_object_count,
			   unsigned long *object_count)
{
	int i, j, k;

	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	if (!sess.find_templ)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (object_count)
		*object_count = 0;

	for (i = sess.find_pos; i < ARRAY_SIZE(objects) && max_object_count > 0; ++i) {
		int match = 1;

		for (j = 0; j < sess.find_templ_len; ++j) {
			for (k = 0; objects[i][k].value; ++k) {
				if (objects[i][k].type == sess.find_templ[j].type &&
				    (objects[i][k].value_len != sess.find_templ[j].value_len ||
				     memcmp(objects[i][k].value, sess.find_templ[j].value, objects[i][k].value_len))) {
					match = 0;
					break;
				}
			}

			if (!match)
				break;
		}

		if (match) {
			if (object) {
				*object = i;
				++object;
				++*object_count;
				--max_object_count;
			}
		}
	}

	sess.find_pos = i;

	return CKR_OK;
}

static ck_rv_t FindObjectsFinal(ck_session_handle_t session)
{
	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	if (!sess.find_templ)
		return CKR_OPERATION_NOT_INITIALIZED;

	free(sess.find_templ);
	sess.find_templ = NULL;
	return CKR_OK;
}

static ck_rv_t GetAttributeValue(ck_session_handle_t session,
				 ck_object_handle_t object,
				 struct ck_attribute *templ,
				 unsigned long count)
{
	struct ck_attribute *attrs;
	ck_rv_t res = CKR_OK;
	int i, j;

	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	if (object >= ARRAY_SIZE(objects))
		return CKR_OBJECT_HANDLE_INVALID;

	attrs = objects[object];

	for (i = 0; i < count; ++i) {
		for (j = 0; attrs[j].value; ++j) {
			if (attrs[j].type == templ[i].type)
				break;
		}

		if (!attrs[j].value) {
			templ[i].value_len = CK_UNAVAILABLE_INFORMATION;
			continue;
		}

		if (!templ[i].value) {
			templ[i].value_len = attrs[j].value_len;
		} else if (templ[i].value_len < attrs[j].value_len) {
			templ[i].value_len = CK_UNAVAILABLE_INFORMATION;
			res = CKR_BUFFER_TOO_SMALL;
		} else {
			memcpy(templ[i].value, attrs[j].value, attrs[j].value_len);
		}
	}

	return res;
}

static ck_rv_t SignInit(ck_session_handle_t session,
			struct ck_mechanism *mechanism,
			ck_object_handle_t key)
{
	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	if (key >= ARRAY_SIZE(objects))
		return CKR_OBJECT_HANDLE_INVALID;

	if (!mechanism)
		return CKR_ARGUMENTS_BAD;

	if (mechanism->mechanism != CKM_ECDSA)
		return CKR_MECHANISM_INVALID;

	if (objects[key] != priv_attrs)
		return CKR_KEY_TYPE_INCONSISTENT;

	return CKR_OK;
}

static ck_rv_t keyctl_sign(ck_session_handle_t session,
		    unsigned char *data, unsigned long data_len,
		    unsigned char *signature,
		    unsigned long *signature_len)
{
	int res;

	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	if (data_len != 64)
		return CKR_DATA_LEN_RANGE;

	*signature_len = 132;
	res = keyctl_pkey_sign(keyctl_key_id, "",
			data, data_len,
			signature, *signature_len);
	if (res == -1)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

static ck_rv_t sysfs_sign(ck_session_handle_t session,
		    unsigned char *data, unsigned long data_len,
		    unsigned char *signature,
		    unsigned long *signature_len)
{
	int fd;
	unsigned char sig[136];
	unsigned char use_debugfs = 0;

	if (session != 1 || !sess.open)
		return CKR_SESSION_HANDLE_INVALID;

	if (data_len != 64)
		return CKR_DATA_LEN_RANGE;

	fd = open("/sys/kernel/debug/turris-mox-rwtm/do_sign", O_RDWR);
	if (fd >= 0)
		use_debugfs = 1;
	else {
		/* on old versions of turris os */
		use_debugfs = 0;
		fd = mox_sysfs_open("do_sign", O_RDWR);
		if (fd < 0)
			return CKR_FUNCTION_FAILED;
	}

	/* flush in the case of pending previous sig */
	read(fd, sig, 136);

	if (write(fd, data, data_len) != data_len)
		goto fail;

	/* seek only on sysfs */
	if (!use_debugfs)
		if (lseek(fd, 0, SEEK_SET) < 0)
			goto fail;

	if (read(fd, sig, 136) != 136)
		goto fail;

	close(fd);

	memcpy(&signature[0], &sig[2], 66);
	memcpy(&signature[66], &sig[70], 66);
	*signature_len = 132;

	return CKR_OK;
fail:
	close(fd);
	return CKR_FUNCTION_FAILED;
}

/*
 * Used when keyctl API for MOX is supported (Linux >=6.16)
 */
static struct ck_function_list keyctl_fnc_list = {
	.version = {
		.major = CRYPTOKI_VERSION_MAJOR,
		.minor = CRYPTOKI_VERSION_MINOR,
	},
	.C_Initialize = keyctl_initialize,
	.C_Finalize = Finalize,
	.C_GetInfo = GetInfo,
	.C_GetFunctionList = C_GetFunctionList,
	.C_GetSlotList = GetSlotList,
	.C_GetSlotInfo = GetSlotInfo,
	.C_GetTokenInfo = GetTokenInfo,

	.C_OpenSession = OpenSession,
	.C_CloseSession = CloseSession,
	.C_FindObjectsInit = FindObjectsInit,
	.C_FindObjects = FindObjects,
	.C_FindObjectsFinal = FindObjectsFinal,

	.C_GetAttributeValue = GetAttributeValue,

	.C_SignInit = SignInit,
	.C_Sign = keyctl_sign,
};

/*
 * Used as fallback when keyctl API for accessing the key is not supported
 * (Linux <=6.15)
 */
static struct ck_function_list sysfs_fnc_list = {
	.version = {
		.major = CRYPTOKI_VERSION_MAJOR,
		.minor = CRYPTOKI_VERSION_MINOR,
	},
	.C_Initialize = sysfs_initialize,
	.C_Finalize = Finalize,
	.C_GetInfo = GetInfo,
	.C_GetFunctionList = C_GetFunctionList,
	.C_GetSlotList = GetSlotList,
	.C_GetSlotInfo = GetSlotInfo,
	.C_GetTokenInfo = GetTokenInfo,

	.C_OpenSession = OpenSession,
	.C_CloseSession = CloseSession,
	.C_FindObjectsInit = FindObjectsInit,
	.C_FindObjects = FindObjects,
	.C_FindObjectsFinal = FindObjectsFinal,

	.C_GetAttributeValue = GetAttributeValue,

	.C_SignInit = SignInit,
	.C_Sign = sysfs_sign,
};
