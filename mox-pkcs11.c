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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <keyutils.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>

#define CRYPTOKI_GNU
#include "pkcs11.h"

#define ARRAY_SIZE(a)		(sizeof((a))/sizeof((a)[0]))

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

	/* first two digits determine the y-bit */
	pubkey[134] = '\0';
	if (pubkey[0] != '0' || (pubkey[1] != '2' && pubkey[1] != '3'))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}

static ck_rv_t keyctl_read_pubkey(char *pubkey_str)
{
	key_serial_t keyring_id;
	char key_desc[46], pubkey_bin[68];

	keyring_id = find_key_by_type_and_desc("keyring", ".turris-signing-keys", 0);
	if (keyring_id == -1)
		return CKR_DEVICE_ERROR;

	snprintf(key_desc, 46, "Turris MOX SN %.16s rWTM ECDSA key", token_info.serial_number);

	keyctl_key_id = keyctl_search(keyring_id, "turris-signing-key", key_desc, 0);
	if (keyctl_key_id == -1)
		return CKR_DEVICE_ERROR;

	if (keyctl_read(keyctl_key_id, pubkey_bin, 67) != 67) {
		return CKR_DEVICE_ERROR;
	}
	pubkey_bin[67] = '\0';

	/* convert to sysfs form for init_crypto() */
	bin2hex(pubkey_str, pubkey_bin, 67);
	pubkey_str[134] = '\0';

	/* first two digits determine the y-bit */
	if (pubkey_str[0] != '0' || (pubkey_str[1] != '2' && pubkey_str[1] != '3'))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}

static int init_crypto(const char *pubkey)
{
	BN_CTX *bn_ctx;
	EC_GROUP *group;
	BIGNUM *pub_bn;
	EC_POINT *pub_point;
	unsigned char *compr_point_buf;
	size_t compr_point_len;
	OSSL_PARAM_BLD *param_bld;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey = NULL;
	unsigned char *der_pubkey = NULL;
	size_t der_pubkey_len;
	ASN1_OCTET_STRING *asn1_pubkey;

	bn_ctx = BN_CTX_new();
	if (bn_ctx == NULL)
		goto fail_bn_new;

	BN_CTX_start(bn_ctx);
	pub_bn = BN_CTX_get(bn_ctx);
	if (!pub_bn)
		goto fail_bn;

	if (!BN_hex2bn(&pub_bn, pubkey + 2))
		goto fail_bn;

	group = EC_GROUP_new_by_curve_name(NID_secp521r1);
	if (group == NULL)
		goto fail_group;

	pub_point = EC_POINT_new(group);
	if (!pub_point)
		goto fail_point;

        if (!EC_POINT_set_compressed_coordinates(group, pub_point, pub_bn, pubkey[1] == '3', bn_ctx))
                goto fail_point;

	compr_point_len = EC_POINT_point2buf(group, pub_point, POINT_CONVERSION_COMPRESSED, &compr_point_buf, bn_ctx);
	if (compr_point_len == 0)
		goto fail_point_buf;

#ifdef MOX_DEBUG
	printf("printing\n");
	printf("0x%x\n", compr_point_len);
	for (size_t i = 0; i < compr_point_len; i++)
		printf("%02x ", compr_point_buf[i]);
	printf("\n");
#endif

	param_bld = OSSL_PARAM_BLD_new();
	if (param_bld == NULL
		|| !OSSL_PARAM_BLD_push_utf8_string(param_bld, "group",
			"secp521r1", 0)
		|| !OSSL_PARAM_BLD_push_octet_string(param_bld, "pub",
			compr_point_buf, compr_point_len)
		)
		goto fail_param_bld;

	params = OSSL_PARAM_BLD_to_param(param_bld);
	if (params == NULL)
		goto fail_params;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL)
		goto fail_pkey_ctx;

	if (EVP_PKEY_fromdata_init(ctx) <= 0)
		goto fail_pkey_ctx;

	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
		goto fail_pkey;

	pub_attrs[4].value = NULL;
	pub_attrs[4].value_len = i2d_KeyParams(pkey,
			(unsigned char **)&pub_attrs[4].value);
	if (pub_attrs[4].value_len == 0)
		goto fail_attr_params;

	der_pubkey_len = EVP_PKEY_get1_encoded_public_key(pkey, &der_pubkey);
	if (der_pubkey_len == 0)
		goto fail_der_pubkey;

	asn1_pubkey = ASN1_OCTET_STRING_new();
	if (!asn1_pubkey)
		goto fail_der_pubkey;
	if (!ASN1_OCTET_STRING_set(asn1_pubkey, der_pubkey, der_pubkey_len))
		goto fail_asn1_pubkey;

	pub_attrs[3].value = NULL;
	pub_attrs[3].value_len = i2d_ASN1_OCTET_STRING(asn1_pubkey, (unsigned char **)&pub_attrs[3].value);
	if (pub_attrs[3].value_len < 0)
		goto fail_attr_point;

	OPENSSL_free(asn1_pubkey);
	OPENSSL_free(der_pubkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(param_bld);
	free(compr_point_buf);
	EC_POINT_free(pub_point);
	EC_GROUP_free(group);
	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);

	return CKR_OK;

fail_attr_point:
	OPENSSL_free(pub_attrs[3].value);
fail_asn1_pubkey:
	OPENSSL_free(asn1_pubkey);
fail_der_pubkey:
	OPENSSL_free(der_pubkey);
fail_attr_params:
	OPENSSL_free(pub_attrs[4].value);
fail_pkey:
	EVP_PKEY_free(pkey);
fail_pkey_ctx:
	EVP_PKEY_CTX_free(ctx);
fail_params:
	OSSL_PARAM_free(params);
fail_param_bld:
	OSSL_PARAM_BLD_free(param_bld);
fail_point_buf:
	free(compr_point_buf);
fail_point:
	EC_POINT_free(pub_point);
fail_group:
	EC_GROUP_free(group);
fail_bn:
	BN_CTX_end(bn_ctx);
fail_bn_new:
	BN_CTX_free(bn_ctx);

	pub_attrs[3].value = pub_attrs[4].value = NULL;
	pub_attrs[3].value_len = pub_attrs[4].value_len = 0;

	return CKR_FUNCTION_FAILED;
}

static ck_rv_t init_token()
{
	char buf[16];
	int res;

	if (mox_sysfs_read("serial_number", buf, 16) != 16)
		return CKR_DEVICE_ERROR;

	memcpy(token_info.serial_number, &buf, 16);

	res = mox_sysfs_read("board_version", buf, 10);
	if (res < 0)
		return CKR_DEVICE_ERROR;
	else {
		int board_version;
		buf[res] = '\0';

		if (sscanf(buf, "%d", &board_version) != 1)
			return CKR_DEVICE_ERROR;

		token_info.hardware_version.major = board_version;
	}

	return CKR_OK;
}

static ck_rv_t keyctl_initialize(void *init_args)
{
	int res;
	char pubkey[135];

	res = init_token();
	if (res != CKR_OK)
		return res;

	res = keyctl_read_pubkey(pubkey);
	if (res != CKR_OK)
		return res;

	res = init_crypto(pubkey);
	if (res != CKR_OK)
		return res;

	sess.open = 0;

	return CKR_OK;
}

static ck_rv_t sysfs_initialize(void *init_args)
{
	int res;
	char pubkey[135];

	res = init_token();
	if (res != CKR_OK)
		return res;

	res = sysfs_read_pubkey(pubkey);
	if (res != CKR_OK)
		return res;

	res = init_crypto(pubkey);
	if (res != CKR_OK)
		return res;

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
