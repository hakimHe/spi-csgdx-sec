#ifndef CSGDX_H
#define CSGDX_H

#include <linux/types.h>

enum SM2_KEY_GEN_TYPE {
	SM2_NEW_KEY = 0,
	SM2_UPDATE_KEY,
	SM2_KEY_GEN_ERROR,
};
enum SM2_KEY_SAVE_TYPE {
	SM2_KEY_SAVE_IN_RAM = 0,
	SM2_KEY_SAVE_IN_FLASH,
	SM2_KEY_SAVE_ERROR,
};

#define CSGDX_IOC_MAGIC				'X'
#define CSGDX_IOC_VERSION			_IOR(CSGDX_IOC_MAGIC, 1, __u8)
#define CSGDX_IOC_SM2_GEN_KEY		_IOW(CSGDX_IOC_MAGIC, 2, __u8)
#define CSGDX_IOC_SM2_EXPORT_KEY	_IOW(CSGDX_IOC_MAGIC, 3, __u8)
#define CSGDX_IOC_SM2_ENCRYPT		_IOW(CSGDX_IOC_MAGIC, 4, __u8)
#define CSGDX_IOC_SM2_DECRYPT		_IOW(CSGDX_IOC_MAGIC, 5, __u8)

struct csgdx_ioc_transfer {
	__u64		tx_buf;
	__u64		rx_buf;

	__u32		len;
	__u32		speed_hz;

	__u16		delay_usecs;
	__u8		bits_per_word;
	__u8		cs_change;
	__u32		pad;

	/* If the contents of 'struct spi_ioc_transfer' ever change
	 * incompatibly, then the ioctl number (currently 0) must change;
	 * ioctls with constant size fields get a bit more in the way of
	 * error checking than ones (like this) where that field varies.
	 *
	 * NOTE: struct layout is the same in 64bit and 32bit userspace.
	 */
};

struct csgdx_sec_platform_data {
};

struct csgdx_ioc_version {
	unsigned char version[0x50];
};

struct csgdx_ioc_gen_key {
	int new_or_update;
	int save_2_ram_or_flash;
	int key_id;
};

struct csgdx_ioc_export_key {
	int key_id;
	unsigned char pub_key[64];
};

struct csgdx_ioc_encrypt {
	int key_id;
	void* src;
	int src_len;
	void* encrypt;
	int encrypt_len;
};

struct csgdx_ioc_decrypt {
	int key_id;
	void* encrypt;
	int encrypt_len;
	void* decrypt;
	int decrypt_len;
};

#endif /* CSGDX_H */

