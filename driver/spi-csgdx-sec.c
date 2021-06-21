
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/bitops.h>
#include <linux/firmware.h>
#include <linux/spi/spi.h>
#include <linux/spi/csgdx-sec.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#define DRV_NAME	"spi-csgdx-sec"
#define DRV_DESC	"CSGDX-SEC-201701 secure Encrypt driver"
#define DRV_VERSION	"0.1.0"

/* Module Parameters */
static unsigned int printk_mode = 0;
module_param(printk_mode, uint, 0644);
MODULE_PARM_DESC(printk_mode, "0 - close printk , 1 - open printk");

#define csgdx_dbg(fmt, ...)\
{\
	if(printk_mode == 1)\
		printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__);\
	else\
		no_printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__);\
}

#define CSGDX_BASE_MINOR	0
#define CSGDX_MINOR_CNT 	1

static struct class *csgdx_class;
static dev_t csgdx_dev_t;

struct csgdx_data {
	struct cdev cdev;
	struct spi_device *spi;
	spinlock_t		spi_lock;
	struct mutex	buf_lock;
	u8* tx_buffer;
	u8* rx_buffer;
	u8* encrypt_buffer;
	u8* decrypt_buffer;
	u8* source_buffer;
	u8* transfer_buffer;
};

struct dl_cmd_reserve {
	char cla;
	char ins;
	char p1;
	char p2;
	char reserve[4];
} __attribute__ ((packed));

struct ul_status_reserve {
	short status;
	char reserve[6];
} __attribute__ ((packed));

struct msg_hdr {
	u32 hdr;
	u32 data_len;
	union {
		struct dl_cmd_reserve dcr;
		struct ul_status_reserve usr;
	};
} __attribute__ ((packed));

struct msg_tail {
	u32 tail;
};

struct msg_crc {
	u32 crc;
};

#define DL_MSG_HEAD_KEY 0x43534744
#define DL_MSG_TAIL_KEY 0x31373031
#define UL_MSG_HEAD_KEY 0x44544845
#define UL_MSG_TAIL_KEY 0x32383132

#define KEY_ID_MAX 4
#define PRIVATE_KEY_LEN 32
#define PUBLIC_KEY_LEN 64
#define KEY_MAX_LEN (PUBLIC_KEY_LEN+PRIVATE_KEY_LEN)
#define SOURCE_DATA_LENGTH 128
#define ENCRYPT_DATA_LENGTH (SOURCE_DATA_LENGTH+KEY_MAX_LEN)
#define DECRYPT_DATA_LENGTH (SOURCE_DATA_LENGTH+KEY_MAX_LEN)
#define TRANSFER_BUF_LEN 4096
#define PACKET_LENGTH 4096

#define BUSY	0x5A
#define READY1	0x42
#define READY2	0x53
#define RX_STATUS_OK	0x9000

#define DL_HDR(MSG, LEN, CLA, INS, P1, P2) do{ \
	MSG->hdr = cpu_to_le32(DL_MSG_HEAD_KEY);\
	MSG->data_len = cpu_to_le32(LEN); \
	MSG->dcr.cla = CLA; \
	MSG->dcr.ins = INS; \
	MSG->dcr.p1 = P1; \
	MSG->dcr.p2 = P2; \
	memset(MSG->dcr.reserve , 0x55, 4);\
}while(0);

#define UL_HDR(MSG, LEN) do {\
	MSG->hdr = cpu_to_le32(UL_MSG_HEAD_KEY);\
	MSG->data_len = cpu_to_le32(LEN);\
	memset(MSG->usr.reserve , 0x5A, 6);\
}while(0);

static const unsigned int table32[256] = {
	0x0000,0x4c11db7,0x9823b6e,0xd4326d9,0x130476dc,0x17c56b6b,0x1a864db2,0x1e475005,
	0x2608edb8,0x22c9f00f,0x2f8ad6d6,0x2b4bcb61,0x350c9b64,0x31cd86d3,0x3c8ea00a,0x384fbdbd,
	0x4c11db70,0x48d0c6c7,0x4593e01e,0x4152fda9,0x5f15adac,0x5bd4b01b,0x569796c2,0x52568b75,
	0x6a1936c8,0x6ed82b7f,0x639b0da6,0x675a1011,0x791d4014,0x7ddc5da3,0x709f7b7a,0x745e66cd,
	0x9823b6e0,0x9ce2ab57,0x91a18d8e,0x95609039,0x8b27c03c,0x8fe6dd8b,0x82a5fb52,0x8664e6e5,
	0xbe2b5b58,0xbaea46ef,0xb7a96036,0xb3687d81,0xad2f2d84,0xa9ee3033,0xa4ad16ea,0xa06c0b5d,
	0xd4326d90,0xd0f37027,0xddb056fe,0xd9714b49,0xc7361b4c,0xc3f706fb,0xceb42022,0xca753d95,
	0xf23a8028,0xf6fb9d9f,0xfbb8bb46,0xff79a6f1,0xe13ef6f4,0xe5ffeb43,0xe8bccd9a,0xec7dd02d,
	0x34867077,0x30476dc0,0x3d044b19,0x39c556ae,0x278206ab,0x23431b1c,0x2e003dc5,0x2ac12072,
	0x128e9dcf,0x164f8078,0x1b0ca6a1,0x1fcdbb16,0x18aeb13,0x54bf6a4,0x808d07d,0xcc9cdca,
	0x7897ab07,0x7c56b6b0,0x71159069,0x75d48dde,0x6b93dddb,0x6f52c06c,0x6211e6b5,0x66d0fb02,
	0x5e9f46bf,0x5a5e5b08,0x571d7dd1,0x53dc6066,0x4d9b3063,0x495a2dd4,0x44190b0d,0x40d816ba,
	0xaca5c697,0xa864db20,0xa527fdf9,0xa1e6e04e,0xbfa1b04b,0xbb60adfc,0xb6238b25,0xb2e29692,
	0x8aad2b2f,0x8e6c3698,0x832f1041,0x87ee0df6,0x99a95df3,0x9d684044,0x902b669d,0x94ea7b2a,
	0xe0b41de7,0xe4750050,0xe9362689,0xedf73b3e,0xf3b06b3b,0xf771768c,0xfa325055,0xfef34de2,
	0xc6bcf05f,0xc27dede8,0xcf3ecb31,0xcbffd686,0xd5b88683,0xd1799b34,0xdc3abded,0xd8fba05a,
	0x690ce0ee,0x6dcdfd59,0x608edb80,0x644fc637,0x7a089632,0x7ec98b85,0x738aad5c,0x774bb0eb,
	0x4f040d56,0x4bc510e1,0x46863638,0x42472b8f,0x5c007b8a,0x58c1663d,0x558240e4,0x51435d53,
	0x251d3b9e,0x21dc2629,0x2c9f00f0,0x285e1d47,0x36194d42,0x32d850f5,0x3f9b762c,0x3b5a6b9b,
	0x315d626,0x7d4cb91,0xa97ed48,0xe56f0ff,0x1011a0fa,0x14d0bd4d,0x19939b94,0x1d528623,
	0xf12f560e,0xf5ee4bb9,0xf8ad6d60,0xfc6c70d7,0xe22b20d2,0xe6ea3d65,0xeba91bbc,0xef68060b,
	0xd727bbb6,0xd3e6a601,0xdea580d8,0xda649d6f,0xc423cd6a,0xc0e2d0dd,0xcda1f604,0xc960ebb3,
	0xbd3e8d7e,0xb9ff90c9,0xb4bcb610,0xb07daba7,0xae3afba2,0xaafbe615,0xa7b8c0cc,0xa379dd7b,
	0x9b3660c6,0x9ff77d71,0x92b45ba8,0x9675461f,0x8832161a,0x8cf30bad,0x81b02d74,0x857130c3,
	0x5d8a9099,0x594b8d2e,0x5408abf7,0x50c9b640,0x4e8ee645,0x4a4ffbf2,0x470cdd2b,0x43cdc09c,
	0x7b827d21,0x7f436096,0x7200464f,0x76c15bf8,0x68860bfd,0x6c47164a,0x61043093,0x65c52d24,
	0x119b4be9,0x155a565e,0x18197087,0x1cd86d30,0x29f3d35,0x65e2082,0xb1d065b,0xfdc1bec,
	0x3793a651,0x3352bbe6,0x3e119d3f,0x3ad08088,0x2497d08d,0x2056cd3a,0x2d15ebe3,0x29d4f654,
	0xc5a92679,0xc1683bce,0xcc2b1d17,0xc8ea00a0,0xd6ad50a5,0xd26c4d12,0xdf2f6bcb,0xdbee767c,
	0xe3a1cbc1,0xe760d676,0xea23f0af,0xeee2ed18,0xf0a5bd1d,0xf464a0aa,0xf9278673,0xfde69bc4,
	0x89b8fd09,0x8d79e0be,0x803ac667,0x84fbdbd0,0x9abc8bd5,0x9e7d9662,0x933eb0bb,0x97ffad0c,
	0xafb010b1,0xab710d06,0xa6322bdf,0xa2f33668,0xbcb4666d,0xb8757bda,0xb5365d03,0xb1f740b4,
};

static unsigned int msg_crc32(unsigned int start,unsigned char *buff, unsigned int len)
{
	unsigned int accu = start;
	int i= 0;
	char j=0;
	unsigned int left = len%4;

	for (i=0; i < len/4; i++) {
		for(j=4;j>0;j--){
			accu = (accu<<8) ^ table32[(accu>>24) ^ buff[4*i+j-1]];
		}
	}

	if(left) {
		for(j=4-left;j>0;j--) {
			accu = (accu<<8) ^ table32[(accu>>24) ^ 0];
		}
		for(j=1;j<=left;j++) {
			accu = (accu<<8) ^ table32[(accu>>24) ^ buff[len-j]];
		}
	}

	return accu;
}

static void msg_show(u8* msg, int len)
{
	int i;

	if(!printk_mode)
		return;

	printk("msg len 0x%02X:\n", len);
	for(i = 0; i < len; i++)
    {
		printk("%02X", msg[i]);
    }
	printk("\n");

	return;
}

static int csgdx_spi_async(struct spi_device *spi, void* tx_buf, int len, void *rx_buf)
{
	int ret=0;
	struct spi_transfer	t;
	struct spi_message	msg;

	memset(&t, 0, sizeof(t));
	t.tx_buf = tx_buf;
	t.len = len;
	t.rx_buf = rx_buf;
	spi_message_init(&msg);
	spi_message_add_tail(&t, &msg);

	ret = spi_sync(spi, &msg);
	if (ret < 0) {
		pr_err("csgdx_spi_sync ret %d\n", ret);
		return ret;;
	}

	return ret;
}

static int msg_dl_transfer (struct csgdx_data *csgdx, struct dl_cmd_reserve *dcr, void* tx_buf, u32 len)
{
	int ret = 0, dlmsg_len, tail_offs, crc_offs, data_offs, tx_len;
	u32 crc32;
	u8 *dlmsg;
	struct msg_hdr *hdr;

	tx_len = tx_buf ? len : 0;
	dlmsg_len = sizeof(struct msg_hdr) + tx_len + sizeof(struct msg_tail) + sizeof(struct msg_crc);
	data_offs = sizeof(struct msg_hdr);
	tail_offs = data_offs + tx_len;
	crc_offs = tail_offs + sizeof(struct msg_tail);
	dlmsg = csgdx->tx_buffer;
	hdr = (struct msg_hdr*)dlmsg;

	hdr->hdr = cpu_to_le32(DL_MSG_HEAD_KEY);
	hdr->data_len = cpu_to_le32(len);
	memset(hdr->dcr.reserve, 0x55, sizeof(hdr->dcr.reserve));
	memcpy(&hdr->dcr, dcr, sizeof(hdr->dcr));

	if(tx_buf && tx_len) {
		memcpy(dlmsg+data_offs, tx_buf, tx_len);
	}

	*(u32*)(dlmsg+tail_offs) = cpu_to_le32(DL_MSG_TAIL_KEY);

	crc32 = msg_crc32(0xFFFFFFFF, dlmsg, dlmsg_len-sizeof(struct msg_crc));
	crc32 = cpu_to_le32(crc32);
	memcpy((u32*)(dlmsg+crc_offs), &crc32, sizeof(u32));

	ret = spi_write(csgdx->spi, dlmsg, dlmsg_len);
	if (ret) {
		pr_err("spi_read ret %d\n", ret);
		return -1;
	}

	return 0;
}

static int msg_ul_transfer (struct csgdx_data *csgdx, void* rx_buf, u32 rx_len)
{
	int ret = 0, ulmsg_len, tail_offs, crc_offs, data_offs;
	u32 crc32, status;
	u8 *ulmsg;
	struct msg_hdr *hdr;

	ulmsg_len = sizeof(struct msg_hdr) + rx_len + sizeof(struct msg_tail) + sizeof(struct msg_crc);
	data_offs = sizeof(struct msg_hdr);
	tail_offs = data_offs + rx_len;
	crc_offs = tail_offs + sizeof(struct msg_tail);
	ulmsg = csgdx->rx_buffer;

	hdr = (struct msg_hdr*)ulmsg;
	UL_HDR(hdr, rx_len);
	*(u32*)(ulmsg+tail_offs) = cpu_to_le32(UL_MSG_TAIL_KEY);

	crc32 = msg_crc32(0xFFFFFFFF, ulmsg, ulmsg_len-sizeof(struct msg_crc));
	*(u32*)(ulmsg+crc_offs) = cpu_to_le32(crc32);

	ret = spi_read(csgdx->spi, ulmsg, ulmsg_len);
	if (ret) {
		pr_err("msg_ul_transfer spi_read fail, ret %d!\n", ret);
		return ret;
	}

	if(rx_buf && rx_len) {
		memcpy(rx_buf, ulmsg+data_offs, rx_len);
	}

	hdr = (struct msg_hdr*)ulmsg;
	status = le16_to_cpu(hdr->usr.status);
	if(status != RX_STATUS_OK) {
		pr_err("msg_ul_transfer status 0x%x\n", status);
		return -1;
	}

	return ret;
}

static int msg_wait_status(struct csgdx_data *csgdx)
{
	int ret=0, status=-1,ready1_flag=0;
	u8 wr_data=BUSY, rd_data=0;
	unsigned long begin;

	begin = jiffies;
	while (!time_after(jiffies, begin + msecs_to_jiffies(5000))) {
		ret = csgdx_spi_async(csgdx->spi, &wr_data, 1, &rd_data);
		if (ret < 0) {
			pr_err("msg_wait_status csgdx_spi_sync ret %d\n", ret);
			break;
		}

		if (rd_data == READY1) {
			ready1_flag = 1;
		} else if ((rd_data == READY2) && ready1_flag) {
			status = 0;
			break;
		} else {
		}
		udelay(50);
	}

	return status;
}

static int msg_wake_up(struct csgdx_data *csgdx)
{
	int ret=-0, count=0;
	u8 wr_data=BUSY, rd_data=0;
	unsigned long begin;

	begin = jiffies;
	while (!time_after(jiffies, begin + msecs_to_jiffies(20000))) {
		ret = csgdx_spi_async(csgdx->spi, &wr_data, 1, &rd_data);
		if (ret < 0) {
			pr_err("msg_wake_up csgdx_spi_sync ret %d\n", ret);
			break;
		}

		if (rd_data == BUSY) {
			if(count++ > 5) {
				schedule_timeout_interruptible(1);
				return 0;
			}
		} else {
			count = 0;
		}

		udelay(50);
	}

	return -1;
}

static int msg_transfer(struct csgdx_data *csgdx,
				struct dl_cmd_reserve *dcr, void* tx_buf, u8 tx_len, void *rx_buf, u8 rx_len)
{
	if(msg_wake_up(csgdx)) {
		pr_err("msg_transfer msg_wake_up fail!\n");
		return -1;
	}

	if(msg_dl_transfer(csgdx, dcr, tx_buf, tx_len)) {
		pr_err("msg_transfer msg_dl_transfer fail!\n");
		return -2;
	}

	if(msg_wait_status(csgdx)) {
		pr_err("msg_transfer msg_wait_status fail!\n");
		return -3;
	}

	if(msg_ul_transfer(csgdx, rx_buf, rx_len)) {
		pr_err("msg_transfer msg_ul_transfer fail!\n");
		return -4;
	}

	return 0;
}

static int msg_version(struct csgdx_data *csgdx, unsigned long arg)
{
	int ret=0, len=0x50;
	struct csgdx_ioc_version kbuf;
	struct dl_cmd_reserve dcr = {
		.cla = 0x81,
		.ins = 0x30,
		.p1 = 0,
		.p2 = 0,
	};

	ret = msg_transfer(csgdx, &dcr, NULL, len, kbuf.version, len);
	if(ret) {
		pr_err("msg_version msg_transfer fail! ret %d\n", ret);
		return -1;
	}

	csgdx_dbg("bytes[%d] version: %s\n", len, kbuf.version);
	copy_to_user((void __user*)arg, &kbuf, sizeof(kbuf));

	return ret;
}

static int sm2_gen_key(struct csgdx_data *csgdx, unsigned long arg)
{
	int ret = 0;
	u8 tx_data[] = {0,0,1,0};//私钥不可导出
	u8 rx_data[1] = {0x0};
	struct csgdx_ioc_gen_key gen_key;

	struct dl_cmd_reserve dcr = {
		.cla = 0x81,
		.ins = 0x5A,
	};

	copy_from_user(&gen_key, (void __user *)arg, sizeof(gen_key));
	if(gen_key.new_or_update >= SM2_KEY_GEN_ERROR || gen_key.save_2_ram_or_flash >= SM2_KEY_SAVE_ERROR) {
		pr_err("sm2_gen_key user para error ! %d %d\n", gen_key.new_or_update, gen_key.save_2_ram_or_flash);
		return -1;
	}

	dcr.p1 = gen_key.new_or_update;
	dcr.p2 = gen_key.save_2_ram_or_flash;
	if(gen_key.new_or_update == SM2_NEW_KEY) {
		tx_data[1] = 0;
	} else {
		tx_data[1] = gen_key.key_id;
	}

	ret = msg_transfer(csgdx, &dcr, tx_data, sizeof(tx_data), rx_data, sizeof(rx_data));
	if(ret) {
		pr_err("...sm2_gen_key msg_transfer fail! ret %d, %d %d %d\n",
			ret, gen_key.new_or_update, gen_key.save_2_ram_or_flash, gen_key.key_id);
		return ret;
	}

	csgdx_dbg("sm2_gen_key success, rx_data 0x%x! %d, %d, %d\n",
		rx_data[0], gen_key.new_or_update, gen_key.save_2_ram_or_flash, gen_key.key_id);

	gen_key.key_id = rx_data[0];
	copy_to_user((void __user *)arg, &gen_key, sizeof(gen_key));

	return 0;
}

static int sm2_export_key(struct csgdx_data *csgdx, unsigned long arg)
{
	int ret=0;
	u8 tx_data[4] = {0,0,0x1,0};//导出公钥
	struct csgdx_ioc_export_key key;
	struct dl_cmd_reserve dcr = {
		.cla = 0x81,
		.ins = 0x5E,
		.p1 = 0,
		.p2 = 0,
	};

	copy_from_user(&key, (void __user *)arg, sizeof(key));
	if(key.key_id > 4) {
		pr_err("sm2_export_key user argc fail! key_id %d\n", key.key_id);
		return ret;
	}

	tx_data[1] = key.key_id;
	ret = msg_transfer(csgdx, &dcr, tx_data, sizeof(tx_data), key.pub_key, 64);
	if(ret) {
		pr_err("sm2_export_key msg_transfer fail! ret %d\n", ret);
		return ret;
	}

	csgdx_dbg("sm2_export_key key_id %d, key_len %d:\n", key.key_id, 64);
	msg_show((u8*)&key, 64);
	copy_to_user((void __user *)arg, &key, sizeof(key));

	return 0;
}

static int sm2_encrypt(struct csgdx_data *csgdx, unsigned long arg)
{
	int ret=0, txbuf_len, rxbuf_len, count=0, key_id, src_data_len;
	u8 *txbuf, *src_data, *encrypt_data;
	struct csgdx_ioc_encrypt *tmp;
	struct dl_cmd_reserve dcr = {
		.cla = 0x81,
		.ins = 0x64,
		.p1 = 0,
		.p2 = 0,
	};

	tmp = (struct csgdx_ioc_encrypt __user*)arg;
	if(!tmp->src || !tmp->encrypt || tmp->src_len > SOURCE_DATA_LENGTH ||
		tmp->encrypt_len> ENCRYPT_DATA_LENGTH || tmp->key_id > KEY_ID_MAX) {
		pr_err("sm2_encrypt user para error!");
		return -1;
	}

	src_data = csgdx->source_buffer;
	encrypt_data = csgdx->encrypt_buffer;
	key_id = tmp->key_id;
	src_data_len = tmp->src_len;
	copy_from_user(src_data, tmp->src, src_data_len);

	txbuf_len = 8 + src_data_len;
	rxbuf_len = 96 + src_data_len;
	txbuf = csgdx->transfer_buffer;
	*txbuf = key_id;
	*(u32*)(txbuf+4) = cpu_to_le32(src_data_len);

	count=0;
	while(count < src_data_len) {
		*(u32*)(txbuf+8+count) = le32_to_cpu(*(u32*)(src_data+count));
		count+=sizeof(u32);
	};

	ret = msg_transfer(csgdx, &dcr, txbuf, txbuf_len, encrypt_data, rxbuf_len);
	if(ret) {
		pr_err("sm2_encrypt msg_transfer fail! ret %d\n", ret);
		return ret;
	}

	count = 0;
	while(count < rxbuf_len) {
		*(u32*)(encrypt_data+count) = le32_to_cpu(*(u32*)(encrypt_data+count));
		count+=sizeof(u32);
	};

	csgdx_dbg("sm2_encrypt key_id %d len %d txbuf:\n", key_id, txbuf_len);
	msg_show(txbuf, txbuf_len);
	csgdx_dbg("sm2_encrypt %d rxbuf:\n", rxbuf_len);
	msg_show(encrypt_data, rxbuf_len);
	copy_to_user(tmp->encrypt, encrypt_data, rxbuf_len);

	return ret;
}

static int sm2_decrypt(struct csgdx_data *csgdx, unsigned long arg)
{
	int ret=0, txbuf_len, rxbuf_len, count=0, key_id, encrypt_data_len;
	u8 *txbuf, *encrypt_data, *decrypt_data;
	struct csgdx_ioc_decrypt *tmp;
	struct dl_cmd_reserve dcr = {
		.cla = 0x81,
		.ins = 0x66,
		.p1 = 0,
		.p2 = 0,
	};

	tmp = (struct csgdx_ioc_decrypt __user*)arg;
	if(!tmp->encrypt || !tmp->decrypt || tmp->encrypt_len < KEY_MAX_LEN || tmp->key_id > KEY_ID_MAX) {
		pr_err("sm2_decrypt argv error!");
		return -1;
	}

	key_id = tmp->key_id;
	encrypt_data_len = tmp->encrypt_len;
	encrypt_data = csgdx->encrypt_buffer;
	decrypt_data = csgdx->decrypt_buffer;
	copy_from_user(encrypt_data, tmp->encrypt, encrypt_data_len);

	txbuf_len = 8 + encrypt_data_len;
	rxbuf_len = encrypt_data_len - KEY_MAX_LEN;
	txbuf = csgdx->transfer_buffer;
	*txbuf = key_id;
	*(u32*)(txbuf+4) = cpu_to_le32(encrypt_data_len);

	count=0;
	while(count < encrypt_data_len) {
		*(u32*)(txbuf+8+count) = le32_to_cpu(*(u32*)(encrypt_data+count));
		count+=sizeof(u32);
	};

	ret = msg_transfer(csgdx, &dcr, txbuf, txbuf_len, decrypt_data, rxbuf_len);
	if(ret) {
		pr_err("sm2_decrypt msg_transfer fail! ret %d\n", ret);
		return ret;
	}

	count = 0;
	while(count < rxbuf_len) {
		*(u32*)(decrypt_data+count) = le32_to_cpu(*(u32*)(decrypt_data+count));
		count+=sizeof(u32);
	};

	csgdx_dbg("sm2_decrypt %d txbuf:\n", txbuf_len);
	msg_show(txbuf, txbuf_len);
	csgdx_dbg("sm2_decrypt %d rxbuf:\n", rxbuf_len);
	msg_show(decrypt_data, rxbuf_len);
	copy_to_user(tmp->decrypt, decrypt_data, rxbuf_len);

	return ret;
}

static int csgdx_open(struct inode *inode, struct file *filp)
{
	struct csgdx_data *csgdx;

	csgdx = container_of(inode->i_cdev, struct csgdx_data, cdev);
	if(!csgdx) {
		pr_err("container_of struct csgdx_data fail!\n");
		return -1;
	}

	if(!csgdx->spi) {
		pr_err("data->spi null!\n");
		return -1;
	}

	if( !csgdx->spi->master) {
		pr_err("data->spi->master null!\n");
		return -1;
	}

	filp->private_data = csgdx;

	return 0;
}

static int csgdx_release(struct inode *inode, struct file *filp)
{
	csgdx_dbg("csgdx_release!\n");
	return 0;
}

static ssize_t
csgdx_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *f_pos)
{
	csgdx_dbg("csgdx_write nothing to do!\n");
	return 0;
}

static ssize_t
csgdx_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	csgdx_dbg("csgdx_read nothing to do!\n");
	return 0;
}

static long
csgdx_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct csgdx_data *csgdx;

	csgdx = (struct csgdx_data *)filp->private_data;
	if(!csgdx) {
		pr_err("csgdx_ioctl filp->private csgdx_data null!\n");
		return -1;
	}

	if((void*)arg == NULL) {
		pr_err("csgdx_ioctl arg null!\n");
		return -1;
	}

	mutex_lock(&csgdx->buf_lock);
	switch (cmd) {
		case CSGDX_IOC_VERSION:
			ret = msg_version(csgdx, arg);
			break;
		case CSGDX_IOC_SM2_GEN_KEY:
			ret = sm2_gen_key(csgdx, arg);
			break;
		case CSGDX_IOC_SM2_EXPORT_KEY:
			ret = sm2_export_key(csgdx, arg);
			break;
		case CSGDX_IOC_SM2_ENCRYPT:
			ret = sm2_encrypt(csgdx, arg);
			break;
		case CSGDX_IOC_SM2_DECRYPT:
			ret = sm2_decrypt(csgdx, arg);
			break;
		default:
			pr_err("warning: unkown cmd 0x%x\n", cmd);
			ret = -1;
			break;
	};
	mutex_unlock(&csgdx->buf_lock);

	return ret;
}

#ifdef CONFIG_COMPAT
static long
csgdx_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return csgdx_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#else
#define csgdx_compat_ioctl NULL
#endif /* CONFIG_COMPAT */

static const struct file_operations csgdx_fops = {
	.owner =	THIS_MODULE,
	/* REVISIT switch to aio primitives, so that userspace
	 * gets more complete API coverage.  It'll simplify things
	 * too, except for the locking.
	 */
	.write =	csgdx_write,
	.read =		csgdx_read,
	.unlocked_ioctl = csgdx_ioctl,
	.compat_ioctl = csgdx_compat_ioctl,
	.open =		csgdx_open,
	.release =	csgdx_release,
	.llseek =	no_llseek,
};

static struct csgdx_data *csgdx_alloc(struct spi_device *spi)
{
	struct csgdx_data *csgdx;
	csgdx = kzalloc(sizeof(*csgdx), GFP_KERNEL);
	if (!csgdx) {
		dev_err(&spi->dev, "no memory for private data\n");
		return NULL;
	}

	csgdx->tx_buffer = kzalloc(PACKET_LENGTH, GFP_KERNEL);
	if (!csgdx->tx_buffer) {
		dev_err(&spi->dev, "kzalloc tx_buffer failed\n");
		goto free_tx_buf;
	}

	csgdx->rx_buffer = kzalloc(PACKET_LENGTH, GFP_KERNEL);
	if (!csgdx->rx_buffer) {
		dev_err(&spi->dev, "kzalloc rx_buffer failed\n");
		goto free_rx_buf;
	}

	csgdx->encrypt_buffer = kzalloc(ENCRYPT_DATA_LENGTH, GFP_KERNEL);
	if (!csgdx->encrypt_buffer) {
		dev_err(&spi->dev, "kzalloc encrypt_buffer failed\n");
		goto free_encrypt_buffer;
	}

	csgdx->decrypt_buffer = kzalloc(DECRYPT_DATA_LENGTH, GFP_KERNEL);
	if (!csgdx->decrypt_buffer) {
		dev_err(&spi->dev, "kzalloc decrypt_buffer failed\n");
		goto free_decrypt_buffer;
	}

	csgdx->source_buffer = kzalloc(SOURCE_DATA_LENGTH, GFP_KERNEL);
	if (!csgdx->source_buffer) {
		dev_err(&spi->dev, "kzalloc source_buffer failed\n");
		goto free_source_buffer;
	}

	csgdx->transfer_buffer = kzalloc(TRANSFER_BUF_LEN, GFP_KERNEL);
	if (!csgdx->transfer_buffer) {
		dev_err(&spi->dev, "kzalloc transfer_buffer failed\n");
		goto free_transfer_buffer;
	}

	return csgdx;

free_transfer_buffer:
	kfree(csgdx->transfer_buffer);
free_source_buffer:
	kfree(csgdx->source_buffer);
free_decrypt_buffer:
	kfree(csgdx->decrypt_buffer);
free_encrypt_buffer:
	kfree(csgdx->encrypt_buffer);
free_rx_buf:
	kfree(csgdx->rx_buffer);
free_tx_buf:
	kfree(csgdx->tx_buffer);
	kfree(csgdx);
	return NULL;
}

static void csgdx_free(struct spi_device *spi)
{
	struct csgdx_data *csgdx;
	csgdx = dev_get_drvdata(&spi->dev);
	kfree(csgdx->transfer_buffer);
	kfree(csgdx->source_buffer);
	kfree(csgdx->decrypt_buffer);
	kfree(csgdx->encrypt_buffer);
	kfree(csgdx->tx_buffer);
	kfree(csgdx->rx_buffer);
	kfree(csgdx);
	return;
}

static int __devinit csgdx_probe(struct spi_device *spi)
{
	struct device *dev;
	struct csgdx_data *csgdx;
	int	err = 0;

	pr_info(KERN_INFO DRV_DESC " version " DRV_VERSION " driver " DRV_NAME "\n");

	csgdx = csgdx_alloc(spi);
	if (!csgdx) {
		pr_err("csgdx_alloc fail!\n");
		return -1;;
	}

	mutex_init(&csgdx->buf_lock);
	spin_lock_init(&csgdx->spi_lock);
	spi->bits_per_word = 8;
	csgdx->spi = spi;
	spi_set_drvdata(spi, csgdx);

	err = alloc_chrdev_region(&csgdx_dev_t, CSGDX_BASE_MINOR, CSGDX_MINOR_CNT, "csgdx");
	if (err < 0) {
		pr_err("alloc_chrdev_region fail!\n");
		goto free_data;
	}

	cdev_init(&csgdx->cdev, &csgdx_fops);
	err = cdev_add(&csgdx->cdev, csgdx_dev_t, CSGDX_MINOR_CNT);
	if (err < 0) {
		pr_err("cdev_add fail!\n");
		goto unregister_chardev;
	}

	csgdx_class = class_create(THIS_MODULE, "csgdx");
	if (IS_ERR(csgdx_class)) {
		pr_err("class_create fail!\n");
		goto unregister_chardev;
	}

	dev = device_create(csgdx_class, &spi->dev, csgdx_dev_t,
				csgdx, "csgdx%d.%d",
				spi->master->bus_num, spi->chip_select);
	err = IS_ERR(dev) ? PTR_ERR(dev) : 0;
	if (err) {
		dev_err(&spi->dev, "spi_setup failed, err=%d\n", err);
		goto destory_class;
	}

	return 0;

destory_class:
	class_destroy(csgdx_class);
unregister_chardev:
	unregister_chrdev_region(csgdx_dev_t ,CSGDX_MINOR_CNT);
free_data:
	csgdx_free(spi);
	dev_set_drvdata(&spi->dev, NULL);
	return err;
}

static int __devexit csgdx_remove(struct spi_device *spi)
{
	csgdx_free(spi);
	dev_set_drvdata(&spi->dev, NULL);

	device_destroy(csgdx_class, csgdx_dev_t);
	class_destroy(csgdx_class);
	return 0;
}

static struct spi_driver csgdx_driver = {
	.driver = {
		.name		= DRV_NAME,
		.bus		= &spi_bus_type,
		.owner		= THIS_MODULE,
	},
	.probe		= csgdx_probe,
	.remove		= __devexit_p(csgdx_remove),
};

static int __init csgdx_init(void)
{
	int status;

	status = spi_register_driver(&csgdx_driver);
	if (status < 0) {
		pr_err("spi_register_driver fail!");
	}

	pr_info("csgdx_init spi_register_driver success!\n");
	return status;
}
module_init(csgdx_init);

static void __exit csgdx_exit(void)
{
	pr_info("csgdx_exit spi_unregister_driver!\n");
	spi_unregister_driver(&csgdx_driver);
}
module_exit(csgdx_exit);


MODULE_DESCRIPTION(DRV_DESC);
MODULE_VERSION(DRV_VERSION);
MODULE_AUTHOR("Hakim <751244340@qq.com>");
MODULE_LICENSE("GPL v2");

