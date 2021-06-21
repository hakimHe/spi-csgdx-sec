#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include "csgdx-sec.h"

static const char *device = "/dev/csgdx2.1";

void user_show(unsigned char* msg, int len)
{
	int i;

	printf("************user msg show: len 0x%02X\n", len);
	for(i = 0; i < len; i++)
    {
		printf("%02X", msg[i]);
    }
	printf("\n");

	return;
}

int main(int argc, char**argv)
{
	int fd;
	struct csgdx_ioc_version ioc_version;
	struct csgdx_ioc_gen_key gen_key;
	struct csgdx_ioc_export_key export_key;
	struct csgdx_ioc_encrypt ioc_encrypt;
	struct csgdx_ioc_decrypt ioc_decrypt;

	printf("hello world! Welcome to OpenWrt!!!\n\n");
	sleep(1);

	fd = open(device, O_RDWR);
	if (fd < 0)
		perror("can't open device");

	read(fd, NULL, 1, 0);
	write(fd, NULL, 1, 0);

	ioctl(fd, CSGDX_IOC_VERSION, &ioc_version);
	printf("user get version %s\n",ioc_version.version);

	gen_key.key_id = 1;
	gen_key.new_or_update = SM2_UPDATE_KEY;
	gen_key.save_2_ram_or_flash = SM2_KEY_SAVE_IN_FLASH;
	ioctl(fd, CSGDX_IOC_SM2_GEN_KEY, &gen_key);

	printf("user get public key:\n");
	export_key.key_id = 1;
	ioctl(fd, CSGDX_IOC_SM2_EXPORT_KEY, &export_key);
	user_show(export_key.pub_key, 64);

	ioc_encrypt.key_id = 1;
	ioc_encrypt.src_len = 32;
	ioc_encrypt.src = malloc(32);
	ioc_encrypt.encrypt = malloc(128);
	ioc_encrypt.encrypt_len = 128;
	memset(ioc_encrypt.src, 0x5a, 32);
	ioctl(fd, CSGDX_IOC_SM2_ENCRYPT, &ioc_encrypt);

	printf("user source data:\n");
	user_show(ioc_encrypt.src, 32);
	printf("after sm2 encrypt, user source data change to:\n");
	user_show(ioc_encrypt.encrypt, 128);

	ioc_decrypt.key_id = 1;
	ioc_decrypt.encrypt_len = 128;
	ioc_decrypt.decrypt_len = 32;
	ioc_decrypt.encrypt = malloc(128);
	ioc_decrypt.decrypt = malloc(32);
	memcpy(ioc_decrypt.encrypt, ioc_encrypt.encrypt, 128);
	ioctl(fd, CSGDX_IOC_SM2_DECRYPT, &ioc_decrypt);

	printf("user encrypt data:\n");
	user_show(ioc_decrypt.encrypt, 128);
	printf("after sm2 decrypt, user encrypt data change to:\n");
	user_show(ioc_decrypt.decrypt, 32);

	if(!memcmp(ioc_encrypt.src, ioc_decrypt.decrypt, 32)) {
		printf("encrypt and decrypt success! sm2 decrypt data is the same as source data!\n");
	}

	close(fd);
	free(ioc_encrypt.src);
	free(ioc_encrypt.encrypt);
	free(ioc_decrypt.decrypt);
	free(ioc_decrypt.encrypt );
	return 0;
}

