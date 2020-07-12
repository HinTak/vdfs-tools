#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <vdfs_tools.h>
#include <getopt.h>

#define ARRAY_SIZE(x) (sizeof((x))/sizeof((x)[0]))

enum {
	opt_help		= 'h',
	opt_crc_exist		= 'x',
	opt_find_bitflip	= 'b',
};

const char *short_opts = "hxb::";
struct option long_opts[] = {
	{"help",		no_argument,		NULL, opt_help},
	{"crc-exist",		no_argument,		NULL, opt_crc_exist},
	{"find-bitflip",	optional_argument,	NULL, opt_find_bitflip},
	{NULL, 0, NULL, 0}
};

struct {
	unsigned char crc_exist;
	unsigned char find_bitflip;
	unsigned int crc;
} param = {false, false, 0};

static void usage(void)
{
	unsigned int i;
	const char *usage_msg[] = {
		"DESCRIPTION\n",
		"\tvdcrc32 - A program to calculate a CRC of a file.\n",
		"SYNOPSIS\n",
		"\tvdcrc32 [OPTIONS]... [FILE]\n",
		"OPTIONS\n",
		"\t-x, --crc-exist\n",
		"\t\tIf there is crc at the end of file.\n",
		"\t-b[0xXXXXXXXX], --crc-exist[=0xXXXXXXXX]\n",
		"\t\tTest by changing bit one by one.\n",
		"\t\tIf '-x, --crc-exist' is not given, "
			"the crc value for comparison must be passed.\n",
	};

	for (i = 0; i < ARRAY_SIZE(usage_msg); i++)
		printf("%s", usage_msg[i]);
	printf("\n");
}

static size_t get_filesize(const char * file_name)
{
	struct stat sb;
	if (stat(file_name, &sb) != 0) {
		fprintf(stderr, "'stat' failed for '%s': %s.\n",
			file_name, strerror(errno));
		return -1;
	}
	return sb.st_size;
}

int main(int argc, char **argv)
{
	int fd = 0, rtn=0;
	int opt=0, opt_idx=0;
	size_t filesize=0, readsize=0, datasize=0;
	unsigned char *filename=NULL, *buffer = NULL;
	unsigned int calc_crc=0, read_crc=0;
	unsigned int i, j;

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, &opt_idx))
	       != EOF && !rtn) {
		switch (opt) {
		case opt_help:
			usage();
			goto exit;
			break;
		case opt_crc_exist:
			param.crc_exist = true;
			break;
		case opt_find_bitflip:
			param.find_bitflip = true;
			if (optarg)
				sscanf(optarg, "%i", &param.crc);
			break;
		default:
			rtn = -EINVAL;
			usage();
			goto exit;
		}
	}

	/* set file name */
	filename = argv[optind];
	if (!filename) {
		printf("Invalid filename option.\n");
		rtn = -EINVAL;
		goto exit;
	}

	/* Parameter Check */
	if (param.find_bitflip == true &&
	    ((param.crc_exist == false && param.crc == 0) ||
	     (param.crc_exist == true && param.crc != 0))) {
		printf("Invalid option.\n");
		rtn = -EINVAL;
		goto exit;
	}

	/* Read data from file */
	if ((filesize = get_filesize(filename)) == -1) {
		rtn = -1;
		goto exit;
	}

	if ((buffer = (unsigned char*)malloc(filesize)) == NULL) {
		fprintf(stderr, "'malloc' failed for '%s'\n",
			strerror(errno));
		rtn = -1;
		goto exit;
	}

	if ((fd=open(filename, O_RDONLY)) == -1) {
		fprintf(stderr, "'open' error for '%s'\n",
			strerror(errno));
		rtn = -1;
		goto mem_alloc;
	}

	if ((readsize=read(fd, buffer, filesize)) != filesize) {
		fprintf(stderr, "'read' error for '%s'."
			" filesize:%zu but readsize:%zu\n",
			strerror(errno), filesize, readsize);
		rtn = -1;
		goto file_open;
	}

	datasize = filesize;
	if (param.crc_exist == true) {
		datasize -= 4; /* decrease crc(4byte) size */
		read_crc = *(unsigned int*)(buffer + datasize);
	}

	/* Calculate CRC */
	calc_crc = vdfs4_crc32(buffer, datasize);

	/* Output calculation result */
	printf("File Information\n");
	printf(" |- name : %s\n", filename);
	printf(" `- size : %lu KiB (%lu B)\n", filesize / 1024, filesize);
	printf("Calc CRC : 0x%08X\n", calc_crc);
	if (param.crc_exist)
		printf("Read CRC : 0x%08X\n", read_crc);

	if (!param.find_bitflip)
		goto file_open; /* exit */

	if (param.crc_exist && read_crc == calc_crc) {
		printf("Calculated crc is equal as given crc.\n");
		goto file_open; /* exit */
	}

	if (!param.crc_exist && param.crc == calc_crc) {
		printf("Calculated crc is equal as given crc.\n");
		goto file_open; /* exit */
	}

	if (param.crc_exist)
		param.crc = read_crc;

	printf("CRC is mismatch. Start to find bitflip...!!\n");
	for (i = 0; i < datasize; i++) {
		for (j = 0; j < 8; j++) {
			buffer[i] ^= (0x1 << j);
			calc_crc = vdfs4_crc32(buffer, datasize);
			if (calc_crc == param.crc) {
				printf("\tBitflip Found.!!(offset:0x%X.%u)\n",
				       i, j);
				goto file_open;
			}
			buffer[i] ^= (0x1 << j);
		}
	}
	printf("Can not find bitflip position...!!\n");

file_open:
	close(fd);
mem_alloc:
	free(buffer);
exit:
	return rtn;
}
