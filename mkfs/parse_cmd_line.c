/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2012 by Samsung Electronics, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "mkfs.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errors.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

/**
 * @brief	Print mkfs.vdfs4 usage options. Shown in case of wrong parameters.
 * @return  void
 */
void usage(void)
{
	/* TODO: add version print when version format will be selected */
	printf("Usage: mkfs.vdfs4 [options] device_name or image_name\n"\
	"Possible options are:\n"\
	"-i or --image-creation\n"\
	"\tCreate image of filesystem in file.\n"\
	"-n or --simulate-creation\n"\
	"\tSimulate only, do not perform actual disk operations.\n"\
	"-e size or --erase-block-size=size\n"\
	"\tErase block size in bytes.\n"\
	"-t timestamp or --timestamp=timestamp\n"\
	"\tCurrent time for filesystem objects in nanoseconds"\
		" since POSIX epoch\n"\
	"-z size or --image-size=size or --image-size=min_size:max_size\n"\
	"\tSpecify size of filesystem image in bytes.\n"
	"\tUsable only in image"\
	"creation mode.\n"\
	"\tBy default if this option is not specified mkfs creates compact\n"\
	"\tread-only image with data placed to the start of volume.\n"\
	"\tNOTE: You may use multipliers K, M, G for size parameter.\n"\
	"\tIf size is min:max range filesystem will be ready to work\n"\
	"\ton disk within this range and automatically expand at first mount\n"\
	"--no-strip\n"\
	"\tDon't strip image. Usable only in image creation mode.\n"\
	"\tBy default mkfs creates compact image with data placed "\
	"to the start of volume\n"\
	"-r root_dir or --root-dir root_dir\n"\
	"\tImage root directory\n"\
	"-q filename or --squash_images_list=filename\n"\
	"\tExpand and install into image all squashfs images "\
	"listed in file \"filename\".\n"
	"\n"
	"Additional options:\n"\
	"-d filename or --dump=filename\n"\
	"\tDump all filesystem objects to specified file.\n"\
	"-S or --case-insensitive\n"\
	"\tMake case-insensitive filesystem.\n"\
	"-m value or --metadata-size value\n"\
	"\tMaximum metadata size in bytes or percents,"\
	"\tused for journal size expanding.\n"\
	"\tSummary metadata space may differ from this parameter.\n"\
	"-v or --verbose\n"\
	"\tVerbose mode of execution.\n"\
	"-a or --super_page_size\n"\
	"\tAligns metadata to superpage size.\n"\
	"--no-all-root set permissions from src objects\n"\
	"\tSet root owner and group for all objects in image creation\n"\
	"\n"\
	"NOTE: You may use multipliers K, M, G for size parameters\n"\
	"\n"\
	"-q config_file\n"\
	"\tConfig file contains a list of files"\
	" that must be compressed with zlib/gzip/lzo compression types\n"
	"-H rsa-key\n"
	"\tPrivate rsa key for superblock and tuned files signing\n"
	"-H rsa-private-key-exponent -P rsa-pub-key-modulus\n"
	"\tSign superblock and files inside of volume by rsa key from special"
	"files pair (private exponent and public modulus)\n"
	"-T tmpfs directory path\n"
	"\tset directory for mkfs temporary files (default - /tmp)\n"
	"-H rsa-private-key-exponent -P rsa-pub-key-modulus -p prime1 -Q prime2\n"
	"\tSign superblock and files inside of volume by rsa key from special"
	"files (private exponent, public modulus, prime1, prime2)\n"
	"-A - sign all files by rsa/sha1(sha256)\n"
	"--sha256 - select SHA256 algorithm for hash calculation\n(has sense only"
	"when -H option is specified); default algorithm is MD5\n"
	"--sha1 - select SHA1 algorithm for hash calculation\n(has sense only"
	"when -H option is specified); default algorithm is MD5\n"
	"--min-comp-size\n"
	"\tAllows to specify minimum size in bytes of file to be"
	"compressed. Files smaller than specified size won't be compressed.\n"
	"\tIf not set, default is 8kB. This option does not work on ELF files "
	"which are always compressed\n"
	"--compress-elf\n"
	"\tForces to all chunks of tuned ELF files to be always "
	"compressed. NOTE: this might reduce tuned file chunk size.\n"
	"--encrypt-elf\n"
	"\tCauses to encrypt all compressed ELF files (option -E must be given).\n"
	"--encrypt-all\n"
	"\tCauses to encrypt all compressed files (option -E must be given).\n"
	"--force-compr-encrypted\n"
	"\tEnsures that all data of encrypted files will be also compressed.\n"
	"\tNote: use this on platforms that cannot decrypt non-compressed data.\n"
	"-E or --aes-key\n"
	"\tSet path to file containing AES encryption key. "
	" Key must consist of 16 bytes of binary data.\n"
	"-D or --prof-data\n"
	"\tSet path to file containing profiling data file.\n"
	"\n"
	);
	config_file_format();
}

/**
 * @brief	Read numeric value from utility's parameter, parse
 *		and apply data size multipliers (K, M, G) and apply them to
 *		final value if set.
 * @param [in]  value	Parameter string with numeric value to be parsed
 * @return		Returns 64-bit integer value converted from string with
 *			multiplier applied
 */
u_int64_t read_value_with_multiplier(const char *value)
{
	u_int32_t multiplyer;
	u_int32_t value_len;
	u_int64_t value_dec;
	char	*value_dup;

	value_dup = strdup(value);
	assert(value_dup);
	value_len = strlen(value_dup);
	switch (value_dup[value_len - 1]) {
	case 'K':
		multiplyer = 1 << 10;
		break;
	case 'M':
		multiplyer = 1 << 20;
		break;
	case 'G':
		multiplyer = 1 << 30;
		break;
	default:
		multiplyer = 1;
	}

	/* mask multiplyer letter in value */
	value_dup[value_len - 1] = 0;

	value_dec = atoll(value);
	free(value_dup);
	return (u_int64_t)(value_dec * multiplyer);
}

static int read_image_size(struct vdfs4_sb_info *sbi, char *value)
{
	char *sep = strchr(value, ':');

	if (sep) {
		*sep = 0;
		sbi->min_image_size = read_value_with_multiplier(value);
		sbi->image_size = read_value_with_multiplier(sep + 1);
		*sep = ':';
	} else {
		sbi->image_size = read_value_with_multiplier(value);
		sbi->min_image_size = sbi->image_size;
	}

	if (sbi->min_image_size > sbi->image_size) {
		log_error("Minimal image size is more than maximum");
		return -EWRONGOPTS;
	}

	return 0;
}

/**
 * @brief       Parse parameters from mkfs.vdfs4 run command line.
 * @param [in]  argc	Number of command line parameters.
 * @param [in]	argv[]	An array with command line parameters strings.
 * @param [in]	sbi		A pointer to the structure containing runtime
			parameters of vdfs4 superblock.
 * @return  0 if parced successfully, or error
 */
int parse_cmd(int argc, char *argv[], struct vdfs4_sb_info *sbi)
{
	const char *short_options = "e:b:invd:o:z:t:r:sSm:a:fq:H:P:p:Q:T:AE:D:";
	const struct option long_options[] = {
		{"erase-block-size",	required_argument,	NULL, 'e'},
		{"block-size",		required_argument,	NULL, 'b'},
		{"image-creation",	no_argument,		NULL, 'i'},
		{"simulate",		no_argument,		NULL, 'n'},
		{"verbose",		no_argument,		NULL, 'v'},
		{"dump",		required_argument,	NULL, 'd'},
		{"image-size",		required_argument,	NULL, 'z'},
		{"timestamp",		required_argument,	NULL, 't'},
		{"root-dir",		required_argument,	NULL, 'r'},
		{"no-strip",		no_argument,		NULL, '0'},
		{"strip",		no_argument,		NULL, 's'},
		{"case-insensitive",	no_argument,		NULL, 'S'},
		{"metadata-size",	required_argument,	NULL, 'm'},
		{"super_page_size",	required_argument,	NULL, 'a'},
		{"cmd_list",		required_argument,	NULL, 'q'},
		{"no-all-root",		no_argument,		NULL, '1'},
		{"all-root",		no_argument,		NULL, 'R'},
		{"read-only",		no_argument,		NULL, '2'},
		{"hash-priv-rsa-key",	required_argument,	NULL, 'H'},
		{"pub-rsa-key",		required_argument,	NULL, 'P'},
		{"tmpfs-dir",		required_argument,	NULL, 'T'},
		{"p-rsa-key",		required_argument,	NULL, 'p'},
		{"q-rsa-key",		required_argument,	NULL, 'Q'},
		{"auth-all",		required_argument,	NULL, 'A'},
		{"sha256",		no_argument,		NULL, '3'},
		{"sha1",		no_argument,		NULL, '4'},
		{"min-comp-size",	required_argument, 	NULL, '#'},
		{"aes-key",			required_argument,	NULL, 'E'},
		{"encrypt-elf",		no_argument,	NULL, '5'},
		{"encrypt-all",		no_argument,	NULL, '6'},
		{"force-compr-encrypted", no_argument,	NULL, '7'},
		{"prof-data",		required_argument,	NULL, 'D'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0;
	int long_index = 0;
	int ret_code = 0;
	int block_size;
	sbi->min_compressed_size = -1;

	while ((opt = getopt_long(argc, argv,
		short_options, long_options, &long_index)) != EOF) {
		switch (opt) {
		case 'b':
			if (!optarg) {
				log_error("Block size is not set");
				return -EWRONGOPTS;
			}
			block_size = atoi(optarg);
			sbi->log_chunk_size = slog(block_size);
			break;
		case 'i':
			SET_FLAG(sbi->service_flags, IMAGE);
			break;
		case 'n':
			SET_FLAG(sbi->service_flags, SIMULATE);
			break;
		case 'e':
			sbi->log_erase_block_size =
				log2_32(read_value_with_multiplier(optarg));
			break;
		case 'v':
			SET_FLAG(sbi->service_flags, VERBOSE);
			set_logger_verbosity(LOG_ALL);
			break;
		case 'd':
			if (sbi->dump_file != NULL) {
				log_warning("Many -d parameters. "
						"First is used\n");
				break;
			}

			sbi->dump_file = fopen(optarg, "w");
			if (sbi->dump_file == NULL) {
				log_warning("Can't open %s."
				"Dump will not be written", optarg);
				ret_code = -EWRONGOPTS;
			}
			break;
		case 'z':
			ret_code = read_image_size(sbi, optarg);
			if (ret_code)
				return ret_code;
			break;
		case 't':
			sbi->timestamp.seconds = atoll(optarg) /
				NANOSEC_DIVIDER;
			sbi->timestamp.nanoseconds =
				atoll(optarg) % NANOSEC_DIVIDER;
			break;
		case 'r':
			sbi->root_path = optarg;
			break;
		case '1':
			/*no-all-root*/
			break;
		case '0':
			SET_FLAG(sbi->service_flags, NO_STRIP_IMAGE);
			break;
		case '3':
			/*Select SHA256 algorithm for hash calculation;
			 * default - MD5*/
			SET_FLAG(sbi->service_flags, SHA_256);
			break;
		case '4':
			/*Select MD5 algorithm for hash calculation;
			 * default - MD5*/
			SET_FLAG(sbi->service_flags, SHA_1);
			break;
		/*Unused old options: now at default*/
		case '2':
			/*read-only*/
			break;
		case 'R':
			/*all-root*/
			SET_FLAG(sbi->service_flags, ALL_ROOT);
			break;
		case 's':
			/*strip image*/
			break;
		/**********************************/
		case 'S':
			SET_FLAG(sbi->service_flags, CASE_INSENSITIVE);
			break;
		case 'm':
			sbi->metadata_size = read_value_with_multiplier(optarg);
			break;
		case 'a':
			sbi->super_page_size =
				read_value_with_multiplier(optarg);

			if (sbi->super_page_size < MIN_SUPER_PAGE_SIZE ||
					(sbi->super_page_size &
					(sbi->super_page_size - 1))) {
				log_error("Incorrect super_page_size argument");
				ret_code = -EWRONGOPTS;
			}
			break;
		case 'q':
			if (sbi->squash_list_file != NULL) {
				log_warning("Many -q parameters. "
						"First is used\n");
				break;
			}
			sbi->squash_list_file = fopen(optarg, "r");
			if (sbi->squash_list_file == NULL) {
				log_warning("Can't open %s. File with squashfs"
				" images list to install can not be opened",
				optarg);
				ret_code = -EWRONGOPTS;
			}
			break;
		case 'H':
			sbi->rsa_private_file = optarg;
			break;
		case 'P':
			sbi->rsa_public_file = optarg;
			break;
		case 'T':
			sbi->tmpfs_dir = optarg;
			break;
		case 'p':
			sbi->rsa_p_file = optarg;
			break;
		case 'Q':
			sbi->rsa_q_file = optarg;
			break;
		case 'A':
			SET_FLAG(sbi->service_flags, SIGN_ALL);
			break;
		case '#':
			sbi->min_compressed_size = strtol(optarg, NULL, 10);
			if(sbi->min_compressed_size <= 0) {
				log_error("Wrong --min-comp-size paramter passes. Value must be greater than 1");
				ret_code = -EWRONGOPTS;
			}
			log_info("Setting minimum compressed size to %d",
					sbi->min_compressed_size);
			break;
		case 'E':
			if ((ret_code = read_encryption_key(sbi, optarg)))
				log_error("Can't open or use supplied: %s keyfile", optarg);
			break;
		case '5': /* --encrypt-elf */
			log_info("Encrypting all ELF files.");
			SET_FLAG(sbi->service_flags, ENCRYPT_ELF);
			break;
		case '6': /* --encrypt-all */
			log_info("Encrypting all files.");
			SET_FLAG(sbi->service_flags, ENCRYPT_ALL);
			break;
		case '7': /* --force-compr-encrypted */
			log_info("--force-compr-encrypted enabled."
					" All encrypted data will be compressed");
			SET_FLAG(sbi->service_flags, FORCE_COMPR_ENCRYPTED);
			break;
		case 'D':
			sbi->profiling_data_path = optarg;
			break;
		default:
			log_error("Unrecognized option");
			ret_code = -EWRONGOPTS;
			break;
		};
	}
	if (sbi->log_chunk_size == 0)
		sbi->log_chunk_size = 17;

	if (sbi->squash_list_file && !sbi->root_path) {
		log_error("\"-q\" option illegal without \"-r\" option");
		ret_code = -EWRONGOPTS;
	}

	if (sbi->rsa_private_file) {
		sbi->rsa_key = create_rsa(sbi->rsa_private_file,
				sbi->rsa_public_file, sbi->rsa_q_file,
				sbi->rsa_p_file);
		if (!sbi->rsa_key) {
			log_error("Wrong rsa key file");
			return -EWRONGOPTS;
		}
	}

	if (IS_FLAG_SET(sbi->service_flags, SHA_256)) {
		sbi->hash_alg = SHA256;
		sbi->hash_len = VDFS4_SHA256_HASH_LEN;
	} else if (IS_FLAG_SET(sbi->service_flags, SHA_1)) {
		sbi->hash_alg = SHA1;
		sbi->hash_len = VDFS4_SHA1_HASH_LEN;
	} else {
		sbi->hash_alg = MD5;
		sbi->hash_len = VDFS4_MD5_HASH_LEN;
	}

	if(IS_FLAG_SET(sbi->service_flags, ENCRYPT_ELF) ||
	    IS_FLAG_SET(sbi->service_flags, ENCRYPT_ALL)) {
		if(!sbi->aes_key) {
			log_error("Encryption was enabled but AES key was"
					" not supplied with -E option. Please use -E");
			ret_code = -EWRONGOPTS;
		}
	}


	/* If no arguments left after parsing options, we assume
	 *  no disk name was given */
	if ((argc - 1) < optind) {
		log_error("No device or image name given");
		ret_code = -EWRONGOPTS;
	}

	if ((argc - 1) > optind) {
		log_error("Too many options");
		ret_code = -EWRONGOPTS;
	}

	sbi->file_name = argv[optind];

	if (sbi->profiling_data_path) {
		FILE * fp;
		char * line = NULL;
		size_t len = 0;
		ssize_t read;
		unsigned int chunk_count, i;
		char filename[VDFS4_FULL_PATH_LEN];

		fp = fopen(sbi->profiling_data_path, "r");
		if (fp == NULL)
			return -EWRONGOPTS;
		while ((read = getline(&line, &len, fp)) != -1) {
			struct profiled_file* pfile;

			sscanf(line, "%5u %1022s", &chunk_count, filename);
			pfile = malloc(sizeof(struct profiled_file) +
				chunk_count*sizeof(__u16));
			if (!pfile) {
			    fclose(fp);
				free(line);
			    return -ENOMEM;
			}
			pfile->chunk_count = chunk_count;
			pfile->chunk_order = (__u16*)((char *)pfile + sizeof(struct profiled_file));
			strncpy(pfile->path, filename, VDFS4_FULL_PATH_LEN-1);

			for (i = 0; i < chunk_count; i++) {
				read = getline(&line, &len, fp);
				if (read < 0) {
					free(pfile);
					fclose(fp);
					free(line);
					return -EWRONGOPTS;
				}
				sscanf(line, "%5hu", &pfile->chunk_order[i]);
			}
			list_add(&pfile->list, &sbi->prof_data);
		}
		free(line);
		fclose(fp);
	}

	if (ret_code)
		usage();

	return ret_code;
}
