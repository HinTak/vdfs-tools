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
#include "rsa_debug_key.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errors.h>
#include <stdbool.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define ARRAY_SIZE(x) (sizeof((x))/sizeof((x)[0])) 

/**
 * @brief	Print mkfs.vdfs4 usage options. Shown in case of wrong parameters.
 * @return  void
 */
void usage(bool expert)
{
	unsigned int i,j;
	const char *basic_opt[] = {
		"usage: mkfs.vdfs filename",
		"[-i,-image-creation] [-r,--root-dir directory] [-z,--image-size size[K|M|G]]",
		"[-c,--compressor gzip|zlib|lzo] [-s,--sign 1024|2048|file] [-h,--hash-type sha256|sha1|md5]",
		"[-v,--verbose] [-V,--Verbose] [--dry-run] [--help] [--version]"};
	const char *basic_desc[][10] = {
		{"-i,-image-creation",
			"enable image creation mode. mkfs create image of filesystem in file."},
		{"-r,--root-dir directory",
			"Image root directory"},
		{"-z,--image-size size or --image-size=min_size:max_size",
			"Specify size of filesystem image in bytes. Usable only in image creation mode.",
			"By default if this option is not specified,",
			"mkfs creates compact read-only image with data placed to the start of volume.",
			"NOTE: You may use multipliers K, M, G for size parameter.",
			"If size is min:max range,",
			"filesystem will be ready to work on disk within this range and automatically expand at first mount"},
		{"-c,--compressor gzip|zlib|lzo",
			"Set compress type."},
		{"-s,--sign 1024|2048|file",
			"sign superblock and tuned files.",
			"if value is 1024,2048, mkfs tool use debug key in binary.",
			"if value is file, mkfs tool use file containing RSA private key.",
			"NOTE: You can specify hash type using '-h,--hash-type' option."},
		{"-h,--hash-type sha256|sha1|md5",
			"select algorithm for hash calculation. Usable only in sign mode (default:sha256)"},
		{"-v,--verbose",
			"Verbose mode of execution."},
		{"-V,--Verbose",
			"Verbose(LOG_ACTIVITY) mode of execution."},
		{"--dry-run",
			"Simulate only, do not perform actual disk operations."},
		{"--help",
			"show detail usage"},
		{"--version",
			"show tool version"},
		};
	const char *expert_opt[] = {
		"[-t,--timestamp nanoseccond] [-e,--erase-block-size size] [--min-space-saving-ratio ratio]",
		"[--min-comp-size size] [--tmp-dir directory] [--chunk-size size] [--case-insensitive]",
		"[--super_page_size size[K|M|G]] [--metadata-size size] [--all-root] [--no-strip]",
		"[--hash-priv-rsa-key file] [--pub-rsa-key file] [--p-rsa-key] [--q-rsa-key] [--sign-all]",
		"[--aes-key] [--encrypt-exec] [--encrypt-all] [--prof-data] [--dump] [-q,--config file]",
		"[--sha256] [--sha1] [--no-all-root]"};
	const char *expert_desc[][10] = {
		{"-t,--timestamp nanoseccond",
			"Current time for filesystem objects in nanoseconds since POSIX epoch"},
		{"-e,--erase-block-size size",
			"Erase block size in bytes."},
		{"--min-space-saving-ratio ratio",
			"Set minimum space saving ratio(0~100) about data compression. Default value is 25.",
			"If space saving ratio in chunks is not more than(<=) given value, the chunk keeps the original.",
			"(if space saving ratio <= given value, keep original. else do compression)"},
		{"--min-comp-size size",
			"Allows to specify minimum size in bytes of file to be compressed. Files smaller than specified size won't be compressed.",
			"If not set, default is 8kB. This option does not work on EXEC files which are always compressed"},
		{"--tmp-dir directory",
			"set directory for mkfs temporary files (default:/tmp)"},
		{"--chunk-size size",
			"Set chunk size in byte(default:128KBytes)"},
		{"--case-insensitive",
			"Make case-insensitive filesystem."},
		{"--super_page_size size[K|M|G]",
			"Aligns metadata to superpage size.",
			"NOTE: You may use multipliers K, M, G for size parameters"},
		{"--metadata-size size",
			"Maximum metadata size in bytes, used for journal size expanding.",
			"Summary metadata space may differ from this parameter."},
		{"--all-root",
			"Set uid and gid of all files to zero(root)"},
		{"--no-strip",
			"Don't strip image. Usable only in image creation mode.",
			"By default mkfs creates compact image with data placed to the start of volume"},
		{"--hash-priv-rsa-key file",
			"Private rsa key for superblock and tuned files signing"},
		{"--pub-rsa-key file",
			"Sign superblock and files inside of volume by rsa key from special files pair (private exponent and public modules)"},
		{"--p-rsa-key prime1 --q-rsa-key prime2",
			"Sign superblock and files inside of volume by rsa key from special files (private exponent, public modules, prime1, prime2)"},
		{"--sign-all",
			"sign all files"},
		{"--aes-key",
			"Set path to file containing AES encryption key. Key must consist of 16 bytes of binary data."},
		{"--encrypt-exec",
			"Causes to encrypt all compressed exec(ELF, PE) files (option '--aes-key' must be given)."},
		{"--encrypt-all",
			"Causes to encrypt all compressed files (option '--aes-key' must be given)."},
		{"--prof-data",
			"Set path to file containing profiling data file."},
		{"--dump",
			"Dump all filesystem objects to specified file."},
		{"-q,--config file",
			"Config file contains a list of files that must be compressed with zlib/gzip/lzo compression types",
			"Tip: In all config files you can use comments by using '#' as first character in line",
			"Config file format:",
			"	COMPRESS=zlib   /dir3/file3",
			"	COMPRESS=lzo    /dir4",
			"	#Force disable file compression:",
			"	#INFO: NOCOMPRESS doesn't affect ELF files",
			"	NOCOMPRESS /dir1/file1"},
		};
	/* print option list */
	for (i = 0; i < ARRAY_SIZE(basic_opt); i++) {
		if (i)
			printf("\t\t");
		printf("%s\n", basic_opt[i]);
	}
	if (expert == true) {
		for (i = 0; i < ARRAY_SIZE(expert_opt); i++)
			printf("\t\t%s\n", expert_opt[i]);
	}
	printf("\n");

	/* print description */
	for (i = 0; i < ARRAY_SIZE(basic_desc); i++) {
		for (j = 0; j < ARRAY_SIZE(basic_desc[i]); j++) {
			if (!basic_desc[i][j])
				break;
			if (j == 0)
				printf("  %s\n", basic_desc[i][j]);
			else
				printf("\t%s\n", basic_desc[i][j]);
		}
	}
	if (expert == true) {
		for (i = 0; i < ARRAY_SIZE(expert_desc); i++) {
			for (j = 0; j < ARRAY_SIZE(expert_desc[i]); j++) {
				if (!expert_desc[i][j])
					break;
				if (j == 0)
					printf("  %s\n", expert_desc[i][j]);
				else
					printf("\t%s\n", expert_desc[i][j]);
			}
		}
	}
	print_version();
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
enum {
	opt_erase_block_size	= 'e',
	opt_image_creation	= 'i',
	opt_verbose		= 'v',
	opt_Verbose		= 'V',
	opt_image_size		= 'z',
	opt_timestamp		= 't',
	opt_root_dir		= 'r',
	opt_config		= 'q',
	opt_compressor		= 'c',
	opt_sign		= 's',
	opt_hash_type		= 'h',
	/* option list without short arg */
	opt_chunk_size		= 1000,
	opt_dry_run,
	opt_dump,
	opt_no_strip,
	opt_case_insensitive,
	opt_metadata_size,
	opt_super_page_size,
	opt_all_root,
	opt_pub_rsa_key,
	opt_tmp_dir,
	opt_p_rsa_key,
	opt_q_rsa_key,
	opt_sign_all,
	opt_min_comp_size,
	opt_aes_key,
	opt_encrypt_exec,
	opt_encrypt_all,
	opt_prof_data,
	opt_min_space_saving_ratio,
	opt_hash_priv_rsa_key,
	opt_help,
	opt_version,
};

int parse_cmd(int argc, char *argv[], struct vdfs4_sb_info *sbi)
{
	const char *short_options = "e:ivVz:t:r:q:c:s:h:";
	const struct option long_options[] = {
		{"erase-block-size",	required_argument,	NULL, opt_erase_block_size},
		{"chunk-size",		required_argument,	NULL, opt_chunk_size},
		{"image-creation",	no_argument,		NULL, opt_image_creation},
		{"dry-run",		no_argument,		NULL, opt_dry_run},
		{"verbose",		no_argument,		NULL, opt_verbose},
		{"Verbose",		no_argument,		NULL, opt_Verbose},
		{"dump",		required_argument,	NULL, opt_dump},
		{"image-size",		required_argument,	NULL, opt_image_size},
		{"timestamp",		required_argument,	NULL, opt_timestamp},
		{"root-dir",		required_argument,	NULL, opt_root_dir},
		{"no-strip",		no_argument,		NULL, opt_no_strip},
		{"case-insensitive",	no_argument,		NULL, opt_case_insensitive},
		{"metadata-size",	required_argument,	NULL, opt_metadata_size},
		{"super_page_size",	required_argument,	NULL, opt_super_page_size},
		{"config",		required_argument,	NULL, opt_config},
		{"all-root",		no_argument,		NULL, opt_all_root},
		{"hash-priv-rsa-key",	required_argument,	NULL, opt_hash_priv_rsa_key},
		{"pub-rsa-key",		required_argument,	NULL, opt_pub_rsa_key},
		{"tmp-dir",		required_argument,	NULL, opt_tmp_dir},
		{"p-rsa-key",		required_argument,	NULL, opt_p_rsa_key},
		{"q-rsa-key",		required_argument,	NULL, opt_q_rsa_key},
		{"sign-all",		required_argument,	NULL, opt_sign_all},
		{"min-comp-size",	required_argument,	NULL, opt_min_comp_size},
		{"aes-key",		required_argument,	NULL, opt_aes_key},
		{"encrypt-exec",		no_argument,		NULL, opt_encrypt_exec},
		{"encrypt-all",		no_argument,		NULL, opt_encrypt_all},
		{"prof-data",		required_argument,	NULL, opt_prof_data},
		{"compressor",		required_argument,	NULL, opt_compressor},
		{"min-space-saving-ratio",	required_argument,	NULL, opt_min_space_saving_ratio},
		{"sign",		required_argument,	NULL, opt_sign},
		{"hash-type",		required_argument,	NULL, opt_hash_type},
		{"help",		no_argument,		NULL, opt_help},
		{"version",		no_argument,		NULL, opt_version},
		{NULL, 0, NULL, 0}
	};
	int opt = 0;
	int long_index = 0;
	int ret_code = 0;
	sbi->min_compressed_size = -1;

	while ((opt = getopt_long(argc, argv,
		short_options, long_options, &long_index)) != EOF) {
		switch (opt) {
		case opt_chunk_size:
			if (!optarg) {
				log_error("chunk size is not set.\n");
				return -EWRONGOPTS;
			}
			if (atoi(optarg) % PAGE_SIZE) {
				log_error("chunk size is invalid. size should be multiple of %d\n", PAGE_SIZE);
				return -EWRONGOPTS;
			}
			sbi->log_chunk_size = slog(atoi(optarg));
			break;
		case opt_image_creation:
			SET_FLAG(sbi->service_flags, IMAGE);
			break;
		case opt_dry_run:
			SET_FLAG(sbi->service_flags, SIMULATE);
			break;
		case opt_erase_block_size:
			sbi->log_erase_block_size =
				log2_32(read_value_with_multiplier(optarg));
			break;
		case opt_verbose:
			SET_FLAG(sbi->service_flags, VERBOSE);
			set_logger_verbosity(LOG_ALL);
			break;
		case opt_Verbose:
			set_logger_verbosity(LOG_ACTIVITY);
			break;
		case opt_dump:
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
		case opt_image_size:
			ret_code = read_image_size(sbi, optarg);
			if (ret_code)
				return ret_code;
			break;
		case opt_timestamp:
			sbi->timestamp.seconds = atoll(optarg) /
				NANOSEC_DIVIDER;
			sbi->timestamp.nanoseconds =
				atoll(optarg) % NANOSEC_DIVIDER;
			break;
		case opt_root_dir:
			sbi->root_path = optarg;
			break;
		case opt_no_strip:
			SET_FLAG(sbi->service_flags, NO_STRIP_IMAGE);
			break;
		case opt_all_root:
			/*all-root*/
			SET_FLAG(sbi->service_flags, ALL_ROOT);
			break;
		/**********************************/
		case opt_case_insensitive:
			SET_FLAG(sbi->service_flags, CASE_INSENSITIVE);
			break;
		case opt_metadata_size:
			sbi->metadata_size = read_value_with_multiplier(optarg);
			break;
		case opt_super_page_size:
			sbi->super_page_size =
				read_value_with_multiplier(optarg);

			if (sbi->super_page_size < MIN_SUPER_PAGE_SIZE ||
					(sbi->super_page_size &
					(sbi->super_page_size - 1))) {
				log_error("Incorrect super_page_size argument");
				ret_code = -EWRONGOPTS;
			}
			break;
		case opt_config:
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
		case opt_hash_priv_rsa_key:
			sbi->rsa_private_file = optarg;
			break;
		case opt_pub_rsa_key:
			sbi->rsa_public_file = optarg;
			break;
		case opt_tmp_dir:
			sbi->tmpfs_dir = optarg;
			break;
		case opt_p_rsa_key:
			sbi->rsa_p_file = optarg;
			break;
		case opt_q_rsa_key:
			sbi->rsa_q_file = optarg;
			break;
		case opt_sign_all:
			SET_FLAG(sbi->service_flags, SIGN_ALL);
			break;
		case opt_min_comp_size:
			sbi->min_compressed_size = strtol(optarg, NULL, 10);
			if(sbi->min_compressed_size <= 0) {
				log_error("Wrong --min-comp-size paramter passes. Value must be greater than 1");
				ret_code = -EWRONGOPTS;
			}
			log_info("Setting minimum compressed size to %d",
					sbi->min_compressed_size);
			break;
		case opt_aes_key:
			if ((ret_code = read_encryption_key(sbi, optarg)))
				log_error("Can't open or use supplied: %s keyfile", optarg);
			break;
		case opt_encrypt_exec: /* --encrypt-exec */
			log_info("Encrypting all EXEC files.");
			SET_FLAG(sbi->service_flags, ENCRYPT_EXEC);
			break;
		case opt_encrypt_all: /* --encrypt-all */
			log_info("Encrypting all files.");
			SET_FLAG(sbi->service_flags, ENCRYPT_ALL);
			break;
		case opt_prof_data:
			sbi->profiling_data_path = optarg;
			break;
		case opt_compressor:
			if (!strncmp(optarg,"gzip",sizeof("gzip"))) {
				sbi->compr_type = optarg;
			} else if (!strncmp(optarg,"zlib",sizeof("zlib"))) {
				sbi->compr_type = optarg;
			} else if (!strncmp(optarg,"lzo",sizeof("lzo"))) {
				sbi->compr_type = optarg;
			} else if (!strncmp(optarg,"uncomp",sizeof("uncomp"))) {
				sbi->compr_type = optarg;
			} else {
				log_error("Invalid Compressor : %s", optarg);
				return -EWRONGOPTS;
			}
			log_info("compressor : %s\n", optarg);
			break;
		case opt_min_space_saving_ratio:
			sbi->min_space_saving_ratio = atoi(optarg);
			if (sbi->min_space_saving_ratio < 0
			    || 100 < sbi->min_space_saving_ratio) {
				log_error("Invalid minimum space saving ratio.(ratio:%d)\n",
					  sbi->min_space_saving_ratio);
				return -EWRONGOPTS;
			}
			break;
		case opt_sign:
			if (atoi(optarg) == 1024||atoi(optarg) == 2048) {
				char *key;
				if (!access(optarg, F_OK)) {
					//equivocal option argument.
					log_error("equivocal option argument."
					" there is file with name of %s.\n",
					optarg);
					return -EWRONGOPTS;
				}
				key = (atoi(optarg) == 1024) ?
					rsa_dbg_key_1024 : rsa_dbg_key_2048;
				sbi->rsa_key = create_rsa_from_private_str(key);
				if (!sbi->rsa_key) {
					log_error("Wrong rsa key");
					return -EWRONGOPTS;
				}
			} else if (!access(optarg, R_OK)) {
				//set key in the file.
				sbi->rsa_private_file = optarg;
			} else {
				log_error("can not read key file(%s)\n",
					optarg);
				return -EWRONGOPTS;
			}
			break;
		case opt_hash_type:
			if (!strncmp(optarg, "sha256", sizeof("sha256"))) {
				SET_FLAG(sbi->service_flags, SHA_256);
			} else if (!strncmp(optarg, "sha1", sizeof("sha1"))) {
				SET_FLAG(sbi->service_flags, SHA_1);
			} else if (!strncmp(optarg, "md5", sizeof("md5"))) {
				SET_FLAG(sbi->service_flags, MD_5);
			} else {
				log_error("Invalid hash algorithm argument(%s)\n",
					optarg);
				return -EWRONGOPTS;
			}
			break;
		case opt_help:
			usage(true);
			exit(0);
			break;
		case opt_version:
			print_version();
			exit(0);
			break;
		default:
			log_error("Unrecognized option");
			ret_code = -EWRONGOPTS;
			break;
		};
	}

	if (sbi->squash_list_file && sbi->compr_type) {
		log_error("Please use '-q config' OR '-c compr_type'.\n");
		return -EWRONGOPTS;
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

	if (IS_FLAG_SET(sbi->service_flags, MD_5)) {
		sbi->hash_alg = MD5;
		sbi->hash_len = VDFS4_MD5_HASH_LEN;
	} else if (IS_FLAG_SET(sbi->service_flags, SHA_1)) {
		sbi->hash_alg = SHA1;
		sbi->hash_len = VDFS4_SHA1_HASH_LEN;
	} else {
		//sha256 is default hash algorithm in vdfs
		sbi->hash_alg = SHA256;
		sbi->hash_len = VDFS4_SHA256_HASH_LEN;
	}

	if(IS_FLAG_SET(sbi->service_flags, ENCRYPT_EXEC) ||
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
		int ret = 0;

		fp = fopen(sbi->profiling_data_path, "r");
		if (fp == NULL) {
			log_error("fopen() fails");
			return -EWRONGOPTS;
		}

		while ((read = getline(&line, &len, fp)) != -1) {
			struct profiled_file* pfile;

			ret = sscanf(line, "%5u %1022s", &chunk_count, filename);

			/*
				if chunk_count, filename is not parsed well or chunk_count is bigger than higher bound
				Worst case assumption : one file with 2G(2097152K) size / 128K (one chunk size) = 16384 chunks
			*/
			if (ret != 2 || chunk_count > 16384) {
				fclose(fp);
				log_error("sscanf() fails (ret:%d, chunk_count:%d)", ret, chunk_count);
				return -EINVAL;
			}

			pfile = malloc(sizeof(struct profiled_file) +
					chunk_count*sizeof(__u16));
			if (!pfile) {
				fclose(fp);
				free(line);
				log_error("malloc() fails");
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
					log_error("getline() fails");
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
		usage(false);

	return ret_code;
}
