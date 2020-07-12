/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2013 by Samsung Electronics, Inc.
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

#ifndef _LINUX_VDFS4_FS_H
#define _LINUX_VDFS4_FS_H

#include <linux/types.h>

/*
 * The VDFS4 filesystem constants/structures
 */
/** crc size in bytes */
#define CRC32_SIZE	4

/** Maximum length of name string of a file/directory */
#define	VDFS4_FILE_NAME_LEN		255
/** Maximum length of full path */
#define VDFS4_FULL_PATH_LEN		1023

/** image created signed with crc */
#define CRC_ENABLED 1
#define CRC_DISABLED 0

#define SECTOR_SIZE		512
#define SECTOR_SIZE_SHIFT	9
#define SECTOR_PER_PAGE		(PAGE_CACHE_SIZE / SECTOR_SIZE)
#define SECTORS_PER_PAGE_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define SECTORS_PER_PAGE	(1 << SECTORS_PER_PAGE_SHIFT)
#define SB_SIZE			(sizeof(struct vdfs4_super_block))
#define SB_SIZE_IN_SECTOR	(SB_SIZE / SECTOR_SIZE)
#define VDFS4_EXSB_SIZE_SECTORS	5
#define VDFS4_EXSB_LEN		(SECTOR_SIZE * VDFS4_EXSB_SIZE_SECTORS)
#define VDFS4_SB_ADDR		0
#define VDFS4_SB_COPY_ADDR	8
#define VDFS4_SB_OFFSET		(VDFS4_SB_ADDR + 2)
#define VDFS4_SB_COPY_OFFSET	(VDFS4_SB_COPY_ADDR + 2)
#define VDFS4_EXSB_OFFSET	(VDFS4_SB_ADDR + 3)
#define VDFS4_EXSB_COPY_OFFSET	(VDFS4_SB_COPY_ADDR + 3)
/** Base super block location in an eMMCFS volume.
 *  First 1024 bytes is reserved area. */
#define VDFS4_RESERVED_AREA_LENGTH		1024

/* Magic Numbers.
 */
#define VDFS4_LAYOUT_VERSION_2006		"2006" /* rsa1024 */
#define VDFS4_LAYOUT_VERSION_2007		"2007"
/* current layout version */
#define VDFS4_LAYOUT_VERSION			VDFS4_LAYOUT_VERSION_2007
	
#define VDFS4_COMPR_LAYOUT_VER_05		0x0005
#define VDFS4_COMPR_LAYOUT_VER_06		0x0006
/* current layout version */
#define VDFS4_COMPR_LAYOUT_VER			VDFS4_COMPR_LAYOUT_VER_06
	
#define VDFS4_COMPR_FILE_DESC_LEN_05	(4*8)
#define VDFS4_COMPR_FILE_DESC_LEN_06	(5*8)
/* current descriptor length (sizeof(struct vdfs4_comp_file_descr)) */
#define VDFS4_COMPR_FILE_DESC_LEN 		VDFS4_COMPR_FILE_DESC_LEN_06

#define VDFS4_SB_SIGNATURE			"VDFS"
#define VDFS4_SB_SIGNATURE_REFORMATTED		"RFMT"
#define VDFS4_SB_VER_MAJOR	1
#define VDFS4_SB_VER_MINOR	0

#define VDFS4_CAT_FOLDER_MAGIC			"rDe"
#define VDFS4_CAT_FILE_MAGIC			"eFr"
#define VDFS4_XATTR_REC_MAGIC			"XAre"
#define VDFS4_SNAPSHOT_BASE_TABLE		"CoWB"
#define VDFS4_SNAPSHOT_EXTENDED_TABLE		"CoWE"
#define VDFS4_META_HASHTABLE			"MeHs"
#define VDFS4_NODE_DESCR_MAGIC			0x644E		/*"dN"*/
#define VDFS4_OOPS_MAGIC			"DBGe"

#define VDFS4_BTREE_HEAD_NODE_MAGIC		"eHND"
#define VDFS4_BTREE_LEAF_NODE_MAGIC		"NDlf"
#define VDFS4_BTREE_INDEX_NODE_MAGIC		"NDin"
#define VDFS4_EXTTREE_KEY_MAGIC			"ExtK"
#define VDFS4_EXT_OVERFL_LEAF			"NDle"
#define VDFS4_HRDTREE_KEY_MAGIC			"HrdL"

#define VDFS4_CATTREE_ILINK_MAGIC		"ILnk"

#define VDFS4_COMPR_ZIP_FILE_DESCR_MAGIC	"Zip"
#define VDFS4_COMPR_GZIP_FILE_DESCR_MAGIC	"Gzp"
#define VDFS4_COMPR_LZO_FILE_DESCR_MAGIC	"Lzo"
#define VDFS4_COMPR_DESCR_START			'C'
#define VDFS4_MD5_AUTH				'I'
#define VDFS4_SHA1_AUTH				'H'
#define VDFS4_SHA256_AUTH			'h'
#define VDFS4_COMPR_EXT_MAGIC			"XT"
#define VDFS4_COMPR_NON_SQUEEZE			0xFFFF

enum sign_type {
	VDFS4_SIGN_NONE = 0x0,
	VDFS4_SIGN_RSA1024 = 0x1,
	VDFS4_SIGN_RSA2048 = 0x2,
	VDFS4_SIGN_MAX,
};

#define VERSION_SIZE				(sizeof(u64))
#define VDFS4_MOUNT_COUNT(version)	(0xffffffff & (__u32)(version >> 32))
#define VDFS4_SYNC_COUNT(version)	(0xffffffff & (__u32)version)

/* inode bitmap magics and crcs*/
#define INODE_BITMAP_MAGIC "inob"
#define INODE_BITMAP_MAGIC_LEN (sizeof(INODE_BITMAP_MAGIC) - 1 + VERSION_SIZE)

/* fsm bitmap magics and crcs*/
#define FSM_BMP_MAGIC		"fsmb"
#define FSM_BMP_MAGIC_LEN	(sizeof(FSM_BMP_MAGIC) - 1 + VERSION_SIZE)

/* return offset of the crc number in buffer */
#define VDFS4_CRC32_OFFSET(buff, block_size)	(buff+(block_size - CRC32_SIZE))
/* real data size of block is block size without signature and crc number */
#define VDFS4_BIT_BLKSIZE(X, MAGIC_LEN)	(((X) -\
		(MAGIC_LEN + CRC32_SIZE))<<3)

#define VDFS4_CHUNK_FLAG_UNCOMPR		0x1
#define VDFS4_CHUNK_FLAG_ENCRYPTED		0x2

#define VDFS4_MD5_HASH_LEN			16
#define VDFS4_SHA1_HASH_LEN			20
#define VDFS4_SHA256_HASH_LEN			32
#define VDFS4_RSA1024_SIGN_LEN			128
#define VDFS4_RSA2048_SIGN_LEN			256
#define VDFS4_MAX_CRYPTED_HASH_LEN		256
#define VDFS4_HW_COMPR_PAGE_PER_CHUNK		32
#define VDFS4_MIN_LOG_CHUNK_SIZE		12
#define VDFS4_MAX_LOG_CHUNK_SIZE		20
#define VDFS4_AES_NONCE_SIZE			8
#define VDFS4_AES_KEY_LENGTH			16
#define VDFS4_AES_CHUNK_ALIGN_LEN		16
#define VDFS4_AES_CHUNK_ALIGN_START		16

/* superblock encryption flags */
#define VDFS4_VOLUME_ENCRYPTED			1

/** Special inodes */
enum special_ino_no {
	VDFS4_ROOTDIR_OBJ_ID = 0,	/** parent_id of root inode */
	VDFS4_ROOT_INO = 1,		/** root inode */
	VDFS4_CAT_TREE_INO,		/** catalog tree inode */
	VDFS4_FSFILE = VDFS4_CAT_TREE_INO,/** First special file */
	VDFS4_SPACE_BITMAP_INO,		/** free space bitmap inode */
	VDFS4_EXTENTS_TREE_INO,		/** inode bitamp inode number */
	VDFS4_FREE_INODE_BITMAP_INO,	/** Free space bitmap inode */
	VDFS4_XATTR_TREE_INO,		/** XAttr tree ino */
	VDFS4_LSFILE = VDFS4_XATTR_TREE_INO,
	VDFS4_SNAPSHOT_INO,
	VDFS4_ORPHAN_INODES_INO,		/** FIXME remove this line breaks fsck*/
	VDFS4_1ST_FILE_INO		/** First file inode */
};

#define VDFS4_ROOTDIR_NAME	"root"

#define VDFS4_SF_NR	(VDFS4_LSFILE - VDFS4_FSFILE + 1)
#define VDFS4_SF_INDEX(x)	(x - VDFS4_FSFILE)


#define VDFS4_XATTR_NAME_MAX_LEN 200
#define VDFS4_XATTR_VAL_MAX_LEN 200

/**
 * @brief	The eMMCFS stores dates in unsigned 64-bit integer seconds and
 *		unsigned 32-bit integer nanoseconds.
 */
struct vdfs4_timespec {
	/** The seconds part of the date */
	__le32	seconds;
	__le32	seconds_high;
	/** The nanoseconds part of the date */
	__le32	nanoseconds;
};

static inline struct vdfs4_timespec vdfs4_encode_time(struct timespec ts)
{
	return (struct vdfs4_timespec) {
		.seconds = cpu_to_le32(ts.tv_sec),
		.seconds_high = cpu_to_le32((u64)ts.tv_sec >> 32),
		.nanoseconds = cpu_to_le32(ts.tv_nsec),
	};
}

static inline struct timespec vdfs4_decode_time(struct vdfs4_timespec ts)
{
	return (struct timespec) {
		.tv_sec = (long)(le32_to_cpu(ts.seconds) +
			((u64)le32_to_cpu(ts.seconds_high) << 32)),
		.tv_nsec = (long)(le32_to_cpu(ts.nanoseconds)),
	};
}

#define DATE_RESOLUTION_IN_NANOSECONDS_ENABLED 1

/**
 * @brief	For each file and folder, eMMCFS maintains a record containing
 *		access permissions.
 */
struct vdfs4_posix_permissions {
	/* File mode        16 |11 8|7  4|3  0| */
	/*                     |_rwx|_rwx|_rwx| */
	__le16 file_mode;			/** File mode */
	__le32 uid;				/** User ID */
	__le32 gid;				/** Group ID */
};

/** Permissions value for user read-write operations allow. */
#define VDFS4_PERMISSIONS_DEFAULT_RW  0x666
/** Permissions value for user read-write-execute operations allow. */
#define VDFS4_PERMISSIONS_DEFAULT_RWX 0x777

/* Flags definition for vdfs4_extent structure */
/** Extent describes information by means of continuous set of LEBs */
#define VDFS4_LEB_EXTENT	0x80
/** Extent describes binary patch which should be apply inside of block or LEB
 * on the offset in bytes from begin */
#define VDFS4_BYTE_PATCH	0x20
/** The information fragment is pre-allocated but not really written yet */
#define VDFS4_PRE_ALLOCATED	0x10

/**
 * @brief	On VDFS4 volume all existed data are described by means of
 *		extents.
 */
struct vdfs4_extent {
	/** start block  */
	__le64	begin;
	/** length in blocks */
	__le64	length;
};

/**
 * @brief	File blocks in catalog tree are described by means extent plus
 *		extent iblock.
 */
struct vdfs4_iextent {
	/** file data location */
	struct vdfs4_extent	extent;
	/** extent start block logical index */
	__le64	iblock;
};

#define VDFS4_SQUEEZE_PRIO_NON_PROFILED 0xFFFF

struct vdfs4_comp_extent {
	union {
		char magic[2];
		__le16 profiled_prio;
	};
	__le16 flags;
	__le32 len_bytes;
	__le64 start;
} __attribute__((packed));

struct vdfs4_comp_file_descr {
	/* new fields are added before magic for easier backward compatibility */
	__u8 reserved[7];
	__u8 sign_type;
	/* from here same as layout 0x0005 */
	char magic[4];
	__le16 extents_num;
	__le16 layout_version;
	__le64 unpacked_size;
	__le32 crc;
	__le32 log_chunk_size;
	__u8 aes_nonce[VDFS4_AES_NONCE_SIZE];
};

/** VDFS4 maintains information about the contents of a file using the
 * vdfs4_fork structure.
 */
#define VDFS4_EXTENTS_COUNT_IN_FORK	9
/**
 * @brief	The VDFS4 fork structure.
 */
struct vdfs4_fork {
	/** The size in bytes of the valid data in the fork */
	__le64			size_in_bytes;
	/** The total number of allocation blocks which is
	 * allocated for file system object under last actual
	 * snapshot in this fork */
	__le64			total_blocks_count;
	/** The set of extents which describe file system
	 * object's blocks placement */
	struct vdfs4_iextent	extents[VDFS4_EXTENTS_COUNT_IN_FORK];
};

/* Snapshots Management */
/** START  ->> SNAPSHOT structuries  -----------------------------------------*/
#define VDFS4_SNAPSHOT_MAX_SIZE (16 * 1024 * 1024)

/* Snapshot tables */
#define VDFS4_SNAPSHOT_EXT_SIZE		4096
#define VDFS4_SNAPSHOT_EXT_TABLES	8
#define VDFS4_SNAPSHOT_BASE_TABLES	2

#define VDFS4_SNAPSHOT_BASE_TABLE		"CoWB"
#define VDFS4_SNAPSHOT_EXTENDED_TABLE		"CoWE"

struct vdfs4_snapshot_descriptor {
	/* signature */
	__u8 signature[4];
	/* sync count */
	__le32 sync_count;
	/* mount count */
	__le64 mount_count;
	/* offset to CRC */
	__le64 checksum_offset;
};

struct vdfs4_base_table {
	/* descriptor: signature, mount count, sync count and checksumm offset*/
	struct vdfs4_snapshot_descriptor descriptor;
	/* last metadata iblock number */
	__le64 last_page_index[VDFS4_SF_NR];
	/* offset into translation tables for special files */
	__le64 translation_table_offsets[VDFS4_SF_NR];
};

struct vdfs4_base_table_record {
	__le64 meta_iblock;
	__le32 sync_count;
	__le32 mount_count;
};

struct vdfs4_extended_record {
	/* special file id */
	__le64 object_id;
	/* object iblock */
	__le64 table_index;
	/* meta iblock */
	__le64 meta_iblock;
};

struct vdfs4_extended_table {
	struct vdfs4_snapshot_descriptor descriptor;
	/* records count in extended table */
	__le32 records_count;
	__le32 pad;
};

struct vdfs4_meta_hashtable {
	/* Signature */
	__u8 signature[4];
	__le32 pad;
	/* Hash table size in bytes */
	__le64 size;
	__le64 hashtable_offsets[VDFS4_SF_NR];
};

/** END  -<< SNAPSHOT structuries  -----------------------------------------*/

/* it is fixed constants, so we can use only digits here */
#define IMAGE_CMD_LENGTH (512 - 4 - 4 - 16 - 16 - 12 - 4)

struct vdfs4_volume_begins {
	/** magic */
	__u8	signature[4];		/* VDFS4 */
	/** vdfs4 layout version **/
	__u8 layout_version[4];
	/* image was created with command line */
	__u8 command_line[IMAGE_CMD_LENGTH];
	/* image creation time, YYYY.MM.DD-hh:mm(16byte) */
	__u8 creation_time[16];
	/* image creater username, (16byte) */
	__u8 user_name[16];
	/* reserved */
	__u8 reserved[12];
	/** Checksum */
	__le32	checksum;
};

/**
 * @brief	The eMMCFS superblock. (+0x200/+0x400)
 */
struct vdfs4_super_block {
	/** magic */
/*000*/ __u8 signature[4];		/* VDFS4 */
	/** vdfs4 layout version **/
	__u8 layout_version[4];

	/* maximum blocks count on volume */
	__le64 maximum_blocks_count;

	/** Creation timestamp */
/*010*/ struct vdfs4_timespec creation_timestamp;

	/** 128-bit uuid for volume */
	__u8 volume_uuid[16];

	/** Volume name */
/*02C*/ char volume_name[16];

	/** The mkfs tool version used to generate Volume */
/*03C*/ char mkfs_version[64];
	/** unused field */
/*07C*/ char unused[40];

	/** log2 (Block size in bytes) */
/*0A4*/ __u8 log_block_size;

	/** Metadata bnode size and alignment */
	__u8 log_super_page_size;

	/** Discard request granularity */
	__u8 log_erase_block_size;

	/** Case insensitive mode */
	__u8 case_insensitive;

	/** Read-only image */
	__u8 read_only;

	__u8 image_crc32_present;

	/*force full decompression enable/disable bit*/
	__u8 force_full_decomp_decrypt;

	/*hash calculation algorithm*/
	__u8 hash_type;

	/* AES encryption flags */
	__u8 encryption_flags;

	/* sb signature type */
	__u8 sign_type;

	/** Padding */
/*0AE*/ __u8 reserved[54];

/*0E4*/	__le32 exsb_checksum;

/*0E8*/	__le32 basetable_checksum;

/*0EC*/	__le32 meta_hashtable_checksum;

/*0F0*/ __le64 image_inode_count;

	__le32 pad;

	/*RSA enctypted hash code of superblock*/
/*0FC*/ __u8 sb_hash[VDFS4_MAX_CRYPTED_HASH_LEN];

	/** Checksum */
/*1FC*/ __le32 checksum;
};

/**
 * @brief	The eMMCFS extended superblock. (+0x600)
 */

#define VDFS4_META_BTREE_EXTENTS		96

struct vdfs4_extended_super_block {
	/** File system files count */
/*000*/	__le64			files_count;
	/** File system folder count */
	__le64			folders_count;
	/** Extent describing the volume */
/*010*/	struct vdfs4_extent	volume_body;
	/** Number of mount operations */
/*020*/	__le32			mount_counter;
	/* SYNC counter */
	__le32			sync_counter;		/* not used */
	/** Number of umount operations */
	__le32			umount_counter;
	/** inode numbers generation */
	__le32			generation;
	/** Debug area position */
/*030*/	struct vdfs4_extent	debug_area;
	/* btrees extents total block count */
/*040*/	__le32			meta_tbc;
	__le32			pad;
	/** translation tables extents */
/*048*/	struct vdfs4_extent	tables;
	/** btrees extents */
/*058*/	struct vdfs4_extent	meta[VDFS4_META_BTREE_EXTENTS];
	/* translation tables extention */
/*658*/	struct vdfs4_extent	extension;		/* not used */

	/* volume size in blocks, could be increased at first mounting */
/*668*/	__le64			volume_blocks_count;

	/** Flag indicating signed image */
/*670*/	__u8			crc;

	/** 128-bit uuid for volume */
/*671*/	__u8			volume_uuid[16];

	/** Reserved */
/*681*/	__u8			_reserved[7];

	/** Write statistics */
/*688*/	__le64			kbytes_written;

	/** Meta HashTable extent */
/*690*/	struct vdfs4_extent	meta_hashtable_area;

	/** Reserved */
/*6A0*/	__u8			reserved[860];

	/** Extended superblock checksum */
/*9FC*/	__le32			checksum;
};

struct vdfs4_superblock {
	struct vdfs4_super_block sing1;
	struct vdfs4_super_block sign2;
	struct vdfs4_super_block superblock;
	struct vdfs4_extended_super_block ext_superblock;
};

#define VDFS4_REFORMAT_HISTORY_ITEM_MAGIC "fmth"

struct vdfs4_reformat_history {
	u8 magic[4];
	__le32 reformat_number;
	__le32 mount_count;
	__le32 sync_count;
	char driver_version[4];
	char mkfs_version[4];
};

struct vdfs4_layout_sb {
	struct vdfs4_super_block  _sb1;
	struct vdfs4_super_block  _sb2;
	struct vdfs4_super_block  sb;
	struct vdfs4_extended_super_block exsb;
};

struct vdfs4_meta_block {
	__le32 magic;
	__le32 sync_count;
	__le32 mount_count;
	__u8 data[4096 - 4 - 8 - 4];
	__le32 crc32;
};

/* Catalog btree record types */
#define VDFS4_CATALOG_RECORD_DUMMY		0x00
#define VDFS4_CATALOG_FOLDER_RECORD		0x01
#define VDFS4_CATALOG_FILE_RECORD		0x02
#define VDFS4_CATALOG_HLINK_RECORD		0x03
/* UNUSED:								0x04 */
#define VDFS4_CATALOG_ILINK_RECORD		0x05
#define VDFS4_CATALOG_UNPACK_INODE		0x10

/**
 * @brief	On-disk structure to hold generic for all the trees.
 */
struct vdfs4_generic_key {
	/** Unique number that identifies structure */
	__u8 magic[4];
	/** Length of tree-specific key */
	__le16 key_len;
	/** Full length of record containing the key */
	__le16 record_len;
};

/**
 * @brief	On-disk structure to catalog tree keys.
 */
struct vdfs4_cattree_key {
	/** Generic key part */
	struct vdfs4_generic_key gen_key;
	/** Object id of parent object (directory) */
	__le64 parent_id;
	/** Object id of child object (file) */
	__le64 object_id;
	/** Catalog tree record type */
	__u8 record_type;
	/** Object's name */
	__u8	name_len;
	char	name[VDFS4_FILE_NAME_LEN];
};

#define VDFS4_CAT_KEY_MAX_LEN	ALIGN(sizeof(struct vdfs4_cattree_key), 8)

/** @brief	Btree search key for xattr tree
 */
struct vdfs4_xattrtree_key {
	/** Key */
	struct vdfs4_generic_key gen_key;
	/** Object ID */
	__le64 object_id;
	__u8 name_len;
	char name[VDFS4_XATTR_NAME_MAX_LEN];
};

#define VDFS4_XATTR_KEY_MAX_LEN	ALIGN(sizeof(struct vdfs4_xattrtree_key), 8)

/**
 * @brief	On-disk structure to hold file and folder records.
 */
struct vdfs4_catalog_folder_record {
	/** Flags */
	__le32	flags;
	__le32	generation;
	/** Amount of files in the directory */
	__le64	total_items_count;
	/** Link's count for file */
	__le64	links_count;
	/** Next inode in orphan list */
	__le64  next_orphan_id;
	/** File mode */
	__le16	file_mode;
	__le16	pad;
	/** User ID */
	__le32	uid;
	/** Group ID */
	__le32	gid;
	/** Record creation time */
	struct vdfs4_timespec	creation_time;
	/** Record modification time */
	struct vdfs4_timespec	modification_time;
	/** Record last access time */
	struct vdfs4_timespec	access_time;
};

/**
 * @brief	On-disk structure to hold file records in catalog btree.
 */
struct vdfs4_catalog_file_record {
	/** Common part of record (file or folder) */
	struct vdfs4_catalog_folder_record common;
	union {
		/** Fork containing info about area occupied by file */
		struct vdfs4_fork	data_fork;
	};
};

/**
 * @brief	On-disk structure to hold hardlink records in catalog btree.
 */
struct vdfs4_catalog_hlink_record {
	/** file mode */
	__le16 file_mode;
	__le16	pad1;
	__le32	pad2;
};

/** START  ->> EXTENTS OVERFLOW BTREE structuries  --------------------------*/
/** @brief	Extents overflow information.
 */
struct vdfs4_exttree_key {
	/** Key */
	struct vdfs4_generic_key gen_key;
	/** Object ID */
	__le64 object_id;
	/** Block number */
	__le64 iblock;
};

/** @brief	Extents overflow tree information.
 */
struct vdfs4_exttree_lrecord {
	/** Key */
	struct vdfs4_exttree_key key;
	/** Extent for key */
	struct vdfs4_extent lextent;
};

/** END  -<< EXTENTS OVERFLOW BTREE  BTREE structuries    --------------------*/

/**
 * @brief	On-disk structure to hold essential information about B-tree.
 */
struct vdfs4_raw_btree_head {
	/** Magic */
	__u8 magic[4];
	__le32 version[2];
	/** The bnode id of root of the tree */
	__le32 root_bnode_id;
	/** Height of the tree */
	__le16 btree_height;
	/** Padding */
	__u8 padding[2];
	/** Starting byte of free bnode bitmap, bitmap follows this structure */
	__u8 bitmap[0];
};

/**
 * @brief	On-disk structure representing information about bnode common
 *		to all the trees.
 */
struct vdfs4_gen_node_descr {
	/** Magic */
	__u8 magic[4];
	__le32 version[2];
	/** Free space left in bnode */
	__le16 free_space;
	/** Amount of records that this bnode contains */
	__le16 recs_count;
	/** Node id */
	__le32 node_id;
	/** Node id of left sibling */
	__le32 prev_node_id;
	/** Node id of right sibling */
	__le32 next_node_id;
	/** Type of bnode node or index (value of enum vdfs4_node_type) */
	__u32 type;
};

/**
 * @brief	Generic value for index nodes - node id of child.
 */
struct generic_index_value {
	/** Node id of child */
	__le32 node_id;
};

#endif	/* _LINUX_VDFS4_FS_H */
