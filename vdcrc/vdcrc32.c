#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <vdfs_tools.h>

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
	size_t filesize=0, readsize=0;
	unsigned char *buffer = NULL;
	unsigned int crc=0;

	if( argc != 2 ) {
		fprintf(stderr,"Parameter missing."
				" Please input filename.\n");
		rtn = -1;
		goto exit;
	}

	if((filesize = get_filesize(argv[1])) == -1 ) {
		rtn = -1;
		goto exit;
	}

	if( (buffer = (unsigned char*)malloc(filesize)) == NULL ) {
		fprintf(stderr, "'malloc' failed for '%s'\n",
				strerror(errno));
		rtn = -1;
		goto exit;
	}

	if( (fd=open(argv[1], O_RDONLY)) == -1 ) {
		fprintf(stderr, "'open' error for '%s'\n", 
				strerror(errno));
		rtn = -1;
		goto mem_alloc;
	}

	if((readsize=read(fd, buffer, filesize)) != filesize) {
		fprintf(stderr, "'read' error for '%s'."
				" filesize:%zu but readsize:%zu\n",
				strerror(errno), filesize, readsize);
		rtn = -1;
		goto file_open;
	}

	crc = vdfs4_crc32( buffer, filesize);
	printf("File:%s(size:%zubyte) CRC is %#x\n", argv[1], filesize, crc);

file_open:
	close(fd);
mem_alloc:
	free(buffer);
exit:
	return rtn;
}
