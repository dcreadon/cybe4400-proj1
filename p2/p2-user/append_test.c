#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <assert.h>

#include "cwlite.h"

#define LIMIT 20

int main( int argc, char *argv[] )
{
	int cwl_fd, fd;
	int ret;
	char buf1[LIMIT], buf2[LIMIT], attrbuf[LIMIT];

	assert( argc == 3 );

	cwl_fd = cwlite_open();
	assert( cwl_fd > 0 );

	// Test APPEND operation on first file (without CW-Lite)
	fd = open(argv[1], O_WRONLY | O_APPEND);

	if ( fd < 0 ) {
		printf( "append_test: %s open for append failed - probably no file\n", argv[1] );
	}
	else {
		ret = getxattr( argv[1], "security.sample", attrbuf, LIMIT );
		if ( ret > 0 ) {
			attrbuf[ret] = '\0';
			printf( "append_test: %s attribute %s\n", argv[1], attrbuf );
		}
		else {
			printf( "append_test: %s attribute retrieval problem\n", argv[1] );
		}
	}

	strcpy(buf1, "APPEND1 ");
	ret = write( fd, buf1, strlen(buf1) );
	printf( "append_test: appended %d bytes to %s\n", ret, argv[1] );
	close( fd );

	// Test APPEND operation on second file (with CW-Lite)
	cwlite_on( cwl_fd );
	fd = open(argv[2], O_WRONLY | O_APPEND);
	cwlite_off( cwl_fd );

	if ( fd < 0 ) {
		printf( "append_test: %s open for append failed - probably no file\n", argv[2] );
	}
	else {
		ret = getxattr( argv[2], "security.sample", attrbuf, LIMIT );
		if ( ret > 0 ) {
			attrbuf[ret] = '\0';
			printf( "append_test: %s attribute %s\n", argv[2], attrbuf );
		}
		else {
			printf( "append_test: %s attribute retrieval problem\n", argv[2] );
		}
	}

	cwlite_on( cwl_fd );
	strcpy(buf2, "APPEND2 ");
	ret = write( fd, buf2, strlen(buf2) );
	cwlite_off( cwl_fd );
	printf( "append_test: appended %d bytes to %s\n", ret, argv[2] );
	
	strcpy(buf2, "APPEND3 ");
	ret = write( fd, buf2, strlen(buf2) );
	printf( "append_test: appended %d bytes to %s\n", ret, argv[2] );

	close( fd );
	cwlite_close( cwl_fd );

	return 0;
}