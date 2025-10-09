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

	printf("=== UNTRUSTED Process Tests ===\n");

	/* Test 1: UNTRUSTED process + CW-Lite OFF + TRUSTED file should be DENIED */
	printf( "Testing: UNTRUSTED process accessing TRUSTED file with CW-Lite OFF\n" );
	cwlite_off( cwl_fd );
	fd = open(argv[1], O_RDONLY);
	
	if ( fd < 0 ) {
		printf( "CORRECT: Access denied to trusted file by untrusted process\n" );
	}
	else {
		printf( "ERROR: Access allowed to trusted file by untrusted process (should be denied)\n" );
		close( fd );
	}

	/* Test 2: UNTRUSTED process + CW-Lite ON + TRUSTED file should be DENIED */
	printf( "Testing: UNTRUSTED process accessing TRUSTED file with CW-Lite ON\n" );
	cwlite_on( cwl_fd );
	fd = open(argv[1], O_RDONLY);
	
	if ( fd < 0 ) {
		printf( "CORRECT: Access denied to trusted file by untrusted process (CW-Lite ON)\n" );
	}
	else {
		printf( "ERROR: Access allowed to trusted file by untrusted process (should be denied)\n" );
		close( fd );
	}

	/* Test 3: UNTRUSTED process + UNTRUSTED file should be ALLOWED */
	printf( "Testing: UNTRUSTED process accessing UNTRUSTED file\n" );
	cwlite_off( cwl_fd );
	fd = open(argv[2], O_RDONLY);
	
	if ( fd < 0 ) {
		printf( "ERROR: Access denied to untrusted file by untrusted process (should be allowed)\n" );
	}
	else {
		printf( "CORRECT: Access allowed to untrusted file by untrusted process\n" );
		ret = read( fd, buf1, LIMIT );
		printf( "Content: %s\n", buf1 );
		close( fd );
	}

	cwlite_close( cwl_fd );

	return 0;
}