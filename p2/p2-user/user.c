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

	fd = open(argv[1], O_RDONLY);

	if ( fd < 0 ) {
		printf( "user: %s open failed - probably no file\n", argv[1] );
	}
	else {
		ret = getxattr( argv[1], "security.sample", attrbuf, LIMIT );
		if ( ret > 0 ) {
			attrbuf[ret] = '\0';  // null terminate the string
			printf( "user: %s attribute %s\n", argv[1], attrbuf );
		}
		else {
			printf( "user: %s attribute retrieval problem\n", argv[1] );
		}
	}

	ret = read( fd, buf1, LIMIT );
	printf( "%s\n", buf1 );
	close( fd );

	cwlite_on( cwl_fd );
	fd = open(argv[2], O_RDONLY);
	cwlite_off( cwl_fd );

	if ( fd < 0 ) {
		printf( "user: %s open failed - probably no file\n", argv[2] );
	}
	else {
		ret = getxattr( argv[2], "security.sample", attrbuf, LIMIT );
		if ( ret > 0 ) {
			attrbuf[ret] = '\0';  // null terminate the string
			printf( "user: %s attribute %s\n", argv[2], attrbuf );
		}
		else {
			printf( "user: %s attribute retrieval problem\n", argv[2] );
		}
	}

	cwlite_on( cwl_fd );
	ret = read( fd, buf2, LIMIT );
	cwlite_off( cwl_fd );
	printf( "%s\n", buf2 );
	
	ret = read( fd, buf2, LIMIT );
	printf( "%s\n", buf2 );

	close( fd );
	
	/* Test the restriction: TRUSTED process + CW-Lite OFF + UNTRUSTED file should be DENIED */
	printf( "Testing restriction: TRUSTED process accessing UNTRUSTED file with CW-Lite OFF\n" );
	cwlite_off( cwl_fd );
	fd = open(argv[2], O_RDONLY);  // This should FAIL for TRUSTED process
	
	if ( fd < 0 ) {
		printf( "CORRECT: Access denied to untrusted file when CW-Lite is OFF\n" );
	}
	else {
		printf( "ERROR: Access allowed to untrusted file when CW-Lite is OFF (should be denied)\n" );
		close( fd );
	}
	
	/* Test write access: TRUSTED process + CW-Lite OFF + TRUSTED file should be ALLOWED */
	printf( "Testing write access: TRUSTED process writing to TRUSTED file with CW-Lite OFF\n" );
	cwlite_off( cwl_fd );
	fd = open(argv[1], O_WRONLY);
	
	if ( fd < 0 ) {
		printf( "ERROR: Write access denied to trusted file when CW-Lite is OFF (should be allowed)\n" );
	}
	else {
		printf( "CORRECT: Write access allowed to trusted file when CW-Lite is OFF\n" );
		close( fd );
	}
	
	/* Test write access: TRUSTED process + CW-Lite ON + UNTRUSTED file should be ALLOWED */
	printf( "Testing write access: TRUSTED process writing to UNTRUSTED file with CW-Lite ON\n" );
	cwlite_on( cwl_fd );
	fd = open(argv[2], O_WRONLY);
	
	if ( fd < 0 ) {
		printf( "ERROR: Write access denied to untrusted file when CW-Lite is ON (should be allowed)\n" );
	}
	else {
		printf( "CORRECT: Write access allowed to untrusted file when CW-Lite is ON\n" );
		close( fd );
	}
	
	/* Test append access: TRUSTED process + CW-Lite OFF + UNTRUSTED file should be DENIED */
	printf( "Testing append access: TRUSTED process appending to UNTRUSTED file with CW-Lite OFF\n" );
	cwlite_off( cwl_fd );
	fd = open(argv[2], O_WRONLY | O_APPEND);
	
	if ( fd < 0 ) {
		printf( "CORRECT: Append access denied to untrusted file when CW-Lite is OFF\n" );
	}
	else {
		printf( "ERROR: Append access allowed to untrusted file when CW-Lite is OFF (should be denied)\n" );
		close( fd );
	}
	
	/* UNTRUSTED PROCESS TESTS - Label this executable as 'untrusted' before running these */
	printf( "\n=== UNTRUSTED Process Tests (requires untrusted executable) ===\n" );
	
	/* Test: UNTRUSTED process + TRUSTED file should be DENIED */
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
	
	/* Test: UNTRUSTED process + UNTRUSTED file should be ALLOWED */
	printf( "Testing: UNTRUSTED process accessing UNTRUSTED file\n" );
	cwlite_off( cwl_fd );
	fd = open(argv[2], O_RDONLY);
	
	if ( fd < 0 ) {
		printf( "ERROR: Access denied to untrusted file by untrusted process (should be allowed)\n" );
	}
	else {
		printf( "CORRECT: Access allowed to untrusted file by untrusted process\n" );
		close( fd );
	}
	
	cwlite_close( cwl_fd );

	return 0;
}
