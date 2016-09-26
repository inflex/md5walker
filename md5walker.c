#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "md5.h"

static int md5test( const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf ) {

	if (typeflag == FTW_F) {
		char hash[128];
		int rr;
		rr = md5_file( fpath, hash, sizeof(hash) );
		if (rr == 0) fprintf(stdout,"%s %s\n", fpath, hash );
	}

	return 0;

}


int main(int argc, char **argv) {

	if (argc < 1) {
		fprintf(stderr,"%s <path to scan>\n", argv[0]);
		return 1;
	}

	nftw(argv[1], md5test, 10, FTW_MOUNT|FTW_PHYS);



	return 0;
}
