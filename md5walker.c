#define _XOPEN_SOURCE 500
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "md5.h"

struct globals {
	int debug;
	int verbose;
	int showdirs;
	char *inputpath;
};

struct globals *glb;

static int md5test( const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf ) {

	if (typeflag == FTW_F) {
		char hash[128];
		int rr;
		rr = md5_file( fpath, hash, sizeof(hash) );
		if (rr == 0) fprintf(stdout,"%s %s\n", fpath, hash );
	}

	if ((typeflag == FTW_D)&&(glb->showdirs)) {
		fprintf(stderr,"%s\n",fpath);
	}

	return 0;

}

int parse_parameters( struct globals *g, int argc, char **argv ) {

	int i;

	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
//				case 'h': fprintf(stdout,"%s", help); exit(0); break;
//				case 'V': fprintf(stdout,"%s\n",  VERSION); exit(0); break;
				case 'v': (g->verbose)++; break;
				case 'p': (g->showdirs)++; break;
				case 'd': (g->debug)++; break;
				case 'i':
						  if ((i < argc -1) && (argv[i+1][0] != '-')){
							  i++;
							  g->inputpath = strdup(argv[i]);
						  }
						  break;
				default:
						  fprintf(stderr,"Unknown parameter (%s)\n", argv[i]);
						  exit(1);
			}
		}
	}
	return 0;
}


int main(int argc, char **argv) {

	struct globals g;

	glb = &g;
	g.showdirs = 0;
	g.debug = 0;
	g.verbose = 0;

	if (argc < 2) {
		fprintf(stderr,"%s [-p] -i <path to scan>\n", argv[0]);
		return 1;
	}

	nftw( g.inputpath, md5test, 10, FTW_MOUNT|FTW_PHYS);



	return 0;
}
