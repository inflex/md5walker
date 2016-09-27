#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>

#include "md5.h"

struct globals {
	int debug;
	int verbose;
	int showdirs;
	int floor;
	char *inputpath;
};

struct globals *glb;

static int md5test( const char *fpath ) {

	char hash[128];
	int rr;
	rr = md5_file( fpath, hash, sizeof(hash) );
	if (rr == 0) { 
		fprintf(stdout,"%s %s\n", hash, fpath );
	} else {
		if (glb->debug) fprintf(stderr,"Error %d computing MD5 for '%s'\n", rr, fpath);
		return rr;
	}
	return 0;
}

char help[] = "md5walker [-v] [-d] [-p] -i <path> [-h]\n\
			   -h : this help\n\
			   -v : turn on verbosity\n\
			   -p : show folders as they're processed (to stderr)\n\
			   -d : turn on debug output\n\
			   -i <path> : MD5Walk the directory tree with <path> as the head\n";

int parse_parameters( struct globals *g, int argc, char **argv ) {

	int i;

	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
				case 'h': fprintf(stdout,"%s", help); exit(0); break;
						  //				case 'V': fprintf(stdout,"%s\n",  VERSION); exit(0); break;
				case 'v': (g->verbose)++; break;
				case 'p': (g->showdirs)++; break;
				case 'd': (g->debug)++; break;
				case 'i':
						i++;
						g->inputpath = strdup(argv[i]);
						  break;
				default:
						  fprintf(stderr,"Unknown parameter (%s)\n", argv[i]);
						  exit(1);
			}
		}
	}
	return 0;
}

int md5scandir( char *path ) {

	DIR *d;

	if (glb->debug) fprintf(stderr,"scanning '%s'\n",path);
	(glb->floor)++;
	if (glb->floor > 30) {
		fprintf(stderr,"Floor hit\n");
		return 1;
	}

	d = opendir( path );
	if (d) {
		struct dirent *f;

		if (glb->showdirs) fprintf(stderr,"%s\n",path);

		while (1) {
			char ffn[4096];

			f = readdir(d);
			if (f == NULL) {
				if (errno > 0) {
					fprintf(stderr,"ERROR: while reading entry '%s' (%s)\n", ffn, strerror(errno));
				} else  {
					if (glb->debug) fprintf(stderr,"END of directory\n");
					break;
				}
			}

			if (strcmp(f->d_name, ".")==0) continue;
			if (strcmp(f->d_name, "..")==0) continue;

			snprintf(ffn, sizeof(ffn),"%s/%s",path, f->d_name);
			if (f->d_type == DT_DIR) {
				md5scandir(ffn);
			} else if (f->d_type == DT_REG) {
				md5test(ffn);
			} else {
				fprintf(stderr,"Unknown d_type %d (%s)\n", f->d_type, ffn);
			}
		}

	} else {
		fprintf(stderr,"Can't open directory '%s' (%s)\n", path, strerror(errno));
	}

	(glb->floor)--;

	closedir(d);
	return 0;
}

int main(int argc, char **argv) {

	struct globals g;
	int rr;

	glb = &g;
	g.showdirs = 0;
	g.debug = 0;
	g.verbose = 0;


	if (argc < 2) {
		fprintf(stderr,"%s", help);
		return 1;
	}

	parse_parameters( glb, argc, argv );

	if (g.debug) fprintf(stderr,"input path: '%s'\n", g.inputpath);
	rr = md5scandir( g.inputpath );



	return rr;
}
