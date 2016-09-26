# md5walker
Creates a MD5 hash list of a filesystem tree.  This is meant as a simple tool for use with ddrescue when trying to find damaged files.  

Previously you could do this with a simple find call but it would tend to hang or cause issues with unpredictably damaged files and/or filesystems.

md5walker will try to stop and/or filter the hiccups.


##Usage

$ ./md5walker ./path-to-filesystem 

