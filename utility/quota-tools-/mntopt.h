#ifndef _MNTOPT_H
#define _MNTOPT_H

#include <mntent.h>

/* filesystem type */
#define MNTTYPE_EXT2		"ext2"	/* 2nd Extended file system */
#define MNTTYPE_EXT3		"ext3"	/* ext2 + journaling */
#define MNTTYPE_MINIX		"minix"	/* MINIX file system */
#define MNTTYPE_UFS		"ufs"	/* UNIX file system */
#define MNTTYPE_UDF		"udf"	/* OSTA UDF file system */
#define MNTTYPE_REISER		"reiserfs"	/* Reiser file system */
#define MNTTYPE_XFS		"xfs"	/* SGI XFS file system */

/* mount options */
#define MNTOPT_NOQUOTA		"noquota"	/* don't enforce quota */
#define MNTOPT_QUOTA		"quota"	/* enforce user quota */
#define MNTOPT_USRQUOTA		"usrquota"	/* enforce user quota */
#define MNTOPT_GRPQUOTA		"grpquota"	/* enforce group quota */
#define MNTOPT_RSQUASH		"rsquash"	/* root as ordinary user */

#endif
