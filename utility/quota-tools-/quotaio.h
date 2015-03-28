/*
 *
 *	Header of IO operations for quota utilities
 *
 */

#ifndef _QUOTAIO_H
#define _QUOTAIO_H

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "quota.h"
#include "mntopt.h"
#include "dqblk_v1.h"
#include "dqblk_v2.h"
#include "dqblk_rpc.h"
#include "dqblk_xfs.h"

/* Latest known versions */
#define INITKNOWNVERSIONS {\
	0,\
	0\
}

#define QUOTAFORMATS 4

#define INITQFBASENAMES {\
	"quota",\
	"aquota",\
	"",\
	""\
}

#define INITQFMTNAMES {\
	"vfsold",\
	"vfsv0",\
	"rpc",\
	"xfs"\
}

/* Values for format handling */
#define QF_TOONEW -2		/* Quota format is too new to handle */
#define QF_ERROR -1		/* There was error while detecting format (maybe unknown format...) */
#define QF_VFSOLD 0		/* Old quota format */
#define QF_VFSV0 1		/* New quota format - version 0 */
#define QF_RPC 2		/* RPC should be used on given filesystem */
#define QF_XFS 3		/* XFS quota format */

/*
 * Definitions for disk quotas imposed on the average user
 * (big brother finally hits Linux).
 *
 * The following constants define the default amount of time given a user
 * before the soft limits are treated as hard limits (usually resulting
 * in an allocation failure). The timer is started when the user crosses
 * their soft limit, it is reset when they go below their soft limit.
 */
#define MAX_IQ_TIME  604800	/* (7*24*60*60) 1 week */
#define MAX_DQ_TIME  604800	/* (7*24*60*60) 1 week */

#define IOFL_QUOTAON	0x01	/* Is quota enabled in kernel? */
#define IOFL_INFODIRTY	0x02	/* Did info change? */
#define IOFL_RO		0x04	/* Just RO access? */

struct quotafile_ops;

/* Generic information about quotafile */
struct util_dqinfo {
	time_t dqi_bgrace;	/* Block grace time for given quotafile */
	time_t dqi_igrace;	/* Inode grace time for given quotafile */
	union {
		struct v2_mem_dqinfo v2_mdqi;
		struct xfs_mem_dqinfo xfs_mdqi;
	} u;			/* Format specific info about quotafile */
};

/* Structure for one opened quota file */
struct quota_handle {
	int qh_fd;		/* Handle of file (-1 when IOFL_QUOTAON) */
	int qh_io_flags;	/* IO flags for file */
	char qh_quotadev[PATH_MAX];	/* Device file is for */
	int qh_type;		/* Type of quotafile */
	int qh_fmt;		/* Quotafile format */
	struct stat qh_stat;	/* stat(2) for qh_quotadev */
	struct quotafile_ops *qh_ops;	/* Operations on quotafile */
	struct util_dqinfo qh_info;	/* Generic quotafile info */
};

/* Utility quota block */
struct util_dqblk {
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	time_t dqb_btime;
	time_t dqb_itime;
	union {
		struct v2_mem_dqblk v2_mdqb;
	} u;			/* Format specific dquot information */
};

#define DQ_FOUND 0x01		/* Dquot was found in the edquotas file */

/* Structure for one loaded quota */
struct dquot {
	struct dquot *dq_next;	/* Pointer to next dquot in the list */
	qid_t dq_id;		/* ID dquot belongs to */
	int dq_flags;		/* Some flags for utils */
	struct quota_handle *dq_h;	/* Handle of quotafile dquot belongs to */
	struct util_dqblk dq_dqb;	/* Parsed data of dquot */
};

/* Structure of quotafile operations */
struct quotafile_ops {
	int (*init_io) (struct quota_handle * h);	/* Open quotafile */
	int (*new_io) (struct quota_handle * h);	/* Create new quotafile */
	int (*end_io) (struct quota_handle * h);	/* Write all changes and close quotafile */
	int (*write_info) (struct quota_handle * h);	/* Write info about quotafile */
	struct dquot *(*read_dquot) (struct quota_handle * h, qid_t id);	/* Read dquot into memory */
	int (*commit_dquot) (struct dquot * dquot);	/* Write given dquot to disk */
	int (*scan_dquots) (struct quota_handle * h, int (*process_dquot) (struct dquot * dquot, char * dqname));	/* Scan quotafile and call callback on every structure */
	int (*report) (struct quota_handle * h, int verbose);	/* Function called after 'repquota' to print format specific file information */
};

static inline void mark_quotafile_info_dirty(struct quota_handle *h)
{
	h->qh_io_flags |= IOFL_INFODIRTY;
}

#define QIO_ENABLED(h)	((h)->qh_io_flags & IOFL_QUOTAON)
#define QIO_RO(h)	((h)->qh_io_flags & IOFL_RO)

/* Detect format of given quotafile */
int detect_qf_format(int fd, int type);

/* Check quota format used on specified medium and initialize it */
struct quota_handle *init_io(struct mntent *mnt, int type, int fmt, int flags);

/* Create new quotafile of specified format on given filesystem */
struct quota_handle *new_io(struct mntent *mnt, int type, int fmt);

/* Close quotafile */
int end_io(struct quota_handle *h);

/* Get empty quota structure */
struct dquot *get_empty_dquot(void);

#endif /* _QUOTAIO_H */
