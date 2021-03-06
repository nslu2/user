/*
 *	Headerfile for old quotafile format
 */

#ifndef _DQBLK_V1_H
#define _DQBLK_V1_H

/* Values of quota calls */
#define Q_V1_RSQUASH	0x1000
#define Q_V1_GETQUOTA	0x300
#define Q_V1_SETQUOTA	0x400

struct quotafile_ops;		/* Will be defined later in quotaio.h */

/* Operations above this format */
extern struct quotafile_ops quotafile_ops_1;

#endif
