/*
 * pam_userns.c
 * Copyright (C) 2016 Enno Boland <g@s01.de>
 *
 * Distributed under terms of the MIT license.
 */

#define _GNU_SOURCE

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sched.h>

#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

static void dolog(int err, const char *format, ...) {
	va_list args;

	va_start(args, format);
	openlog("pam_ns", LOG_PID, LOG_AUTHPRIV);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int i, unshare_flags = 0, num;
	const char *username, *uid = NULL, *gid = NULL;
	struct passwd *pwd;
	struct group *grp, *tgrp;

	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
		dolog(LOG_ERR, "cannot not get username");
		return PAM_SESSION_ERR;
	}

	for(i = 0; i < argc; i++) {
		if(strncmp(argv[i], "uid=", 4) == 0)
			uid = argv[i] + 4;
		else if(strncmp(argv[i], "gid=", 4) == 0)
			gid = argv[i] + 4;
		else if (strcmp("mount", argv[i]) == 0)
			unshare_flags = CLONE_NEWNS;
		else if (strcmp("uts", argv[i]) == 0)
			unshare_flags = CLONE_NEWUTS;
		else if (strcmp("ipc", argv[i]) == 0)
			unshare_flags = CLONE_NEWIPC;
		else if (strcmp("net", argv[i]) == 0)
			unshare_flags = CLONE_NEWNET;
		else if (strcmp("pid", argv[i]) == 0)
			unshare_flags = CLONE_NEWPID;
		else if (strcmp("user", argv[i]) == 0)
			unshare_flags = CLONE_NEWUSER;
	}

	if (!(pwd = pam_modutil_getpwnam (pamh, username))) {
		dolog(LOG_ERR, "cannot not get passwd entry");
		return PAM_SESSION_ERR;
	}

	if (!(grp = pam_modutil_getgrgid(pamh, pwd->pw_gid))) {
		dolog(LOG_ERR, "cannot not get groups entry");
		return PAM_SESSION_ERR;
	}

	if(pwd->pw_uid == 0)
		return PAM_SUCCESS;

	/* Check uid */
	if(uid != NULL && strcmp(username, uid) != 0) {
		/* Assuming numeric uid */
		num = strtol(uid, NULL, 10);
		if(errno == EINVAL)
			return PAM_SUCCESS;
		if(num != pwd->pw_uid)
			return PAM_SUCCESS;
	}

	/* Check gid */
	if(gid != NULL && strcmp(grp->gr_name, gid) != 0) {
		if(!(tgrp = pam_modutil_getgrnam(pamh, gid))) {
			/* Assuming numeric gid */
			num = strtol(gid, NULL, 10);
			if(errno == EINVAL)
				return PAM_SUCCESS;
			if(!(tgrp = pam_modutil_getgrgid(pamh, num)))
				return PAM_SUCCESS;
		}
		for(i = 0; tgrp->gr_mem[i] && strcmp(tgrp->gr_mem[i], username); i++);
		if(!tgrp->gr_mem[i])
			return PAM_SUCCESS;
	}

	if(unshare(unshare_flags)) {
		dolog(LOG_ERR, "%s: error unsharing: %s", username, strerror(errno));
		return PAM_SESSION_ERR;
	}
	dolog(LOG_DEBUG, "%s: successfully unshared", username);

	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}
