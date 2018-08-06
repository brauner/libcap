/*
 * Copyright (c) 1997,2007,2016 Andrew G Morgan <morgan@kernel.org>
 *
 * This file deals with setting capabilities on files.
 */

#include <sys/types.h>
#include <byteswap.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/xattr.h>

/*
 * We hardcode the prototypes for the Linux system calls here since
 * there are no libcap library APIs that expose the user to these
 * details, and that way we don't need to force clients to link any
 * other libraries to access them.
 */
extern ssize_t getxattr(const char *, const char *, void *, size_t);
extern ssize_t fgetxattr(int, const char *, void *, size_t);
extern int setxattr(const char *, const char *, const void *, size_t, int);
extern int fsetxattr(int, const char *, const void *, size_t, int);
extern int removexattr(const char *, const char *);
extern int fremovexattr(int, const char *);

#include "libcap.h"

#ifdef VFS_CAP_U32

#if VFS_CAP_U32 != __CAP_BLKS
# error VFS representation of capabilities is not the same size as kernel
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define FIXUP_32BITS(x) bswap_32(x)
#else
#define FIXUP_32BITS(x) (x)
#endif

#ifdef VFS_CAP_REVISION_3
static cap_t _fcaps_load(struct vfs_ns_cap_data *rawvfscap, cap_t result,
			 int bytes)
#else
static cap_t _fcaps_load(struct vfs_cap_data *rawvfscap, cap_t result, int bytes)
#endif
{
    __u32 magic_etc;
    unsigned tocopy, i;

    magic_etc = FIXUP_32BITS(rawvfscap->magic_etc);
    switch (magic_etc & VFS_CAP_REVISION_MASK) {
#ifdef VFS_CAP_REVISION_1
    case VFS_CAP_REVISION_1:
	tocopy = VFS_CAP_U32_1;
	bytes -= XATTR_CAPS_SZ_1;
	break;
#endif

#ifdef VFS_CAP_REVISION_2
    case VFS_CAP_REVISION_2:
	tocopy = VFS_CAP_U32_2;
	bytes -= XATTR_CAPS_SZ_2;
	break;
#endif

#ifdef VFS_CAP_REVISION_3
    case VFS_CAP_REVISION_3:
	tocopy = VFS_CAP_U32_3;
	bytes -= XATTR_CAPS_SZ_3;
	break;
#endif

    default:
	cap_free(result);
	result = NULL;
	return result;
    }

    /*
     * Verify that we loaded exactly the right number of bytes
     */
    if (bytes != 0) {
	cap_free(result);
	result = NULL;
	return result;
    }

    for (i=0; i < tocopy; i++) {
	result->u[i].flat[CAP_INHERITABLE]
	    = FIXUP_32BITS(rawvfscap->data[i].inheritable);
	result->u[i].flat[CAP_PERMITTED]
	    = FIXUP_32BITS(rawvfscap->data[i].permitted);
	if (magic_etc & VFS_CAP_FLAGS_EFFECTIVE) {
	    result->u[i].flat[CAP_EFFECTIVE]
		= result->u[i].flat[CAP_INHERITABLE]
		| result->u[i].flat[CAP_PERMITTED];
	}
    }
    while (i < __CAP_BLKS) {
	result->u[i].flat[CAP_INHERITABLE]
	    = result->u[i].flat[CAP_PERMITTED]
	    = result->u[i].flat[CAP_EFFECTIVE] = 0;
	i++;
    }

#ifdef VFS_CAP_REVISION_3
    /* The kernel returns the rootid as a _le32. In case we're on a big endian
     * machine we need to fix this up.
     */
    result->rootid = FIXUP_32BITS(rawvfscap->rootid);
#endif

    return result;
}

#ifdef VFS_CAP_REVISION_3
static int _fcaps_save(struct vfs_ns_cap_data *rawvfscap, cap_t cap_d,
		       int *bytes_p)
#else
static int _fcaps_save(struct vfs_cap_data *rawvfscap, cap_t cap_d, int *bytes_p)
#endif
{
    __u32 eff_not_zero, magic;
    unsigned tocopy, i;

    if (!good_cap_t(cap_d)) {
	errno = EINVAL;
	return -1;
    }

    switch (cap_d->head.version) {
#ifdef _LINUX_CAPABILITY_VERSION_1
    case _LINUX_CAPABILITY_VERSION_1:
	magic = VFS_CAP_REVISION_1;
	tocopy = VFS_CAP_U32_1;
	*bytes_p = XATTR_CAPS_SZ_1;
	break;
#endif

#ifdef _LINUX_CAPABILITY_VERSION_2
    case _LINUX_CAPABILITY_VERSION_2:
	magic = VFS_CAP_REVISION_2;
	tocopy = VFS_CAP_U32_2;
	*bytes_p = XATTR_CAPS_SZ_2;
	break;
#endif

#ifdef _LINUX_CAPABILITY_VERSION_3
    case _LINUX_CAPABILITY_VERSION_3:
#ifdef VFS_CAP_REVISION_3
	magic = VFS_CAP_REVISION_3;
	tocopy = VFS_CAP_U32_3;
	*bytes_p = XATTR_CAPS_SZ_3;
#else
	magic = VFS_CAP_REVISION_2;
	tocopy = VFS_CAP_U32_2;
	*bytes_p = XATTR_CAPS_SZ_2;
#endif
	break;
#endif

    default:
	errno = EINVAL;
	return -1;
    }

    _cap_debug("setting named file capabilities");

    for (eff_not_zero = 0, i = 0; i < tocopy; i++) {
	eff_not_zero |= cap_d->u[i].flat[CAP_EFFECTIVE];
    }
    while (i < __CAP_BLKS) {
	if ((cap_d->u[i].flat[CAP_EFFECTIVE]
	     || cap_d->u[i].flat[CAP_INHERITABLE]
	     || cap_d->u[i].flat[CAP_PERMITTED])) {
	    /*
	     * System does not support these capabilities
	     */
	    errno = EINVAL;
	    return -1;
	}
	i++;
    }

    for (i=0; i < tocopy; i++) {
	rawvfscap->data[i].permitted
	    = FIXUP_32BITS(cap_d->u[i].flat[CAP_PERMITTED]);
	rawvfscap->data[i].inheritable
	    = FIXUP_32BITS(cap_d->u[i].flat[CAP_INHERITABLE]);

	if (eff_not_zero
	    && ((~(cap_d->u[i].flat[CAP_EFFECTIVE]))
		& (cap_d->u[i].flat[CAP_PERMITTED]
		   | cap_d->u[i].flat[CAP_INHERITABLE]))) {
	    errno = EINVAL;
	    return -1;
	}
    }

#ifdef VFS_CAP_REVISION_3
    /* The kernel expects the rootid to be a _le32. In case we're on a big
     * endian machine we need to fix this up.
     */
    rawvfscap->rootid = FIXUP_32BITS(cap_d->rootid);
    if (rawvfscap->rootid == 0) {
	/* If libcap was compiled on a kernel supporting VFS_CAP_REVISION_3 but
	 * running on a kernel that does not support VFS_CAP_REVISION_3 we
	 * should always pass down a legacy struct vfs_cap_data if the rootid is
	 * 0. On kernels supporting VFS_CAP_REVISION_3 the kernel will take care
	 * of translating it from VFS_CAP_REVISION_2 to a VFS_CAP_REVISION_3
	 * version.  We can elegantly handle both cases by setting magic to
	 * VFS_CAP_REVISION_2 and only passing down XATTR_CAPS_SZ_2 bytes which
	 * will leave out the rootid field.  If the rootid field is not 0 then
	 * we will pass down the VFS_CAP_REVISION_3 and XATTR_CAPS_SZ_3. On
	 * kernels supporting VFS_CAP_REVISION_3 this will succeed on kernels
	 * not supporting VFS_CAP_REVISION_3 this will fail. The failure on kernels
	 * not supporting VFS_CAP_REVISION_3 is wanted since the user explicitly
	 * requested an unprivileged file capability but the kernel does not
	 * actually support it. So fail hard. */
	magic = VFS_CAP_REVISION_2;
	*bytes_p = XATTR_CAPS_SZ_2;
    }
#endif

    if (eff_not_zero == 0) {
	rawvfscap->magic_etc = FIXUP_32BITS(magic);
    } else {
	rawvfscap->magic_etc = FIXUP_32BITS(magic|VFS_CAP_FLAGS_EFFECTIVE);
    }

    return 0;      /* success */
}

/*
 * Get the capabilities of an open file, as specified by its file
 * descriptor.
 */

cap_t cap_get_fd(int fildes)
{
    cap_t result;

    /* allocate a new capability set */
    result = cap_init();
    if (result) {
#ifdef VFS_CAP_REVISION_3
	struct vfs_ns_cap_data rawvfscap;
#else
	struct vfs_cap_data rawvfscap;
#endif
	int sizeofcaps;

	_cap_debug("getting fildes capabilities");

	/* fill the capability sets via a system call */
	rawvfscap.rootid = 0;
	sizeofcaps = fgetxattr(fildes, XATTR_NAME_CAPS,
			       &rawvfscap, sizeof(rawvfscap));
	if (sizeofcaps < ssizeof(rawvfscap.magic_etc)) {
	    cap_free(result);
	    result = NULL;
	} else {
	    result = _fcaps_load(&rawvfscap, result, sizeofcaps);
	}
    }

    return result;
}

/*
 * Get the capabilities from a named file.
 */

cap_t cap_get_file(const char *filename)
{
    cap_t result;

    /* allocate a new capability set */
    result = cap_init();
    if (result) {
#ifdef VFS_CAP_REVISION_3
	struct vfs_ns_cap_data rawvfscap;
#else
	struct vfs_cap_data rawvfscap;
#endif
	int sizeofcaps;

	_cap_debug("getting filename capabilities");

	/* fill the capability sets via a system call */
	rawvfscap.rootid = 0;
	sizeofcaps = getxattr(filename, XATTR_NAME_CAPS,
			      &rawvfscap, sizeof(rawvfscap));
	if (sizeofcaps < ssizeof(rawvfscap.magic_etc)) {
	    cap_free(result);
	    result = NULL;
	} else {
	    result = _fcaps_load(&rawvfscap, result, sizeofcaps);
	}
    }

    return result;
}

/*
 * Get rootid as seen in the current user namespace for the file capability
 * sets.
 */

uid_t cap_get_nsowner(cap_t cap_d)
{
	return cap_d->rootid;
}

/*
 * Set the capabilities of an open file, as specified by its file
 * descriptor.
 */

int cap_set_fd(int fildes, cap_t cap_d)
{
#ifdef VFS_CAP_REVISION_3
    struct vfs_ns_cap_data rawvfscap;
#else
    struct vfs_cap_data rawvfscap;
#endif
    int sizeofcaps;
    struct stat buf;

    if (fstat(fildes, &buf) != 0) {
	_cap_debug("unable to stat file descriptor %d", fildes);
	return -1;
    }
    if (S_ISLNK(buf.st_mode) || !S_ISREG(buf.st_mode)) {
	_cap_debug("file descriptor %d for non-regular file", fildes);
	errno = EINVAL;
	return -1;
    }

    if (cap_d == NULL) {
	_cap_debug("deleting fildes capabilities");
	return fremovexattr(fildes, XATTR_NAME_CAPS);
    } else if (_fcaps_save(&rawvfscap, cap_d, &sizeofcaps) != 0) {
	return -1;
    }

    _cap_debug("setting fildes capabilities");

    return fsetxattr(fildes, XATTR_NAME_CAPS, &rawvfscap, sizeofcaps, 0);
}

/*
 * Set the capabilities of a named file.
 */

int cap_set_file(const char *filename, cap_t cap_d)
{
#ifdef VFS_CAP_REVISION_3
    struct vfs_ns_cap_data rawvfscap;
#else
    struct vfs_cap_data rawvfscap;
#endif
    int sizeofcaps;
    struct stat buf;

    if (lstat(filename, &buf) != 0) {
	_cap_debug("unable to stat file [%s]", filename);
	return -1;
    }
    if (S_ISLNK(buf.st_mode) || !S_ISREG(buf.st_mode)) {
	_cap_debug("file [%s] is not a regular file", filename);
	errno = EINVAL;
	return -1;
    }

    if (cap_d == NULL) {
	_cap_debug("removing filename capabilities");
	return removexattr(filename, XATTR_NAME_CAPS);
    } else if (_fcaps_save(&rawvfscap, cap_d, &sizeofcaps) != 0) {
	return -1;
    }

    _cap_debug("setting filename capabilities");
    return setxattr(filename, XATTR_NAME_CAPS, &rawvfscap, sizeofcaps, 0);
}

#else /* ie. ndef VFS_CAP_U32 */

cap_t cap_get_fd(int fildes)
{
    errno = EINVAL;
    return NULL;
}

cap_t cap_get_file(const char *filename)
{
    errno = EINVAL;
    return NULL;
}

uid_t cap_get_nsowner(cap_t cap_d)
{
    errno = EINVAL;
    return -1;
}

int cap_set_fd(int fildes, cap_t cap_d)
{
    errno = EINVAL;
    return -1;
}

int cap_set_file(const char *filename, cap_t cap_d)
{
    errno = EINVAL;
    return -1;
}

#endif /* def VFS_CAP_U32 */
