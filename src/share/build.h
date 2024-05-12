#pragma once

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifdef HAVE_PAM
#define _PAM_FEATURE_ "+PAM"
#else
#define _PAM_FEATURE_ "-PAM"
#endif

#ifdef HAVE_AUDIT
#define _AUDIT_FEATURE_ "+AUDIT"
#else
#define _AUDIT_FEATURE_ "-AUDIT"
#endif

#ifdef HAVE_SELINUX
#define _SELINUX_FEATURE_ "+SELINUX"
#else
#define _SELINUX_FEATURE_ "-SELINUX"
#endif

#ifdef HAVE_APPARMOR
#define _APPARMOR_FEATURE_ "+APPARMOR"
#else
#define _APPARMOR_FEATURE_ "-APPARMOR"
#endif

#ifdef HAVE_IMA
#define _IMA_FEATURE_ "+IMA"
#else
#define _IMA_FEATURE_ "-IMA"
#endif

#ifdef HAVE_SMACK
#define _SMACK_FEATURE_ "+SMACK"
#else
#define _SMACK_FEATURE_ "-SMACK"
#endif

#ifdef HAVE_SYSV_COMPAT
#define _SYSVINIT_FEATURE_ "+SYSVINIT"
#else
#define _SYSVINIT_FEATURE_ "-SYSVINIT"
#endif

#ifdef HAVE_UTMP
#define _UTMP_FEATURE_ "+UTMP"
#else
#define _UTMP_FEATURE_ "-UTMP"
#endif

#ifdef HAVE_LIBCRYPTSETUP
#define _LIBCRYPTSETUP_FEATURE_ "+LIBCRYPTSETUP"
#else
#define _LIBCRYPTSETUP_FEATURE_ "-LIBCRYPTSETUP"
#endif

#ifdef HAVE_GCRYPT
#define _GCRYPT_FEATURE_ "+GCRYPT"
#else
#define _GCRYPT_FEATURE_ "-GCRYPT"
#endif

#ifdef HAVE_GNUTLS
#define _GNUTLS_FEATURE_ "+GNUTLS"
#else
#define _GNUTLS_FEATURE_ "-GNUTLS"
#endif

#ifdef HAVE_ACL
#define _ACL_FEATURE_ "+ACL"
#else
#define _ACL_FEATURE_ "-ACL"
#endif

#ifdef HAVE_XZ
#define _XZ_FEATURE_ "+XZ"
#else
#define _XZ_FEATURE_ "-XZ"
#endif

#ifdef HAVE_LZ4
#define _LZ4_FEATURE_ "+LZ4"
#else
#define _LZ4_FEATURE_ "-LZ4"
#endif

#ifdef HAVE_SECCOMP
#define _SECCOMP_FEATURE_ "+SECCOMP"
#else
#define _SECCOMP_FEATURE_ "-SECCOMP"
#endif

#ifdef HAVE_BLKID
#define _BLKID_FEATURE_ "+BLKID"
#else
#define _BLKID_FEATURE_ "-BLKID"
#endif

#ifdef HAVE_ELFUTILS
#define _ELFUTILS_FEATURE_ "+ELFUTILS"
#else
#define _ELFUTILS_FEATURE_ "-ELFUTILS"
#endif

#ifdef HAVE_KMOD
#define _KMOD_FEATURE_ "+KMOD"
#else
#define _KMOD_FEATURE_ "-KMOD"
#endif

#ifdef HAVE_LIBIDN
#define _IDN_FEATURE_ "+IDN"
#else
#define _IDN_FEATURE_ "-IDN"
#endif

#define SYSTEMD_FEATURES                                                \
        _PAM_FEATURE_ " "                                               \
        _AUDIT_FEATURE_ " "                                             \
        _SELINUX_FEATURE_ " "                                           \
        _IMA_FEATURE_ " "                                               \
        _APPARMOR_FEATURE_ " "                                          \
        _SMACK_FEATURE_ " "                                             \
        _SYSVINIT_FEATURE_ " "                                          \
        _UTMP_FEATURE_ " "                                              \
        _LIBCRYPTSETUP_FEATURE_ " "                                     \
        _GCRYPT_FEATURE_ " "                                            \
        _GNUTLS_FEATURE_ " "                                            \
        _ACL_FEATURE_ " "                                               \
        _XZ_FEATURE_ " "                                                \
        _LZ4_FEATURE_ " "                                               \
        _SECCOMP_FEATURE_ " "                                           \
        _BLKID_FEATURE_ " "                                             \
        _ELFUTILS_FEATURE_ " "                                          \
        _KMOD_FEATURE_ " "                                              \
        _IDN_FEATURE_
