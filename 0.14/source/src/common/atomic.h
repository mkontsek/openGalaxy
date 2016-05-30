/* This file is part of openGalaxy.
 *
 * opengalaxy - a SIA receiver for Galaxy security control panels.
 * Copyright (C) 2015 - 2016 Alexander Bruines <alexander.bruines@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * as published by the Free Software Foundation, or (at your option)
 * any later version.
 *
 * In addition, as a special exception, the author of this program
 * gives permission to link the code of its release with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables. You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".
 * If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so.
 * If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file is included by every C/C++ file in the project
 * before that C/C++ file does anything else...
 */

#ifndef __OPENGALAXY_ATOMIC_H__
#define __OPENGALAXY_ATOMIC_H__

/* Include the autoconf generated headerfile. */
#if HAVE_CONFIG_H
  #include "config.h"
#else
  #error "Could not include Autoconf generated 'config.h'"
#endif

/* Include profiler headers */
#if HAVE_GPERFTOOLS
#include "gperftools/profiler.h"
#endif

/* Feature test macros (see: man 7 feature_test_macros). */
#undef _GNU_SOURCE
#define _GNU_SOURCE 1
#undef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 2
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500

#if __GNUC__
#define __ATTR_NOT_USED__ __attribute__((unused))
#else
#define __ATTR_NOT_USED__
#endif

#endif

