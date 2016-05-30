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

// Make sure that we have thread & reentrant safe memory allocation functions

#include "atomic.h"
#include <malloc.h>
#include <string.h>
#include <mutex>

namespace openGalaxy {

static std::mutex m;

void *thread_safe_malloc(size_t len)
{
  m.lock();
  void *retv = malloc(len);
  m.unlock();
  if(retv == nullptr) throw new std::bad_alloc();
  return retv;
}

void *thread_safe_zalloc(size_t len)
{
  m.lock();
  void *retv = malloc(len);
  m.unlock();
  if(retv == nullptr) throw new std::bad_alloc();
  memset(retv, 0, len);
  return retv;
}

void *thread_safe_realloc(void *p, size_t len)
{
  m.lock();
  void *retv = realloc(p, len);
  m.unlock();
  if(retv == nullptr) throw new std::bad_alloc();
  return retv;
}

char *thread_safe_strdup(const char *s1)
{
  m.lock();
  char* retv = strdup(s1);
  m.unlock();
  if(retv == nullptr) throw new std::bad_alloc();
  return retv;
}

/*
char *thread_safe_strndup(const char *str, size_t s)
{
  m.lock();
  char* retv = strndup(str, s);
  m.unlock();
  if(retv == nullptr) throw new std::bad_alloc();
  return retv;
}
*/

void thread_safe_free(void *ptr)
{
  m.lock();
  free(ptr);
  m.unlock();
  return;
}

} // ends namespace openGalaxy


