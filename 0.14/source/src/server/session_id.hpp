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

#ifndef __OPENGALAXY_SESSION_ID_HPP__
#define __OPENGALAXY_SESSION_ID_HPP__

#include "atomic.h"
#include "context_options.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#endif

// Prevent MSYS2/MinGW64 from choking on redefinition of strcasecmp
// by libwebsockets.h
#ifdef _WIN32
#ifdef strcasecmp
#undef strcasecmp
#endif
#endif
#include "libwebsockets.h"
#ifdef _WIN32
#ifdef strcasecmp
#undef strcasecmp
#endif
#endif


#include "ssl_evp.h"

namespace openGalaxy {

// SHA256 fingerprint length in bytes
//constexpr const int SHA256LEN = 32;

//
// A class to associate a client with a 'Session' object based on the value of:
//  a unique (random) number AND
//  a pointer to a struct lws* (wsi) belonging to that client AND
//  an SHA-256 fingerprint (from that client certificate)
//
class session_id {
private:
  class context_options m_options;
public:
  unsigned long long int id;
  char sha256str[2*SSL_SHA256LEN+1];
  struct lws* websocket_wsi;

  session_id(context_options& options) : m_options(options) {
    id = 0;
    websocket_wsi = nullptr;
    sha256str[0] = '\0';
  }

  session_id(context_options& options, unsigned int _id, const char _sha256str[2*SSL_SHA256LEN+1]) : m_options(options) {
    strcpy(sha256str, _sha256str);
    id = _id;
    websocket_wsi = nullptr;
  }

  session_id& operator=(session_id& s) {
    m_options = s.m_options;
    id = s.id;
    strcpy(sha256str, s.sha256str);
    websocket_wsi = s.websocket_wsi;
    return *this;
  }

  int operator==(session_id& s) {
    if(id == s.id){
      if(m_options.no_ssl || m_options.no_client_certs){
        if(websocket_wsi == s.websocket_wsi){
          return 1;
        }
      }
      else if( strcmp(sha256str, s.sha256str) == 0){
        return 1;
      }
    }
    return 0;
  }

  int operator!=(session_id& s) {
    return !operator==(s);
  }
};

}
#endif

