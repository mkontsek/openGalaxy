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

#ifndef __OPENGALAXY_CONTEXT_OPTIONS_HPP__
#define __OPENGALAXY_CONTEXT_OPTIONS_HPP__

#include "atomic.h"

namespace openGalaxy {

// Options that were set on the commandline
class context_options {
public:

  int no_client_certs;  // Set to 1 to disable the need for client certificates.
  int no_ssl;           // Set to 1 to disable SSL.
  int no_password;      // Set to 1 to disable the use of a username/password (when using client certificates).
  int auto_logoff;      // Set to 1 to enable automatic logoff after a timeout.

  // default ctor
  context_options(){
    no_password = 0;
    auto_logoff = 1;
    no_client_certs = 0;
    no_ssl = 0;
  }

  // copy ctor
  context_options(class context_options& s){
    no_password = s.no_password;
    auto_logoff = s.auto_logoff;
    no_client_certs = s.no_client_certs;
    no_ssl = s.no_ssl;
  }

  // = operator
  context_options& operator=(context_options& s){
    no_password = s.no_password;
    auto_logoff = s.auto_logoff;
    no_client_certs = s.no_client_certs;
    no_ssl = s.no_ssl;
    return *this;
  }
  context_options& operator=(context_options* s){
    return operator=(*s);
  }

  bool parse_command_line(int argc, char *argv[]);
};

}
#endif

