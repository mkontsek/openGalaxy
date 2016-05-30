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
#ifndef __OPENGALAXY_SERVER_SYSLOG_HPP__
#define __OPENGALAXY_SERVER_SYSLOG_HPP__

#include "atomic.h"
#include <mutex>

namespace openGalaxy {

class Syslog {
public:
  // Log 'level' used by class Syslog
  enum class Level : int {
    Invalid = -1,
    Always = 0,  // Always log this message
    Error,       // Error message
    Info,        // Informational message
    Debug,       // Debug message
    Level_max
  };

  Syslog();
  Syslog( Syslog::Level nLevel );
  ~Syslog();

  // Set the higest level of message that will be logged/printed
  void set_level( Syslog::Level nLevel );

  // Get the higest level of message that will be logged/printed
  Syslog::Level get_level() { return m_nMaxLevel; }

  // Writes a C string to the log if the level is lower or queal then the maximum level
  void write( Syslog::Level nLevel, const char* str );

  // Format a C string then send it to Write()
  void message( Syslog::Level nLevel, const char* format, ... );

  // Convenience functions
  void print( const char* format, ... );   // Send to log at SyslogAlways level
  void error( const char* format, ... );   // Send to log at SyslogError level
  void info( const char* format, ... );    // Send to log at SyslogInfo level
  void debug( const char* format, ... );   // Send to log at SyslogDebug level

private:
  Syslog::Level m_nMaxLevel; // max 'level' that is logged
  std::mutex m_mutex;
};

} // ends namespace openGalaxy

#endif

