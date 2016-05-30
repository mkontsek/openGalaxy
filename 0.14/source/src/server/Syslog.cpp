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

#include "atomic.h"

#include "Syslog.hpp"
#include "Settings.hpp"

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>

//#if HAVE_SYSLOG_H
//#include <syslog.h>    // for syslog(), openlog(), closelog()
//#endif

namespace openGalaxy {

Syslog::Syslog(){
  set_level( Syslog::Level::Error ); // Set the default maximum log level
//#if HAVE_SYSLOG_H
//  openlog( "openGalaxy", LOG_PERROR | LOG_PID, LOG_DAEMON );
//#endif
}

Syslog::Syslog( Syslog::Level nLevel ){
  set_level( nLevel );
//#if HAVE_SYSLOG_H
//  openlog( "openGalaxy", LOG_PERROR | LOG_PID, LOG_DAEMON );
//#endif
}

Syslog::~Syslog(){
//#if HAVE_SYSLOG_H
//  closelog();
//#endif
}

void Syslog::set_level( Syslog::Level nLevel )
{
  if( !(nLevel > Level::Always && nLevel < Level::Level_max) ){
    throw new std::runtime_error("Syslog::set_level(): Level out of bounds.");
  }
  m_nMaxLevel = nLevel;
}


void Syslog::write( Syslog::Level nLevel, const char* str )
{
  if( !(nLevel >= Level::Always && nLevel < Level::Level_max) ){
    throw new std::runtime_error("Syslog::write(): Level out of bounds.");
  }

  if( nLevel <= m_nMaxLevel ){
    m_mutex.lock();
//#if HAVE_SYSLOG_H
//    int nType;
//    switch( nLevel ){
//      case Level::Error:
//        nType = LOG_ERR;
//        break;
//      case Level::Info:
//        nType = LOG_INFO;
//        break;
//      case Level::Debug:
//      default:
//        nType = LOG_DEBUG;
//        break;
//    }
//    syslog( nType, str );
//#else
#ifndef _WIN32
    std::cout << "openGalaxy";
#ifdef HAVE_GETPID
    std::cout << '[' << getpid() << ']';
#endif
    std::cout << ':' << ' ';
#endif
    std::cout << str << std::endl;
//#endif

    m_mutex.unlock();
  }
}

void Syslog::message( Syslog::Level nLevel, const char* format, ... )
{
  char buffer[8192];
  va_list arguments;
  va_start( arguments, format );
  vsnprintf( buffer, sizeof buffer, format, arguments );
  write( nLevel, (const char*)buffer );
  va_end( arguments );
}

void Syslog::print( const char* format, ... )
{
  char buffer[8192];
  va_list arguments;
  va_start( arguments, format );
  vsnprintf( buffer, sizeof buffer, format, arguments );
  write( Level::Always, buffer );
  va_end( arguments );
}

void Syslog::error( const char* format, ... )
{
  if( Level::Error > m_nMaxLevel ) return;
  char buffer[8192];
  va_list arguments;
  va_start( arguments, format );
  vsnprintf( buffer, sizeof buffer, format, arguments );
  write( Level::Error, buffer );
  va_end( arguments );
}

void Syslog::info( const char* format, ... )
{
  if( Level::Info > m_nMaxLevel ) return;
  char buffer[8192];
  va_list arguments;
  va_start( arguments, format );
  vsnprintf( buffer, sizeof buffer, format, arguments );
  write( Level::Info, buffer );
  va_end( arguments );
}

void Syslog::debug( const char* format, ... )
{
  if( Level::Debug > m_nMaxLevel ) return;
  char buffer[8192];
  va_list arguments;
  va_start( arguments, format );
  vsnprintf( buffer, sizeof buffer, format, arguments );
  write( Level::Debug, buffer );
  va_end( arguments );
}

} // ends namespace openGalaxy

