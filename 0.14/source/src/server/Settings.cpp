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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#endif

#include "Syslog.hpp"
#include "Settings.hpp"
#include <fstream>

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>

#if __linux__
#ifndef _LOG_DIR_
#error _LOG_DIR_ has not been set!
#endif
#ifndef _CONFIG_DIR_
#error _CONFIG_DIR_ has not been set!
#endif
#endif

namespace openGalaxy {

#ifdef _WIN32
static bool GetRegistry( const char *key, std::string& out )
{
  DWORD dwType = REG_SZ;
  HKEY hKey = 0;
  char value[1024];
  DWORD value_length = sizeof( value );
  const char* subkey = "Software\\openGalaxy";
  value[0] = '\0';
  RegOpenKey( HKEY_CURRENT_USER, subkey, &hKey );
  if( RegQueryValueEx( hKey, key, nullptr, &dwType, ( LPBYTE )&value, &value_length ) != ERROR_SUCCESS ){
    out.assign("");
    return false;
  }
  RegCloseKey( hKey );
  if( strlen(value) > 2 ){
    for( size_t t=0; t<strlen(value); t++ ) if( value[t] == '\\' ) value[t] = '/';
    if( *value == '\"' ){ // remove the quotes
      size_t t = strlen( value ) - 1;
      if( t > 0 && t < value_length ) value[ t ] = '\0';
      out.assign( &value[1] );
    }
    else out.assign( value );
  }
  else {
    out.assign("");
  }

  return true;
}
#endif


// Returns 1 if string v contains 'yes', 'on', 'true', or '1'
// Returns 0 if string v contains 'no', 'off', 'false', or '0'
static int is_yes_or_no( char *v )
{
  int retv = 0;
  for( unsigned int t = 0; t < std::char_traits<char>::length( v ); t++ ) v[t] = std::toupper( v[t] ); // convert v to an all uppercase string
  if( std::strcmp( v, "YES" ) == 0 ){
    retv = 1;
  }
  else if( std::strcmp( v, "TRUE" ) == 0 ){
    retv = 1;
  }
  else if( std::strcmp( v, "ON" ) == 0 ){
    retv = 1;
  }
  else if( std::strcmp( v, "Y" ) == 0 ){
    retv = 1;
  }
  else if( std::strcmp( v, "1" ) == 0 ){
    retv = 1;
  }
  else if( std::strcmp( v, "NO" ) == 0 ){
    retv = 0;
  }
  else if( std::strcmp( v, "FALSE" ) == 0 ){
    retv = 0;
  }
  else if( std::strcmp( v, "OFF" ) == 0 ){
    retv = 0;
  }
  else if( std::strcmp( v, "N" ) == 0 ){
    retv = 0;
  }
  else if( std::strcmp( v, "0" ) == 0 ){
    retv = 0;
  }
  else {
    throw new std::runtime_error( "openGalaxy::Settings: Syntax error in configuration file!" );
  }
  return retv;
}

Settings::Settings(openGalaxy *opengalaxy) : m_openGalaxy(opengalaxy)
{
#if __linux__
  // Linux: use configured (hardcoded) values
  default_textfile.assign( _LOG_DIR_ "/galaxy.log" );
  configfile.assign( _CONFIG_DIR_ "/galaxy.conf" );
  ssmtp_configfile.assign( _CONFIG_DIR_ "/ssmtp.conf" ); // only used under linux
  www_root_directory.assign( _WWW_DIR_ );
  certificates_directory.assign( _CERT_DIR_ );
#endif
#if _WIN32
  // Windows: load values from the registry
  std::string configdir;
  std::string datadir;
  std::string wwwdir;
  if(
   (false == GetRegistry("ConfigDirectory", configdir)) ||
   (false == GetRegistry("DataDirectory", datadir)) ||
   (false == GetRegistry("WebDirectory", wwwdir))
  ){
    throw new std::runtime_error( "openGalaxy::Settings could not read from registry!" ); 
  }
  default_textfile = configdir;
  default_textfile += "/galaxy.log.txt";
  configfile = configdir;
  configfile += "/galaxy.conf";
  www_root_directory = wwwdir;
  certificates_directory = datadir;
  certificates_directory += "/ssl";
#endif

  // Set default values
  defaults();

  // Apply the (new) syslog level
  m_openGalaxy->syslog().set_level(syslog_level);

  // Read settings from configuration file
  read( configfile.c_str() );
}

Settings::~Settings()
{
  clear();
}


// Sets all values to 'empty'
void Settings::clear( void )
{
  remote_code.clear();
  receiver_tty.clear();
#ifdef HAVE_EMAIL_PLUGIN
  email_recipients.clear();
  email_from_name.clear();
  email_from_address.clear();
#endif
#ifdef HAVE_MYSQL_PLUGIN
  mysql_server.clear();
  mysql_user.clear();
  mysql_password.clear();
  mysql_database.clear();
#endif
#ifdef HAVE_FILE_PLUGIN
  textfile.clear();
#endif
  receiver_baudrate = -1;
  sia_use_alt_control_blocks = -1;
  syslog_level = Syslog::Level::Invalid;
  plugin_use_email = -1;
  plugin_use_mysql = -1;
  plugin_use_odbc = -1;
  plugin_use_file = -1;
  galaxy_dip8 = -1;
  session_timeout_seconds = -1;
  blacklist_timeout_minutes = -1;
  iface = "";
  http_port = -1;
  https_port = -1;
}

// Sets a default value for any 'empty' values
void Settings::defaults( void )
{
  // remote code
  if( remote_code.length() == 0 ){
    remote_code.assign( default_remote_code );
  }

  // receiver settings
  if( receiver_tty.length() == 0 ){
    receiver_tty.assign( default_receiver_tty );
  }
  if( receiver_baudrate == -1 ) {
    receiver_baudrate = default_receiver_baudrate;
#if __linux__
    receiver_baudrate_termios = default_receiver_baudrate_termios;
#endif
  }

  // email plugin
#ifdef HAVE_EMAIL_PLUGIN
  if( email_from_name.length() == 0 ){
    email_from_name.assign( default_email_from_name );
  }
  if( email_from_address.length() == 0 ){
    email_from_address.assign( default_email_from_address );
  }
  if( email_recipients.length() == 0 ){
    email_recipients.assign( default_email_recipients );
  }
#endif

  // MySQL plugin
#ifdef HAVE_MYSQL_PLUGIN
  if( mysql_server.length() == 0 ){
    mysql_server.assign( default_mysql_server );
  }
  if( mysql_user.length() == 0 ){
    mysql_user.assign( default_mysql_user );
  }
  if( mysql_password.length() == 0 ){
    mysql_password.assign( default_mysql_password );
  }
  if( mysql_database.length() == 0 ){
    mysql_database.assign( default_mysql_database );
  }
#endif

  // Textfile plugin
#ifdef HAVE_FILE_PLUGIN
  if( textfile.length() == 0 ){
    textfile.assign( default_textfile );
  }
#endif

  // SIA
  if( sia_use_alt_control_blocks == -1 ) sia_use_alt_control_blocks = default_sia_use_alt_control_blocks;

  // global
  if( syslog_level == Syslog::Level::Invalid ) syslog_level = default_log_level;
  if( plugin_use_email == -1 ) plugin_use_email = default_use_plugin_email;
  if( plugin_use_mysql == -1 ) plugin_use_mysql = default_use_plugin_mysql;
  if( plugin_use_odbc == -1 ) plugin_use_odbc = default_use_plugin_odbc;
  if( plugin_use_file == -1 ) plugin_use_file = default_use_plugin_file;

  // Galaxy dip8
  if( galaxy_dip8 == -1 ) galaxy_dip8 = default_galaxy_dip8;

  // timeouts
  if( session_timeout_seconds == -1 ) session_timeout_seconds = default_session_timeout_seconds;
  if( blacklist_timeout_minutes == -1 ) blacklist_timeout_minutes = default_blacklist_timeout_minutes;

  if( iface.compare("") == 0 ) iface = default_iface;

  if( http_port == -1 ) http_port = default_http_port;
  if( https_port == -1 ) https_port = default_https_port;
}

bool Settings::read(const char* filename)
{

  std::ifstream ifs; // new input file stream
  ifs.exceptions( std::ifstream::failbit | std::ifstream::badbit ); // throw exceptions for logical and r/w io-failures

  // free any malloced config vars and set empty values
  clear();

  // Open the configuration file and read the values 

  try {
    ifs.open( filename );
    ifs.exceptions( std::ifstream::badbit ); // modify exceptions: remove failbit (ie do not throw an exception for eof)

    int line_nr = 0;

    // For every line that is read...
    while( !ifs.eof() ){
      char buffer[1024]; // this is also the max length of a line in the config file...
      char *p, *name, *value, *saveptr;
      int len;

      // Read a line
      ifs.getline( buffer, sizeof buffer );
      line_nr++;

      // Remove CRs and LFs
      p = buffer;
      p += std::char_traits<char>::length( p );
      while( p > buffer && ( p[-1] == '\n' || p[-1] == '\r' ) ) *--p = '\0';

      // Skip whitespaces and tabs at the beginning of the line.
      p = buffer;
      while( *p == ' ' || *p == '\t' ) p++;

      // Skip comment lines.
      if( *p == '#' ) continue;

      // Get the name of the variable
      name = strtok_r( p, "=#", &saveptr );
      if( name == NULL ) continue; // line was empty
      len = std::char_traits<char>::length( name ) - 1;
      while( name[len] == ' ' || name[len] == '\t' ) name[len--] = '\0';

      // Get the value for the variable
      value = strtok_r( NULL, "#", &saveptr );
      if( value == NULL ) continue; // value was empty
      len = std::char_traits<char>::length( value ) - 1;
      while( value[len] == ' ' || value[len] == '\t' ) value[len--] = '\0';
      if( len ) while( *value == ' ' || *value == '\t' ) value++;
      if( len<=0 ) continue; // value was empty
      if( std::char_traits<char>::length( value ) == 0 ) continue; // value was empty

      // BaudRate
      if( strcmp( name, "BAUDRATE" ) == 0 ){ 
        receiver_baudrate = std::strtoul( value, NULL, 10 );
#if __linux__
        switch (receiver_baudrate) {
          case 300:
            receiver_baudrate_termios = B300;
            break;
          case 600:
            receiver_baudrate_termios = B600;
            break;
          case 1200:
            receiver_baudrate_termios = B1200;
            break;
          case 2400:
            receiver_baudrate_termios = B2400;
            break;
          case 4800:
            receiver_baudrate_termios = B4800;
            break;
          case 9600:
            receiver_baudrate_termios = B9600;
            break;
          case 19200:
            receiver_baudrate_termios = B19200;
            break;
          case 38400:
            receiver_baudrate_termios = B38400;
            break;
          case 57600:
            receiver_baudrate_termios = B57600; // Internal RS232 only
            break;
          default:
            throw new std::runtime_error( "Warning: Invalid baudrate in configuration file! " );
        }
#else
        switch (receiver_baudrate) {
          case 300:
          case 600:
          case 1200:
          case 2400:
          case 4800:
          case 9600:
          case 19200:
          case 38400:
          case 57600:
            break;
          default:
            throw new std::runtime_error( "Error: Invalid baudrate in configuration file! " );
            return 0;
        }
#endif
      }

      else if( strcmp( name,"REMOTE-CODE" ) == 0 ){
        char* s = strtok_r( value, " \t", &saveptr );
        if( s ) remote_code.assign( s );
      }

      else if( strcmp( name,"SERIALPORT" ) == 0 ){
        char* s = strtok_r( value, " \t", &saveptr );
        if( s ) receiver_tty.assign( s );
      }

      else if( strcmp( name, "EMAIL-RECIPIENTS" ) == 0 ){
#ifdef HAVE_EMAIL_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) email_recipients.assign( s );
#endif
      }

      else if( strcmp( name, "SIA-LEVEL" ) == 0 ){
	      opengalaxy().syslog().error( "Warning: The use of SIA-LEVEL is deprecated: in configuration file: %s", filename );
      }

      else if( strcmp( name, "FROM-NAME" ) == 0 ){
#ifdef HAVE_EMAIL_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) email_from_name.assign( s );
#endif
      }

      else if( strcmp( name, "FROM-ADDRESS" ) == 0 ){
#ifdef HAVE_EMAIL_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) email_from_address.assign( s );
#endif
      }

      else if( strcmp( name, "LOG-LEVEL" ) == 0 ){
        int lvl = strtol( value, NULL, 10 );
        switch( lvl ){
          case 0:
            default_log_level = Syslog::Level::Invalid;
            break;
          case 1:
            default_log_level = Syslog::Level::Error;
            break;
          case 2:
            default_log_level = Syslog::Level::Info;
            break;
          case 3:
            default_log_level = Syslog::Level::Debug;
            break;
          default:
            opengalaxy().syslog().error( "Warning: Invalid LOG-LEVEL(%d) in configuration file (ignored)!", lvl );
            default_log_level = Syslog::Level::Info;
            break;
        }
      }

      else if( strcmp( name, "MYSQL-SERVER" ) == 0 ){
#ifdef HAVE_MYSQL_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) mysql_server.assign( s );
#endif
      }

      else if( strcmp( name,"MYSQL-USER") == 0 ){
#ifdef HAVE_MYSQL_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) mysql_user.assign( s );
#endif
      }

      else if( strcmp( name, "MYSQL-PASSWORD" ) == 0 ){
#ifdef HAVE_MYSQL_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) mysql_password.assign( s );
#endif
      }

      else if( strcmp( name, "MYSQL-DATABASE" ) == 0 ){
#ifdef HAVE_MYSQL_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) mysql_database.assign( s );
#endif
      }

      else if( strcmp( name, "TEXT-FILE" ) == 0 ){
#ifdef HAVE_FILE_PLUGIN
        char* s = strtok_r( value, "", &saveptr );
        if( s ) textfile.assign( s );
#endif
      }

      else if( strcmp( name, "USE-EMAIL-PLUGIN" ) == 0 ){
        char *tmp = thread_safe_strdup( strtok_r( value, "", &saveptr ) );
        plugin_use_email = is_yes_or_no( tmp );
        thread_safe_free( tmp );
      }

      else if( strcmp( name, "USE-MYSQL-PLUGIN" ) == 0 ){
        char *tmp = thread_safe_strdup( strtok_r( value, "", &saveptr ) );
        plugin_use_mysql = is_yes_or_no( tmp );
        thread_safe_free( tmp );
      }

      else if( strcmp( name, "USE-ODBC-PLUGIN" ) == 0 ){
        char *tmp = thread_safe_strdup( strtok_r( value, "", &saveptr ) );
        plugin_use_odbc = is_yes_or_no( tmp );
        thread_safe_free( tmp );
      }

      else if( strcmp( name, "USE-FILE-PLUGIN" ) == 0 ){
        char *tmp = thread_safe_strdup( strtok_r( value, "", &saveptr ) );
        plugin_use_file = is_yes_or_no( tmp );
        thread_safe_free( tmp );
      }

      else if( strcmp( name, "ALT-CONTROL-BLOCKS" ) == 0 ){
        char *tmp = thread_safe_strdup( strtok_r( value, "", &saveptr ) );
        sia_use_alt_control_blocks = is_yes_or_no( tmp );
        thread_safe_free( tmp );
      }

      else if( strcmp( name, "DIP8" ) == 0 ){
        char *tmp = thread_safe_strdup( strtok_r( value, "", &saveptr ) );
        galaxy_dip8 = is_yes_or_no( tmp );
        thread_safe_free( tmp );
      }

      else if( strcmp( name, "BLACKLIST-TIMEOUT-MINUTES" ) == 0 ){
        int timeout = strtol( value, NULL, 10 );
        if( timeout > 0 ) blacklist_timeout_minutes = timeout;
        else {
          opengalaxy().syslog().error( "Error: Error on line %d in configuration file: %s", line_nr, filename );
          throw new std::runtime_error("BLACKLIST-TIMEOUT-MINUTES must be greater then 0!");
        }
      }

      else if( strcmp( name, "SESSION-TIMEOUT-SECONDS" ) == 0 ){
        int timeout = strtol( value, NULL, 10 );
        if( timeout > 0 ) session_timeout_seconds = timeout;
        else {
          opengalaxy().syslog().error( "Error: Error on line %d in configuration file: %s", line_nr, filename );
          throw new std::runtime_error("SESSION-TIMEOUT-SECONDS must be greater then 0!");
        }
      }

      else if( strcmp( name, "IFACE" ) == 0 ){
        iface.assign( strtok_r( value, "", &saveptr ) );
      }

      else if( strcmp( name, "HTTP-PORT" ) == 0 ){
        http_port = strtol( value, NULL, 10 );
      }

      else if( strcmp( name, "HTTPS-PORT" ) == 0 ){
        https_port = strtol( value, NULL, 10 );
      }

      else {
        opengalaxy().syslog().error( "Error: Syntax error on line %d in configuration file: %s", line_nr, filename );
        throw new std::runtime_error("Syntax error!");
      }

      // Parse next line.
    }

    // Close the configuration file
    ifs.close();
  }
  catch( std::ios_base::failure& ex ){
    defaults();
    opengalaxy().syslog().set_level(syslog_level);
    // opengalaxy().syslog().error( "Error reading configuration file '%s': %s", filename, ex.code().message().c_str() ); //<- does not work yet with gcc
    opengalaxy().syslog().error( "Error: Could not read configuration file '%s' (%s)", filename, ex.what() );
    return false;
  }

  // Set a default value if a variable was not found in the config file...
  //
  defaults();

  // Apply the (new) syslog level
  opengalaxy().syslog().set_level(syslog_level);

  return true;
}

} // ends namespace openGalaxy

