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
#ifndef __OPENGALAXY_SERVER_SETTINGS_HPP__
#define __OPENGALAXY_SERVER_SETTINGS_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#if __linux__
#include <termios.h>
#endif

#include "opengalaxy.hpp"
#include "Syslog.hpp"

namespace openGalaxy {

// A convieniant place to store all settings
//
class Settings {
private:
  class openGalaxy *m_openGalaxy;

  // default value for the remote code
  std::string default_remote_code = "543210";

  // default values for the Galaxy connector
#if __linux__
  std::string default_receiver_tty = "/dev/ttyUSB0";
#else
  std::string default_receiver_tty = "COM1:";
#endif
  int default_receiver_baudrate = 9600;
#if __linux__
  tcflag_t default_receiver_baudrate_termios = B9600;
#endif

#ifdef HAVE_EMAIL_PLUGIN
  // default configuration values for the Email plugin
  std::string default_email_recipients   = "";
  std::string default_email_from_name    = "";
  std::string default_email_from_address = "";
#endif

#ifdef HAVE_MYSQL_PLUGIN
  // default configuration values for the MySQL plugin
  std::string default_mysql_server   = "localhost";
  std::string default_mysql_user     = "Galaxy";
  std::string default_mysql_password = "topsecret";
  std::string default_mysql_database = "Galaxy";
#endif

#ifdef HAVE_FILE_PLUGIN
  // initialized in the constructor
  std::string default_textfile;
#endif

  // default configuration values for the SIA receiver
  int default_sia_use_alt_control_blocks = 0;

  // default global configuration values
  Syslog::Level default_log_level = Syslog::Level::Info;
  int default_use_plugin_email = 0;
  int default_use_plugin_mysql = 0;
  int default_use_plugin_odbc = 0;
  int default_use_plugin_file = 0;

  // Galaxy dipswitch 8 position
  int default_galaxy_dip8 = 0;

  // default time afterwhich an inactive session times out
  int default_session_timeout_seconds = 60;

  // default blacklist timeout in minutes
  int default_blacklist_timeout_minutes = 3;

  // The default interface to bind the listen socket to (empty = all)
  std::string default_iface = "";

  // The default port to use in http/https mode
#if __linux__
  int default_http_port = 1500;
  int default_https_port = 1500;
#else
  int default_http_port = 80;
  int default_https_port = 443;
#endif


  void defaults( void );

public:
  std::string remote_code;          // The remote code for the Galaxy panel
  std::string receiver_tty;         // Serial port to use (ie '/dev/ttyS0' on linux or COM1 on windows)
  int receiver_baudrate = -1;       // Baudrate to use
#if __linux__
  tcflag_t receiver_baudrate_termios;   // As used by termios
#endif
#ifdef HAVE_EMAIL_PLUGIN
  std::string email_from_name;      // Name used in the from field when sending email
  std::string email_from_address;   // Email address used in the from field when sending email
  std::string email_recipients;     // Email addresses to send messages to. (Whitespace seperated list)
#endif
#ifdef HAVE_MYSQL_PLUGIN
  std::string mysql_server;         // MySQL server to use
  std::string mysql_user;           // MySQL user to connect with
  std::string mysql_password;       // MySQL user password to use
  std::string mysql_database;       // MySQL database to use
#endif
#ifdef HAVE_FILE_PLUGIN
  std::string textfile;             // Textfile output plugin's file to write
#endif
  Syslog::Level syslog_level = Syslog::Level::Invalid; // How much information to log
  int plugin_use_email = -1;        // Use the email plugin true/false
  int plugin_use_mysql = -1;        // Use the MySQL plugin true/false
  int plugin_use_odbc = -1;         // Use the ODBC plugin true/false
  int plugin_use_file = -1;         // Use the Textfile plugin true/false
  int galaxy_dip8 = -1;
  int sia_use_alt_control_blocks = -1;

  int session_timeout_seconds = -1;   // the time after which a login times out after inactivity
  int blacklist_timeout_minutes = -1; // the time after which a blaclisted ip address is removed from the list

  std::string iface = ""; // The interface to bind the listening socket to (empty = all)

  int http_port = -1; // The port to use in HTTP mode
  int https_port = -1; // The port to use in HTTPS mode

  // Variables that have hardcoded values under Linux but
  // that are stored in the registry under Windows
  //
  // configfile: location the configuration file
  //  - linux: [/usr[/local]]/etc/galaxy.conf
  //  - windows: HKCU\Software\openGalaxy\ConfigDirectory + "/galaxy.conf" (C:\Users\username\Documents\openGalaxy)
  //
  // www_root_directory
  //  - linux: [/usr[/local]]/share/galaxy/www
  //  - windows: HKCU\Software\openGalaxy\WebDirectory (C:\Program Files\openGalaxy\www)
  //
  // certificates_directory
  //  - linux: [/usr[/local]]/share/galaxy/ssl
  //  - windows: HKCU\Software\openGalaxy\DataDirectory + "/ssl" (C:\Users\username\Documents\openGalaxy)
  //
  std::string configfile;
  std::string www_root_directory;
  std::string certificates_directory;

  // Variables that have hardcoded values under Linux but
  // that are not used under Windows
#if __linux__
  // ssmtp_configfile: location the ssmtp configuration file
  //  [/usr[/local]]/etc/ssmtp.conf
  std::string ssmtp_configfile;
#endif

  Settings(openGalaxy *opengalaxy);
  ~Settings();

  private:

  void clear( void );               // Clear all settings and set default values
  bool read( const char* filename );// Read settings from filename and set defaults for settings that were not found

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return *m_openGalaxy; }
};

} // ends namespace openGalaxy

#endif

