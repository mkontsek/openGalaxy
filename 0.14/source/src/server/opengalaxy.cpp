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
#include "opengalaxy.hpp"
#include "libwebsockets.h"

#include <thread>
#include <mutex>
#include <condition_variable>

#include <iostream>
#include <thread>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

namespace openGalaxy {

static const char* header1 =
  "openGalaxy " VERSION " - SIA receiver for Galaxy security control panels.";

static const char* header2 =
  "Copyright (C) 2015-2016 Alexander Bruines <" PACKAGE_BUGREPORT ">";

static const char* header3 =
  "License: GNU GPL v2+ with OpenSSL exception.";

static struct option cmd_line_options[] = {
    { "help",                   no_argument,       nullptr, 'h' },
    { "license",                no_argument,       nullptr, 'l' },
    { "version",                no_argument,       nullptr, 'v' },
    { "no-client-certs",        no_argument,       nullptr, 'n' },
    { "disable-ssl",            no_argument,       nullptr, 'd' },
    { "disable-password",       no_argument,       nullptr, 'p' },
    { "disable-auto-logoff",    no_argument,       nullptr, 'a' },
    { NULL, 0, 0, 0 }
  };

static const char* synopsis =
  "\n"
  "Synopsis: opengalaxy [-h] [-l] "
  "[-v] "
  "[-n] [-d] [-a]"
  "\n"
  "\n"
  " -h or --help\t\t\tPrints this help text and exit.\n"
  " -l or --license\t\tDisplay the license for openGalaxy and exit.\n"
  " -v or --version\t\tPrints openGalaxy's version number then exits.\n"
  " -d or --disable-ssl\t\tDisable SSL entirely (implies -n).\n"
  " -n or --no-client-certs\tDo not require client certificates (implies -p)\n"
  " -p or --disable-password\tDo not require that clients enter a username\n"
  "\t\t\t\tand password to log on (implies -a).\n"
  " -a or --disable-auto-logoff\tDisable automaticly logging off clients\n"
  "\t\t\t\twhen they have been inactive for a while.\n"
  "\n";

static const char* licence =
  "\n"
  "This program is free software: you can redistribute it and/or modify\n"
  "it under the terms of the GNU General Public License version 2 as\n"
  "as published by the Free Software Foundation, or (at your option)\n"
  "any later version.\n"
  "\n"
  "In addition, as a special exception, the author of this program\n"
  "gives permission to link the code of its release with the OpenSSL\n"
  "project's \"OpenSSL\" library (or with modified versions of it that\n"
  "use the same license as the \"OpenSSL\" library), and distribute the\n"
  "linked executables. You must obey the GNU General Public License\n"
  "in all respects for all of the code used other than \"OpenSSL\".\n"
  "If you modify this file, you may extend this exception to your\n"
  "version of the file, but you are not obligated to do so.\n"
  "If you do not wish to do so, delete this exception statement\n"
  "from your version.\n"
  "\n"
  "This program is distributed in the hope that it will be useful,\n"
  "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
  "GNU General Public License for more details.\n"
  "\n"
  "You should have received a copy of the GNU General Public License\n"
  "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n"
  "\n"
  "Acknoledgements:\n"
  "\n"
  "openGalaxy is based in part on the work of the libwebsockets project\n"
  "(http://libwebsockets.org)\n"
  "\n"
#ifdef HAVE_MYSQL_PLUGIN
  "openGalaxy makes use of MySQL Connector/C (libmysqlclient) which is\n"
  "released under the GNU General Public License version 2 and Copyright (c)\n"
  "2000, 2014, Oracle and/or its affiliates. All rights reserved.\n"
  "\n"
#endif
#ifdef HAVE_OPENSSL
  "This product includes software developed by the OpenSSL project for use\n"
  "in the OpenSSL Toolkit. (http://www.openssl.org/)\n"
  "\n"
#endif
  ;


openGalaxy::openGalaxy(context_options& options)
 : m_options(options)
{
  m_mutex.lock();
  m_quit = false;

  exit_status = EXIT_STATUS_AS_REQUESTED;

  m_Receiver_exptr = nullptr;
  m_Websocket_exptr = nullptr;
  m_Commander_exptr = nullptr;
  m_Output_exptr = nullptr;
  m_Poll_exptr = nullptr;

  // Initialize the mutex for the exit() and isQuit() member functions
  m_lock = new std::unique_lock<std::mutex>(m_lock_mutex);

  // Create instances of Syslog and Settings objects
  m_Syslog = new Syslog();                        // Syslog must be 1st

  // Output banner to the log
  syslog().write(Syslog::Level::Always, header1); // name/description
  syslog().write(Syslog::Level::Always, header2); // copyright
  syslog().write(Syslog::Level::Always, header3); // license
  syslog().write(Syslog::Level::Always, "");

  // This also loads the settings from the configuration file
  m_Settings = new Settings(this);                // Settings must be 2nd

  syslog().info("Compiled with libwebsockets version %s", lws_get_library_version());
  syslog().info("Compiled with %s", SSLeay_version(SSLEAY_VERSION));

  switch(syslog().get_level()){
    case Syslog::Level::Error:
      syslog().info("Log level set to 1 (errors and warnings only).");
      break;
    case Syslog::Level::Info:
      syslog().info("Log level set to 2 (default).");
      break;
    case Syslog::Level::Debug:
      syslog().info("Log level set to 3 (All messages).");
      break;
    default:
      break;
  }

  if( m_options.no_ssl ){
    syslog().error("Warning: Disabling SSL !");
  }
  else {
    if( m_options.no_client_certs ){
      syslog().error("Warning: Disabling SSL Client Authentication!");
    }
    else {
      if( m_options.no_password ){
        syslog().error("Warning: Disabling username/password authorization!");
      }
    }
    if( m_options.auto_logoff ){
      syslog().info(
        "Automaticly logging off clients after %u seconds of inactivity.",
        m_Settings->session_timeout_seconds
      );
    }
  }

  if(m_Settings->galaxy_dip8)
    syslog().info("Galaxy dipswitch 8 position configured as 'ON'.");

  m_Galaxy = new Galaxy(*this);
  m_SIA = new SIA(*this);
  m_Output = new Output(*this);

  // Open the serial port
  // (this blocks for a while on windows if the port does not exist)
  syslog().info(
    "Using serial port %s (%u Baud 8N1).",
    m_Settings->receiver_tty.c_str(),
    m_Settings->receiver_baudrate
  );
  m_Serial = new SerialPort(*this);
  if(m_Serial->isOpen() == false){
    syslog().error(
      "WARNING: CONTINUING WITHOUT SERIAL PORT CONNECTION!"
    );
  }

  m_Receiver = new Receiver(*this);
  m_Commander = new Commander(*this);
  m_Poll = new Poll(*this);
  m_Websocket = new Websocket(this);

  m_mutex.unlock();
}


openGalaxy::~openGalaxy()
{
  if(!isQuit()) exit();
  if(m_Poll) delete m_Poll;
  if(m_Commander) delete m_Commander;
  if(m_Receiver) delete m_Receiver;
  if(m_Websocket) delete m_Websocket;
  if(m_Output) delete m_Output;
  if(m_SIA) delete m_SIA;
  if(m_Galaxy) delete m_Galaxy;
  if(m_Serial) delete m_Serial;
  if(m_Settings) delete m_Settings;
  if(m_Syslog) delete m_Syslog;
}


void openGalaxy::exit()
{
  syslog().info("Quit signal received");

  // Unlock m_quit so everybody knows it is time to exit
  m_mutex.lock();
  m_quit = true;
  m_mutex.unlock();

  // Notify the worker threads and wait until they exit
  try {
    poll().notify();
    poll().join();
  }
  catch(...) {
    m_Poll_exptr = std::current_exception();
  }

  try {
    receiver().notify();
    receiver().join();
  }
  catch(...) {
    m_Receiver_exptr = std::current_exception();
  }

  try {
    commander().notify();
    commander().join();
  }
  catch(...) {
    m_Commander_exptr = std::current_exception();
  }

  try {
    output().notify();
    output().join();
  }
  catch(...) {
    m_Output_exptr = std::current_exception();
  }

  // notify our wait() method
  m_lock_cv.notify_one();
}


void openGalaxy::rethrow_thread_exceptions()
{
  // this function re-throws any caught exception
  // in a worker thread in te current thread

   // re-throw any exception from the receiver thread
  if(m_Receiver_exptr) std::rethrow_exception(m_Receiver_exptr);

  // re-throw any exception from the websocket thread
  if(m_Websocket_exptr) std::rethrow_exception(m_Websocket_exptr);

  // re-throw any exception from the commander thread
  if(m_Commander_exptr) std::rethrow_exception(m_Commander_exptr);

  // re-throw any exception from the output thread(s)
  if(m_Output_exptr) std::rethrow_exception(m_Output_exptr);

  // re-throw any exception from the poll thread
  if(m_Poll_exptr) std::rethrow_exception(m_Poll_exptr);
}


void openGalaxy::wait()
{
  m_lock_cv.wait(*m_lock);     // block until exit() has been called,
  rethrow_thread_exceptions(); // then re-throw any exception
}


volatile bool openGalaxy::isQuit()
{
  m_mutex.lock();
  bool retv = m_quit;
  m_mutex.unlock();
  return retv;
}


bool context_options::parse_command_line(int argc, char *argv[])
{
  if(argc==0 || !argv) return true;
  int opt_index;
  int n = 0;
  bool quit = false;

  while( n >= 0 ){
    n = getopt_long( argc, argv, "hlnvdpa"
      , cmd_line_options, &opt_index
    );
    if( n < 0 ) continue;
    switch( n ){
      case 'h':
      case 'l':
        std::cout << std::endl << header1 << std::endl << header2 << std::endl;
        if( n == 'h' ){
          std::cout << synopsis;
        } else {
          std::cout << licence;
        }
        quit = true;
        break;
      case 'v':
        std::cout << VERSION << std::endl;
        quit = true;
        break;
      case 'n':
        no_client_certs = 1;
        auto_logoff = 0;
        break;
      case 'd':
        no_ssl = 1;
        auto_logoff = 0;
        break;
      case 'p':
        no_password = 1;
        auto_logoff = 0;
        break;
      case 'a':
        auto_logoff = 0;
        break;
      default:
        quit = true;
        break;
    }
  }

  if( no_password && auto_logoff ){
    std::cout <<
      "Error: "
      "--disable-password and --enable-auto-logoff cannot work together!\n" <<
      std::endl;
    quit = true;
  }

  return quit;
}


} // ends namespace openGalaxy



