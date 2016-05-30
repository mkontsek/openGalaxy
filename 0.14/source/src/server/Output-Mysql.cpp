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
#include "Output.hpp"
#include "Output-Mysql.hpp"

#include <mysql.h>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>

#include "opengalaxy.hpp"

namespace openGalaxy {

const char *MySqlOutput::name()
{
  return (const char*)"MySQL output";
}

const char *MySqlOutput::description()
{
  return (const char*)"Send messages to a MySQL database";
}

MySqlOutput::MySqlOutput(class openGalaxy& opengalaxy)
 : OutputPlugin(opengalaxy)
{
  m_thread = new std::thread(MySqlOutput::Thread, this);
}

MySqlOutput::~MySqlOutput()
{
  notify();
  m_thread->join();
  delete m_thread;
}

bool MySqlOutput::write_db(class SiaEvent& msg)
{
  int len=1024;
  char q[len--],
       s[96],
       f[] = "INSERT INTO `Galaxy`.`SIA-Messages` VALUES( NULL, ",
       n[] = "NULL, ",
       fmt_u[] = "'%u', ",
       fmt_s[] = "'%s', ";

  // Get current date/time if we do not have date or time in the SIA message
  time_t t;
  struct tm tm;
  memset( &tm, 0, sizeof(struct tm));
  if(msg.haveDate==0 || msg.haveTime==0) {
    t = time(nullptr);
    tm = *localtime(&t);
  }

  // set _date and _time to the ones in the message if present or the local time if not
  char fmt_date[] = "%d-%d-%d";
  char fmt_time[] = "%d:%d:%d";
  char sia_date[16], sia_time[16];
  const char *_date = nullptr, *_time = nullptr;
  if(msg.haveDate) {
    _date = msg.date.get().c_str();
  }
  else {
    snprintf(sia_date, 16, fmt_date, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    _date = sia_date;
  }
  if(msg.haveTime) {
    _time = msg.time.get().c_str();
  }
  else {
    snprintf(sia_time, 16, fmt_time, tm.tm_hour, tm.tm_min, tm.tm_sec);
    _date = sia_date;
  }

  // Compose the query (q)

  memset( q, 0, len );
  strncat( q, f, len );
  len -= strlen( f );

  snprintf( s, 96, fmt_u, msg.accountId );
  strncat( q, s, len );
  len -= strlen( s );

  snprintf( s, 96, fmt_s, msg.event->letter_code.c_str() );
  strncat( q, s, len );
  len -= strlen( s );

  snprintf( s, 96, fmt_s, msg.event->name.c_str() );
  strncat( q, s, len );
  len -= strlen( s );

  snprintf( s, 96, fmt_s, msg.event->desc.c_str() );
  strncat( q, s, len );
  len -= strlen( s );

  snprintf( s, 96, fmt_s, msg.addressType.c_str() );
  strncat( q, s, len );
  len -= strlen( s );

  if( msg.addressNumber > 0 ) {
    snprintf( s, 96, fmt_u, msg.addressNumber );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  snprintf( s, 96, "'%s %s', ", _date, _time );
  strncat( q, s, len );
  len -= strlen( s );

  // If any of the following are empty, set to NULL in the database

  if( msg.haveAscii == true ){
    snprintf( s, 96, fmt_s, msg.ascii.c_str() );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveSubscriberId ){
    snprintf( s, 96, fmt_u, msg.subscriberId );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveAreaId ){
    snprintf( s, 96, fmt_u, msg.areaId );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.havePeripheralId ){
    snprintf( s, 96, fmt_u, msg.peripheralId );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveAutomatedId ){
    snprintf( s, 96, fmt_u, msg.automatedId );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveTelephoneId ){
    snprintf( s, 96, fmt_u, msg.telephoneId );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveLevel ){
    snprintf( s, 96, fmt_u, msg.level );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveValue ){
    snprintf( s, 96, fmt_u, msg.value );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.havePath ){
    snprintf( s, 96, fmt_u, msg.path );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveRouteGroup ){
    snprintf( s, 96, fmt_u, msg.routeGroup );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  if( msg.haveSubSubscriber ){
    snprintf( s, 96, fmt_u, msg.subSubscriber );
    strncat( q, s, len );
    len -= strlen( s );
  } else {
    strncat( q, n, len );
    len -= strlen( s );
  }

  snprintf( s, 96, fmt_s, msg.raw.block.message );
  strncat( q, s, len );
  len -= strlen( s );

  strncat( q, "0);", len );

  opengalaxy().syslog().debug("Output MySQL: Query = %s", q);

  if(mysql_query(connector, q)){
    opengalaxy().syslog().error("Output MySQL: %s\n", mysql_error(connector));
    return false;
  }

  return true;
}

void MySqlOutput::Thread(MySqlOutput* _this)
{
  using namespace std::chrono;
  try {
    int loop_delay = 1;
    std::unique_lock<std::mutex> lck(_this->m_request_mutex);

    _this->opengalaxy().syslog().debug(
      "Output MySQL: Server: '%s'",
      _this->opengalaxy().settings().mysql_server.c_str()
    );
    _this->opengalaxy().syslog().debug(
      "Output MySQL: User: '%s'",
      _this->opengalaxy().settings().mysql_user.c_str()
    );
    /*
    _this->opengalaxy().syslog().debug(
      "Output MySQL: Password: '%s'",
      _this->opengalaxy().settings().mysql_password.c_str()
    );
    */
    _this->opengalaxy().syslog().debug(
      "Output MySQL: Database: '%s'",
      _this->opengalaxy().settings().mysql_database.c_str()
    );

    mysql_library_init(-1, nullptr, nullptr);
    mysql_thread_init();
    _this->connector = mysql_init(nullptr);

    // set MySQL options
    bool autoreconnect = true;
    unsigned int timeout_seconds = 30;
    mysql_options(_this->connector, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_seconds);
    mysql_options(_this->connector, MYSQL_OPT_RECONNECT, &autoreconnect); // Automaticly reconnect to MySQL server after a connection timeout
    mysql_options(_this->connector, MYSQL_INIT_COMMAND, "SET NAMES 'UTF8'");

    // Connect to database
    if(!mysql_real_connect(
      _this->connector,
      _this->opengalaxy().settings().mysql_server.c_str(),
      _this->opengalaxy().settings().mysql_user.c_str(),
      _this->opengalaxy().settings().mysql_password.c_str(),
      _this->opengalaxy().settings().mysql_database.c_str(),
      0,
      nullptr,
      0
    )){
      _this->opengalaxy().syslog().error("Output MySQL: %s", mysql_error(_this->connector));
    }
    else _this->opengalaxy().syslog().debug("Output MySQL: Successfully connected to database");

    // Defeat a pre version 5.1.6 MySQL bug (where mysql_real_connect() resets the reconect option).
    mysql_options(_this->connector, MYSQL_OPT_RECONNECT, &autoreconnect);

    // Outer loop: test if it is time to exit
    while(_this->opengalaxy().isQuit()==false){

      // Inner loop: test if we were notified (or otherwise sleep untill we timeout) and do a loop iteration if we were/did
      while(_this->m_cv_notified || _this->m_request_cv.wait_for(lck,seconds(loop_delay))==std::cv_status::timeout){

        // reset our notification variable
        _this->m_cv_notified = false;

        // Test if we need to exit the thread.
        if(_this->opengalaxy().isQuit()==true) break;

        // If there is at least one message to output then;
        while(_this->m_messages.size() > 0 && _this->opengalaxy().isQuit()==false){

          // 'pop' a message from the array
          _this->m_mutex.lock();
          SiaEvent *msg = new SiaEvent(*_this->m_messages[0]);
          _this->m_messages.remove(0);
          _this->m_mutex.unlock();

          // write the message to the database
          if(_this->write_db(*msg) == false){
            // failed to write to database, try again after reconnecting to the SQL server
            mysql_thread_end();
            mysql_library_end();
            autoreconnect = true;
            mysql_library_init( -1, nullptr, nullptr);
            mysql_thread_init();
            _this->connector = mysql_init(nullptr);
            mysql_options(_this->connector, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_seconds);
            mysql_options(_this->connector, MYSQL_OPT_RECONNECT, &autoreconnect); // Automaticly reconnect to MySQL server after a connection timeout
            mysql_options(_this->connector, MYSQL_INIT_COMMAND, "SET NAMES 'UTF8'");
            if(!mysql_real_connect(
              _this->connector,
              _this->opengalaxy().settings().mysql_server.c_str(),
              _this->opengalaxy().settings().mysql_user.c_str(),
              _this->opengalaxy().settings().mysql_password.c_str(),
              _this->opengalaxy().settings().mysql_database.c_str(),
              0,
              nullptr,
              0
            )){
              _this->opengalaxy().syslog().error("Output MySQL: %s", mysql_error(_this->connector));
            }
            else {
              mysql_options(_this->connector, MYSQL_OPT_RECONNECT, &autoreconnect);
              _this->opengalaxy().syslog().error("Output MySQL: Successfully re-connected to database");
            }
            if(_this->write_db(*msg) == false)
              _this->opengalaxy().syslog().error("Output MySQL: ERROR: MESSAGE LOST!: %s", mysql_error(_this->connector));
          }

          // and then throw it away
          delete msg;

          // Yield before processing the next message
          std::this_thread::yield();
        }
      } // ends inner loop
    } // ends outer loop

    mysql_close(_this->connector); // close connection to db
    mysql_thread_end();
    mysql_library_end(); // cleanup

    _this->opengalaxy().syslog().debug("MySqlOutput::Thread exited normally");
  }
  catch(...){
    // pass the exception on to the main output thread
    _this->opengalaxy().output().m_Plugin_exptr = std::current_exception();
    _this->opengalaxy().exit();
  }
}

void MySqlOutput::notify()
{
  m_cv_notified = true;
  m_request_cv.notify_one();
}

bool MySqlOutput::write(class SiaEvent& msg)
{
  // Add a (new) copy of the message to the list of messages to write to the database
  m_mutex.lock();
  m_messages.append( new SiaEvent(msg) );
  m_mutex.unlock();
  notify();
  return true;
}

} // Ends namespace openGalaxy

