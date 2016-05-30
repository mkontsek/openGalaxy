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

#ifdef HAVE_FILE_PLUGIN 
#include "Output-Text.hpp"
#endif

#ifdef HAVE_EMAIL_PLUGIN 
#include "Output-Email.hpp"
#endif

#ifdef HAVE_MYSQL_PLUGIN 
#include "Output-Mysql.hpp"
#endif

#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>

#include "opengalaxy.hpp"

namespace openGalaxy {

bool NullOutput::write(class SiaEvent& msg) {
  return true;
}

const char *NullOutput::name()
{
  return (const char*)"Null output";
}

const char *NullOutput::description()
{
  return (const char*)"Send messages to websocket clients only";
}


Output::Output(class openGalaxy& opengalaxy)
 : m_openGalaxy(opengalaxy)
{
#ifdef HAVE_FILE_PLUGIN 
  if(m_openGalaxy.settings().plugin_use_file > 0){
    m_plugins.append( new TextfileOutput(m_openGalaxy) );
  }
#endif

#if !defined(HAVE_WINDOWS)
#if defined(HAVE_EMAIL_PLUGIN)
  if(m_openGalaxy.settings().plugin_use_email > 0){
    m_plugins.append( new EmailOutput(m_openGalaxy) );
  }
#endif
#endif

#ifdef HAVE_MYSQL_PLUGIN 
  if(m_openGalaxy.settings().plugin_use_mysql > 0){
    m_plugins.append( new MySqlOutput(m_openGalaxy) );
  }
#endif

  // Use the null-output plugin if no other plugins are used.
  if(m_plugins.size() == 0){
    m_plugins.append( new NullOutput(m_openGalaxy) );
  }

  // Log the active plugins
  m_openGalaxy.syslog().info("Active output plugins:");
  for(int t=0; t<m_plugins.size(); t++){
    m_openGalaxy.syslog().info(
    " - %s (%s).",
      m_plugins[t]->name(),
      m_plugins[t]->description()
    );
  }

  m_thread = new std::thread(Output::Thread, this);
}

Output::~Output()
{
  delete m_thread;
}

void Output::notify()
{
  m_cv_notified = true;
  m_request_cv.notify_one();
}

void Output::join() {
  m_thread->join();
  if(m_Plugin_exptr) std::rethrow_exception(m_Plugin_exptr);
}

void Output::write(SiaEvent& msg)
{
  // Add a copy of the message to the list of messages to output
  m_mutex.lock();
  m_messages.append( new SiaEvent(msg) );
  m_mutex.unlock();
  notify();
}

void Output::json_encode(std::stringstream& json, SiaEvent& msg)
{
  // Get current date/time if we do not have date or time in the SIA message
  time_t t;
  struct tm tm;
  memset( &tm, 0, sizeof(struct tm));
  if(msg.haveDate==0 || msg.haveTime==0) {
    t = time(nullptr);
    tm = *localtime(&t);
  }

  char fmt_date[] = "%d-%d-%d";
  char fmt_time[] = "%d:%d:%d";
  char sia_date[16], sia_time[16];
  const char *_date = nullptr, *_time = nullptr;

  // set the date and time to the ones in the message if present or the local time if not
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

  json << "{";

  json << "\"AccountID\": " << msg.accountId << ",";
  json << "\"EventCode\": \"" << msg.event->letter_code.c_str() << "\",";
  json << "\"EventName\": \"" << msg.event->name.c_str() << "\",";
  json << "\"EventDesc\": \"" << msg.event->desc.c_str() << "\",";
  json << "\"EventAddressType\": \"" << msg.addressType.c_str() << "\",";

  if( msg.addressNumber > 0 )
    json << "\"EventAddressNumber\": " << msg.addressNumber << ",";
  else
    json << "\"EventAddressNumber\": null,";

  json << "\"Date\": \"" << _date << "\",";
  json << "\"Time\": \"" << _time << "\",";

  if( msg.haveAscii == true )
    json << "\"ASCII\": \"" << msg.ascii.c_str() << "\",";
  else
    json << "\"ASCII\": \"null\",";

  if( msg.haveSubscriberId == true )
    json << "\"SubscriberID\": " << msg.subscriberId << ",";
  else
    json << "\"SubscriberID\": null,";

  if( msg.haveAreaId == true )
    json << "\"AreaID\": " << msg.areaId << ",";
  else
    json << "\"AreaID\": null,";

  if( msg.havePeripheralId == true )
    json << "\"PeripheralID\": " << msg.peripheralId << ",";
  else
    json << "\"PeripheralID\": null,";

  if( msg.haveAutomatedId == true )
    json << "\"AutomatedID\": " << msg.automatedId << ",";
  else
    json << "\"AutomatedID\": null,";

  if( msg.haveTelephoneId == true )
    json << "\"TelephoneID\": " << msg.telephoneId << ",";
  else
    json << "\"TelephoneID\": null,";

  if( msg.haveLevel == true )
    json << "\"Level\": " << msg.level << ",";
  else
    json << "\"Level\": null,";

  if( msg.haveValue == true )
    json << "\"Value\": " << msg.value << ",";
  else
    json << "\"Value\": null,";

  if( msg.havePath == true )
    json << "\"Path\": " << msg.path << ",";
  else
    json << "\"Path\": null,";

  if( msg.haveRouteGroup == true )
    json << "\"RouteGroup\": " << msg.routeGroup << ",";
  else
    json << "\"RouteGroup\": null,";

  if( msg.haveSubSubscriber == true )
    json << "\"SubSubscriber\": " << msg.subSubscriber << ",";
  else
    json << "\"SubSubscriber\": null,";

/*
  size_t raw_len;
  unsigned char *raw_b64 = b64.encode(msg.raw.block.data, msg.raw.block.header.block_length, &raw_len);
  json << "\"Raw\": \"";
  for(size_t i=0; i<raw_len; i++) json << raw_b64[i];
  json << "\"";
  delete[] raw_b64;
*/
  size_t raw_len;
  char *raw_b64;
  if(!ssl_base64_encode(msg.raw.block.data, msg.raw.block.header.block_length, &raw_b64, &raw_len)){
    opengalaxy().syslog().error("%s: could not base64 encode!", __func__);
  }
  else{
    json << "\"Raw\": \"" << raw_b64 << "\"";
    ssl_free(raw_b64);
  }

  json << "}";
}

void Output::Thread(Output* output)
{
  using namespace std::chrono;
  try {
    int loop_delay = 1;
    std::unique_lock<std::mutex> lck(output->m_request_mutex);

    // The outer loop only exits if the openGalaxy object is being destroyed.
    // The inner loop iterates once every 'loop_delay' seconds, 
    // or sooner when NotifyWorkerThread() is called.

    // Outer loop: test if it is time to exit
    while(output->opengalaxy().isQuit()==false){

      // Inner loop: test if we were notified (or otherwise sleep untill we timeout) and do a loop iteration if we were/did
      while(output->m_cv_notified || output->m_request_cv.wait_for(lck,seconds(loop_delay))==std::cv_status::timeout){

        // reset our notification variable
        output->m_cv_notified = false;

        // Test if we need to exit the thread.
        if(output->opengalaxy().isQuit()==true) break;

        // If there is at least one message to output then;
        while(output->m_messages.size() > 0 && output->opengalaxy().isQuit()==false){

          // 'pop' a message from the array
          output->m_mutex.lock();
          SiaEvent *msg = new SiaEvent(*output->m_messages[0]);
          output->m_messages.remove(0);
          output->m_mutex.unlock();

          // Prepare the JSON formatted output to send through the websocket
          std::stringstream ss;
          output->json_encode(ss, *msg);
          std::string json = ss.str();

          // Send it to the websocket
          output->opengalaxy().websocket().broadcast(json);

          // Write it to all the plugins,
          for(int nPlugin = 0; nPlugin < output->m_plugins.size(); nPlugin++){
            if(output->opengalaxy().isQuit()==true) break;
            output->m_plugins[nPlugin]->write(*msg);
          }

          // and then throw it away
          delete msg;

          // Yield before processing the next message
          std::this_thread::yield();
        }
      } // ends inner loop
    } // ends outer loop
    output->opengalaxy().syslog().debug("Output::Thread exited normally");
  }
  catch(...){
    output->opengalaxy().syslog().error("Output::Thread has thrown an exception!");
    // pass the exception on to the main() thread
    output->opengalaxy().m_Output_exptr = std::current_exception();
    output->opengalaxy().exit();
  }
}

} // Ends namespace openGalaxy

