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

// Prevent compilation on Windows
#if defined(HAVE_WINDOWS)
#warning Cowardly refusing to build the email output plugin on Windows
#else

#include "Syslog.hpp"
#include "Settings.hpp"
#include "tmalloc.hpp"
#include "Output.hpp"
#include "Output-Email.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>

#include "opengalaxy.hpp"

namespace openGalaxy {

const char *EmailOutput::name()
{
  return (const char*)"Email output";
}

const char *EmailOutput::description()
{
  return (const char*)"Send messages with ssmtp";
}

EmailOutput::EmailOutput(class openGalaxy& opengalaxy)
 : OutputPlugin(opengalaxy)
{
}

EmailOutput::~EmailOutput()
{
}

void EmailOutput::email_encode(std::stringstream& subject, std::stringstream& body, SiaEvent& msg)
{
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

  subject
    << '#'
    << msg.accountId
    << ':'
    << ' '
    << ((msg.haveEvent) ? msg.event->desc.c_str() : ((msg.haveAscii) ? msg.ascii.c_str() : "Unspecified report"));

  body
    << "Message from Account ID #" << msg.accountId << std::endl << std::endl
    << "Event\t\t: " << ((msg.haveEvent) ? msg.event->desc.c_str() : "-") << " (" << ((msg.haveEvent) ? msg.event->letter_code.c_str() : "none") << ')' << std::endl
    << "Address\t\t: " << msg.addressType.c_str();

  if(msg.addressNumber >= 0) body << msg.addressNumber;
  body << std::endl;

  body << "Date\t\t: " << _date << std::endl;
  body << "Time\t\t: " << _time << std::endl;
  if(msg.haveSubscriberId)  body << "User\t\t: " << msg.subscriberId << std::endl;
  if(msg.haveAreaId)        body << "Area\t\t: " << msg.areaId << std::endl;
  if(msg.havePeripheralId)  body << "Peripheral\t: " << msg.peripheralId << std::endl;
  if(msg.haveAutomatedId)   body << "Automated Id\t: " << msg.automatedId << std::endl;
  if(msg.haveTelephoneId)   body << "Telephone Id\t: " << msg.telephoneId << std::endl;
  if(msg.haveLevel)         body << "Level\t\t: " << msg.level << std::endl;
  if(msg.haveValue)         body << "Value\t\t: " << msg.value << std::endl;
  if(msg.havePath)          body << "Path\t\t: " << msg.path << std::endl;
  if(msg.haveRouteGroup)    body << "Route Group\t: " << msg.routeGroup << std::endl;
  if(msg.haveSubSubscriber) body << "Sub User\t: " << msg.subSubscriber << std::endl;
  if(msg.haveAscii)         body << "Text\t\t: " << msg.ascii << std::endl;
}

void EmailOutput::email_send_thread(class openGalaxy* opengalaxy, std::stringstream *psubject, std::stringstream *pbody)
{
  std::string subject = psubject->str();
  std::string body = pbody->str();

  const char *cmd_fmt = "echo \'%s%s\n\' | /usr/sbin/ssmtp -C%s %s";
  const char *header_fmt = "From: \"%s\" <%s>\nSubject: %s\n\n";

  size_t sizeof_header =
    strlen(header_fmt) +
    opengalaxy->settings().email_from_name.size() +
    opengalaxy->settings().email_from_address.size() +
    subject.size();

  size_t sizeof_cmd =
    strlen(cmd_fmt) +
    sizeof_header +
    body.size() +
    opengalaxy->settings().ssmtp_configfile.size() +
    opengalaxy->settings().email_recipients.size() +
    32;

  char *header = (char*) thread_safe_malloc( sizeof_header );
  char *cmd = (char*) thread_safe_malloc(sizeof_cmd);

  snprintf( header, sizeof_header, header_fmt,
    opengalaxy->settings().email_from_name.c_str(),
    opengalaxy->settings().email_from_address.c_str(),
    subject.c_str()
  );

  snprintf( cmd, sizeof_cmd, cmd_fmt,
    header,
    body.c_str(),
    opengalaxy->settings().ssmtp_configfile.c_str(),
    opengalaxy->settings().email_recipients.c_str()
  );

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
  system( cmd ); // execute ssmtp
#pragma GCC diagnostic pop

  thread_safe_free(cmd);
  thread_safe_free(header);
  delete psubject;
  delete pbody;
}

bool EmailOutput::write(class SiaEvent& msg)
{
  std::stringstream *psubject = new std::stringstream();
  std::stringstream *pbody = new std::stringstream();
  email_encode(*psubject, *pbody, msg);
  new std::thread(email_send_thread, &opengalaxy(), psubject, pbody);
  return true;
}

} // Ends namespace openGalaxy

#endif
