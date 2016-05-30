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
#include "Output-Text.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>

#include "opengalaxy.hpp"

namespace openGalaxy {

const char *TextfileOutput::name()
{
  return (const char*)"Textfile output";
}

const char *TextfileOutput::description()
{
  return (const char*)"Send messages to a textfile";
}

TextfileOutput::TextfileOutput(class openGalaxy& opengalaxy)
 : OutputPlugin(opengalaxy)
{
  // Open/create the log file (@EOF) and set the stream to append data
  ofs = new std::ofstream(
    m_openGalaxy.settings().textfile.c_str(),
    std::ofstream::out | std::ofstream::ate | std::ofstream::app
  );

  if ( ofs->fail() ){
    m_openGalaxy.syslog().error("Output: Textfile: Could not open log file!");
  }

  lines = 0;
}

TextfileOutput::~TextfileOutput()
{
  ofs->close();
  delete ofs;
}

void TextfileOutput::text_encode(std::stringstream& out, SiaEvent& msg)
{
  std::string fc2str;

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

  out << "| " << std::setfill(' ')
      << std::left << std::setw(13) << msg.raw.FunctionCodeToString(fc2str) << " | "
      << std::left << std::setw(10) << _date << " | "
      << std::left << std::setw(8)  << _time << " | "
      << std::right << std::setw(7)  << msg.accountId << " | "
      << std::left  << std::setw(2)  << msg.event->letter_code.c_str() << " | ";

  if( msg.haveAscii == true )
    out << std::left << std::setw(24) << msg.ascii.c_str() << " | ";
  else
    out << std::left << std::setw(24) << "-" << " | ";

  out << std::left << std::setw(11) << msg.addressType.c_str() << " | ";

  if( msg.addressNumber > 0 )
    out << std::right << std::setw(7) << msg.addressNumber << " | ";
  else
    out << std::right << std::setw(7) << "-" << " | ";

  if( msg.haveSubscriberId == true )
    out << std::right << std::setw(4) << msg.subscriberId << " | ";
  else
    out << std::right << std::setw(4) << "-" << " | ";

  if( msg.haveAreaId == true )
    out << std::right << std::setw(4) << msg.areaId << " | ";
  else
    out << std::right << std::setw(4) << "-" << " | ";

  if( msg.havePeripheralId == true )
    out << std::right << std::setw(10) << msg.peripheralId << " | ";
  else
    out << std::right << std::setw(10) << "-" << " | ";

  if( msg.haveAutomatedId == true )
    out << std::right << std::setw(12) << msg.automatedId << " | ";
  else
    out << std::right << std::setw(12) << "-" << " | ";

  if( msg.haveTelephoneId == true )
    out << std::right << std::setw(12) << msg.telephoneId << " | ";
  else
    out << std::right << std::setw(12) << "-" << " | ";

  if( msg.haveLevel == true )
    out << std::right << std::setw(5) << msg.level << " | ";
  else
    out << std::right << std::setw(5) << "-" << " | ";

  if( msg.haveValue == true )
    out << std::right << std::setw(5) << msg.value << " | ";
  else
    out << std::right << std::setw(5) << "-" << " | ";

  if( msg.havePath == true )
    out << std::right << std::setw(4) << msg.path << " | ";
  else
    out << std::right << std::setw(4) << "-" << " | ";

  if( msg.haveRouteGroup == true )
    out << std::right << std::setw(11) << msg.routeGroup << " | ";
  else
    out << std::right << std::setw(11) << "-" << " | ";

  if( msg.haveSubSubscriber == true )
    out << std::right << std::setw(14) << msg.subSubscriber << " |";
  else
    out << std::right << std::setw(14) << "-" << " |";
}

bool TextfileOutput::write(class SiaEvent& msg)
{
  if(lines == 0){
    *ofs << "+---------------+------------+----------+---------+----+--------------------------+-------------+---------+------+------+------------+--------------+--------------+-------+-------+------+-------------+----------------+" << std::endl
         << "| FUNCTION CODE | DATE       | TIME     | ACCOUNT | EV | ASCII                    | TYPE        | ADDRESS | USER | AREA | PERIPHERAL | AUTOMATED ID | TELEPHONE ID | LEVEL | VALUE | PATH | ROUTE GROUP | SUB-SUBSCRIBER |" << std::endl
         << "+---------------+------------+----------+---------+----+--------------------------+-------------+---------+------+------+------------+--------------+--------------+-------+-------+------+-------------+----------------+"
         << std::endl << std::flush;
  }
  std::stringstream ss;
  text_encode(ss, msg);
  *ofs << ss.str() << std::endl << std::flush;
  if(lines++ > 32) lines = 0;
  return true;
}

} // Ends namespace openGalaxy

