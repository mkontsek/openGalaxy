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

#ifndef __OPENGALAXY_SERVER_SIA_EVENT_HPP__
#define __OPENGALAXY_SERVER_SIA_EVENT_HPP__

#include "atomic.h"

#include "Siablock.hpp"
#include "opengalaxy.hpp"
#include <iomanip>
#include <sstream>

namespace openGalaxy {

// this class describes a single SIA event code
class SiaEventCode {
public:

  enum class AddressField : unsigned char {
    unused = 0,
    zone,
    area,
    user,
    door,
    dealer_id,
    expander,
    line,
    relay,
    point,
    printer,
    mfr_defined
  };

  std::string& letter_code;     // SIA 2 letter code
  std::string& name;            // SIA code name
  std::string& desc;            // SIA code description
  AddressField address_field;   // SIA Address field

  SiaEventCode(std::string& c, std::string& n, std::string& d, AddressField f)
   : letter_code(c), name(n), desc(d), address_field(f) { /* nothing to do here */ }
};

// this class describes a single decoded SIA event
class SiaEvent {
public:

  class Date {
  friend class SiaEvent;
  private:
    std::stringstream data;
    std::string m_date;
  public:
    void erase() { data.str(""); m_date.clear(); }
    void assign(int month, int day, int year){
      data.str("");
      data << std::setfill('0') << std::setw(2) << month;
      data << '-';
      data << std::setfill('0') << std::setw(2) << day;
      data << '-';
      data << std::setfill('0') << std::setw(2) <<  year;
      m_date.assign(data.str());
    }
    std::string& get() { return m_date; }
  };

  class Time {
  friend class SiaEvent;
  private:
    std::stringstream data;
    std::string m_time;
  public:
    void erase() { data.str(""); m_time.clear(); }
    void assign(int h, int m, int s){
      data.str("");
      data << std::setfill('0') << std::setw(2) << h;
      data << ':';
      data << std::setfill('0') << std::setw(2) << m;
      data << ':';
      data << std::setfill('0') << std::setw(2) << s;
      m_time.assign(data.str());
    }
    std::string& get() { return m_time; }
  };

  // the raw SIA block for this event (parity is always set to 0)
  SiaBlock raw;

  // the Account number (always present)
  int accountId;

  // The event code
  SiaEventCode *event;
  bool haveEvent;
	
  // Date and Time
  Date date;
  bool haveDate;
  Time time;
  bool haveTime;

  // Subscriber (aka User) number
  int subscriberId;
  bool haveSubscriberId;

  // Area (aka section or partition or ...) number
  int areaId;
  bool haveAreaId;

  // Device number of the psysical device causing the events or information in this block
  int peripheralId;
  bool havePeripheralId;

  // ID number of the timer or function that caused the events or information in this block
  int automatedId;
  bool haveAutomatedId;

  // Index of the telephone number used to connect to the RECIEVER
  int telephoneId;
  bool haveTelephoneId;

  // Indicates a state that has multiple, meaningful levels which can be quantitative or qualitative.
  int level;
  bool haveLevel;

  // The numerical value associated with the event code reported.
  int value;
  bool haveValue;

  // The number of the communication path that is relevant to the event reported.
  int path;
  bool havePath;

  // The number of wich communications path grouping (primary and secondary) that has failed to communicate
  int routeGroup;
  bool haveRouteGroup;

  // The subscriber group
  int subSubscriber;
  bool haveSubSubscriber;

  std::string addressType;
  int addressNumber;

  std::string unitsType;
  int units;
  bool haveUnits;

  // Only valid for SIA levels 3 and 4
	
  // The text in the ASCII Blocktype
  std::string ascii;
  bool haveAscii;

  // clear all values so we start anew
  void Erase(){
    raw.Erase();
    accountId = -1;
    event = nullptr;
    haveEvent = false;
    date.erase();
    haveDate = false;
    time.erase();
    haveTime = false;
    subscriberId = -1;
    haveSubscriberId = false;
    areaId = -1;
    haveAreaId = false;
    peripheralId = -1;
    havePeripheralId = false;
    automatedId = -1;
    haveAutomatedId = false;
    telephoneId = -1;
    haveTelephoneId = false;
    level = -1;
    haveLevel = false;
    value = -1;
    haveValue = false;
    path = -1;
    havePath = false;
    routeGroup = -1;
    haveRouteGroup = false;
    subSubscriber = -1;
    haveSubSubscriber = false;
    addressType.erase();
    addressNumber = -1;
    unitsType.erase();
    units = -1;
    haveUnits = false;
    ascii.erase();
    haveAscii = false;
  }

  // constructors
  SiaEvent(){
    Erase();
  }
  SiaEvent(SiaEvent& ev){
    memcpy(raw.block.data, ev.raw.block.data, SiaBlock::block_max);
    accountId = ev.accountId;
    event = ev.event;
    haveEvent = ev.haveEvent;
    date.m_date.assign(ev.date.m_date);
    date.data << ev.date.data.str();
    haveDate = ev.haveDate;
    time.m_time.assign(ev.time.m_time);
    time.data << ev.time.data.str();
    haveTime = ev.haveTime;
    subscriberId = ev.subscriberId;
    haveSubscriberId = ev.haveSubscriberId;
    areaId = ev.areaId;
    haveAreaId = ev.haveAreaId;
    peripheralId = ev.peripheralId;
    havePeripheralId = ev.havePeripheralId;
    automatedId = ev.automatedId;
    haveAutomatedId = ev.haveAutomatedId;
    telephoneId = ev.telephoneId;
    haveTelephoneId = ev.haveTelephoneId;
    level = ev.level;
    haveLevel = ev.haveLevel;
    value = ev.value;
    haveValue = ev.haveValue;
    path = ev.path;
    havePath = ev.havePath;
    routeGroup = ev.routeGroup;
    haveRouteGroup = ev.haveRouteGroup;
    subSubscriber = ev.subSubscriber;
    haveSubSubscriber = ev.haveSubSubscriber;
    addressType.assign(ev.addressType);
    addressNumber = ev.addressNumber;
    unitsType.assign(ev.unitsType);
    units = ev.units;
    haveUnits = ev.haveUnits;
    ascii.assign(ev.ascii);
    haveAscii = ev.haveAscii;
  }
};

} // ends namespace openGalaxy

#endif

