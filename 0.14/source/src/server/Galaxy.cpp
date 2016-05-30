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
#include "Galaxy.hpp"

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>

namespace openGalaxy {

Galaxy::Galaxy(openGalaxy& opengalaxy)
 : m_openGalaxy(opengalaxy)
{
  // create the locks for our condition variables
  m_areaAction_lock = new std::unique_lock<std::mutex>(m_areaAction_mutex);
  m_getAreaArmedState_lock = new std::unique_lock<std::mutex>(m_getAreaArmedState_mutex);
  m_getAllAreasArmedState_lock = new std::unique_lock<std::mutex>(m_getAllAreasArmedState_mutex);
  m_getAllAreasAlarmState_lock = new std::unique_lock<std::mutex>(m_getAllAreasAlarmState_mutex);
  m_getAllAreasReadyState_lock = new std::unique_lock<std::mutex>(m_getAllAreasReadyState_mutex);
  m_zoneAction_lock = new std::unique_lock<std::mutex>(m_zoneAction_mutex);
  m_zoneIsOmit_lock = new std::unique_lock<std::mutex>(m_zoneIsOmit_mutex);
  m_outputAction_lock = new std::unique_lock<std::mutex>(m_outputAction_mutex);
  m_getAllOutputs_lock = new std::unique_lock<std::mutex>(m_getAllOutputs_mutex);
  m_getZoneState_lock = new std::unique_lock<std::mutex>(m_getZoneState_mutex);
  m_getAllZonesReadyState_lock = new std::unique_lock<std::mutex>(m_getAllZonesReadyState_mutex);
  m_getAllZonesAlarmState_lock = new std::unique_lock<std::mutex>(m_getAllZonesAlarmState_mutex);
  m_getAllZonesOpenState_lock = new std::unique_lock<std::mutex>(m_getAllZonesOpenState_mutex);
  m_getAllZonesTamperState_lock = new std::unique_lock<std::mutex>(m_getAllZonesTamperState_mutex);
  m_getAllZonesRState_lock = new std::unique_lock<std::mutex>(m_getAllZonesRState_mutex);
  m_getAllZonesOmittedState_lock = new std::unique_lock<std::mutex>(m_getAllZonesOmittedState_mutex);
  m_getAllZonesMaskedState_lock = new std::unique_lock<std::mutex>(m_getAllZonesMaskedState_mutex);
  m_getAllZonesFaultState_lock = new std::unique_lock<std::mutex>(m_getAllZonesFaultState_mutex);
  m_reprocessEvents_lock = new std::unique_lock<std::mutex>(m_reprocessEvents_mutex);
  m_flushEvents_lock = new std::unique_lock<std::mutex>(m_flushEvents_mutex);
  m_generateWrongCodeAlarm_lock = new std::unique_lock<std::mutex>(m_generateWrongCodeAlarm_mutex);
  m_setZoneState_lock = new std::unique_lock<std::mutex>(m_setZoneState_mutex);
}

Galaxy::~Galaxy()
{
  // Make sure we're not (by chance) waiting for a callback to finish
  m_areaActionCallbackRetv = false;
  m_areaAction_cv.notify_one();
  m_getAreaArmedStateRetv = false;
  m_getAreaArmedState_cv.notify_one();
  m_getAllAreasArmedStateRetv = false;
  m_getAllAreasArmedState_cv.notify_one();
  m_getAllAreasAlarmStateRetv = false;
  m_getAllAreasAlarmState_cv.notify_one();
  m_getAllAreasReadyStateRetv = false;
  m_getAllAreasReadyState_cv.notify_one();
  m_zoneActionRetv = false;
  m_zoneAction_cv.notify_one();
  m_zoneIsOmitRetv = false;
  m_zoneIsOmit_cv.notify_one();
  m_outputActionRetv = false;
  m_outputAction_cv.notify_one();
  m_getAllOutputsRetv = false;
  m_getAllOutputs_cv.notify_one();
  m_getZoneStateRetv = false;
  m_getZoneState_cv.notify_one();
  m_getAllZonesReadyStateRetv = false;
  m_getAllZonesReadyState_cv.notify_one();
  m_getAllZonesAlarmStateRetv = false;
  m_getAllZonesAlarmState_cv.notify_one();
  m_getAllZonesOpenStateRetv = false;
  m_getAllZonesOpenState_cv.notify_one();
  m_getAllZonesTamperStateRetv = false;
  m_getAllZonesTamperState_cv.notify_one();
  m_getAllZonesRStateRetv = false;
  m_getAllZonesRState_cv.notify_one();
  m_getAllZonesOmittedStateRetv = false;
  m_getAllZonesOmittedState_cv.notify_one();
  m_getAllZonesMaskedStateRetv = false;
  m_getAllZonesMaskedState_cv.notify_one();
  m_getAllZonesFaultStateRetv = false;
  m_getAllZonesFaultState_cv.notify_one();
  m_reprocessEventsCallbackRetv = false;
  m_reprocessEvents_cv.notify_one();
  m_flushEventsCallbackRetv = false;
  m_flushEvents_cv.notify_one();
  m_generateWrongCodeAlarmCallbackRetv = false;
  m_generateWrongCodeAlarm_cv.notify_one();
  m_setZoneStateCallbackRetv = false;
  m_setZoneState_cv.notify_one();
}

// Returns true only when nr is a valid (4 digit) zone number
bool Galaxy::IsZone(int nr)
{
  if(opengalaxy().settings().galaxy_dip8 != 0){
    if(nr >= 9011 && nr <= 9018) return true; // RIO 001 (G3/Dimension Dipswitch 8 set to on)
  }

  // subtract line number
  if(nr >= 1001 && nr <= 1158) nr -= 1000;
  else if(nr >= 2001 && nr <= 2158) nr -= 2000;
  else if(nr >= 3001 && nr <= 3158) nr -= 3000;
  else if(nr >= 4001 && nr <= 4158) nr -= 4000;
  else return false;

  // substract device number
  if(nr >= 11 && nr <= 18) nr -= 10;
  else if(nr >= 21 && nr <= 28) nr -= 20;
  else if(nr >= 31 && nr <= 38) nr -= 30;
  else if(nr >= 41 && nr <= 48) nr -= 40;
  else if(nr >= 51 && nr <= 58) nr -= 50;
  else if(nr >= 61 && nr <= 68) nr -= 60;
  else if(nr >= 71 && nr <= 78) nr -= 70;
  else if(nr >= 81 && nr <= 88) nr -= 80;
  else if(nr >= 91 && nr <= 98) nr -= 90;
  else if(nr >= 101 && nr <= 108) nr -= 100;
  else if(nr >= 111 && nr <= 118) nr -= 110;
  else if(nr >= 121 && nr <= 128) nr -= 120;
  else if(nr >= 131 && nr <= 138) nr -= 130;
  else if(nr >= 141 && nr <= 148) nr -= 140;
  else if(nr >= 151 && nr <= 158) nr -= 150;

  // zone between 1 and 8 ?
  if(nr >= 1 && nr <= 8) return true;
  else return false;
}

// Returns true only when nr is a valid output number
bool Galaxy::IsOutput(int nr)
{
  if(nr >= 9001 && nr <= 9006) return true; // header outputs ???? (please verify this)
  if(nr >= 9011 && nr <= 9014) return true; // RIO 001 (G3/Dimension Dipswitch 8 set to on)

  // subtract line number
  if(nr >= 1001 && nr <= 1154) nr -= 1000;
  else if(nr >= 2001 && nr <= 2154) nr -= 2000;
  else if(nr >= 3001 && nr <= 3154) nr -= 3000;
  else if(nr >= 4001 && nr <= 4154) nr -= 4000;
  else return false;

  // substract device number
  if(nr >= 11 && nr <= 14) nr -= 10;
  else if(nr >= 21 && nr <= 24) nr -= 20;
  else if(nr >= 31 && nr <= 34) nr -= 30;
  else if(nr >= 41 && nr <= 44) nr -= 40;
  else if(nr >= 51 && nr <= 54) nr -= 50;
  else if(nr >= 61 && nr <= 64) nr -= 60;
  else if(nr >= 71 && nr <= 74) nr -= 70;
  else if(nr >= 81 && nr <= 84) nr -= 80;
  else if(nr >= 91 && nr <= 94) nr -= 90;
  else if(nr >= 101 && nr <= 104) nr -= 100;
  else if(nr >= 111 && nr <= 114) nr -= 110;
  else if(nr >= 121 && nr <= 124) nr -= 120;
  else if(nr >= 131 && nr <= 134) nr -= 130;
  else if(nr >= 141 && nr <= 144) nr -= 140;
  else if(nr >= 151 && nr <= 154) nr -= 150;

  // output between 1 and 4 ?
  if(nr >= 1 && nr <= 4) return true;
  else return false;
}

// Perform an area action 
// blknum: area 1...32 or all areas (0)
// Action: unset, set, part set, reset, abort set, force set

void Galaxy::AreaActionCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  // Was the command successfull?
  if(buf == nullptr) opengalaxy.galaxy().m_areaActionCallbackRetv = false;
  else opengalaxy.galaxy().m_areaActionCallbackRetv = true;
  // Unblock
  opengalaxy.galaxy().m_areaAction_cv.notify_one();
}

bool Galaxy::AreaAction(unsigned int blknum, Galaxy::area_action action)
{
  if(blknum > 32) return false;
  char buf[16];
  if(blknum == 0) snprintf(buf, 16, "SA*%u", (unsigned int)action); // all partitions
  else snprintf(buf, 16, "SA%u*%u", blknum, (unsigned int)action); // selected partition

  // Let the receiver thread send the command
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    AreaActionCallback
  )==false) return false;

  // and wait for the callback to finish
  m_areaAction_cv.wait(*m_areaAction_lock);
  return m_areaActionCallbackRetv;
}

// Get the armed status of an area

void Galaxy::GetAreaArmedStateCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAreaArmedStateRetv = false;
  }
  else {
    opengalaxy.galaxy().m_getAreaArmedStateRetv = true;
    // 'SAx*y'
    *opengalaxy.galaxy().m_getAreaArmedStateState = (Galaxy::area_armed_state)atoi(
        (char*)&buf[ (opengalaxy.galaxy().m_getAreaArmedStateBlknum < 10) ? 4 : 5 ]
    );
  }

  opengalaxy.galaxy().m_getAreaArmedState_cv.notify_one();
}

bool Galaxy::GetAreaArmedState(unsigned int blknum, Galaxy::area_armed_state* state)
{
  if(blknum==0 || blknum>32) return false;
  char buf[16];
  snprintf(buf, 16, "SA%u", blknum);

  // Let the receiver thread send the command and wait until the callback has been called
  m_getAreaArmedStateState = state;
  m_getAreaArmedStateBlknum = blknum;
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    GetAreaArmedStateCallback
  )==false) return false;
  m_getAreaArmedState_cv.wait(*m_getAreaArmedState_lock);
  return m_getAreaArmedStateRetv;
}

/// Get the armed status of all 32 areas

void Galaxy::GetAllAreasArmedStateCallback(openGalaxy& opengalaxy,char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllAreasArmedStateRetv = false;
  }
  else {
    // 'SA*yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
    for(int i=0; i<32; i++){
      switch(buf[3+i]){
        case '1':
          opengalaxy.galaxy().m_getAllAreasArmedState[i] = Galaxy::area_armed_state::set;
          break;
        case '2':
          opengalaxy.galaxy().m_getAllAreasArmedState[i] = Galaxy::area_armed_state::part_set;
          break;
        default:
          opengalaxy.galaxy().m_getAllAreasArmedState[i] = Galaxy::area_armed_state::unset;
          break;
      }
    }
    opengalaxy.galaxy().m_getAllAreasArmedStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllAreasArmedState_cv.notify_one();
}

bool Galaxy::GetAllAreasArmedState(Galaxy::area_armed_state state[32])
{
  char buf[16];
  snprintf(buf, 16, "SA");

  // Let the receiver thread send the command and wait until the callback has been called
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    GetAllAreasArmedStateCallback
  )==false) return false;
  m_getAllAreasArmedState_cv.wait(*m_getAllAreasArmedState_lock);
  if(m_getAllAreasArmedStateRetv){
    for( int i = 0; i < 32; i++ ) state[i] = m_getAllAreasArmedState[i];
  }
  return m_getAllAreasArmedStateRetv;
}

// Get the alarm status of all areas
void Galaxy::GetAllAreasAlarmStateCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllAreasAlarmStateRetv = false;
  }
  else {
    // 'SA91*yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
    for(int i=0; i<32; i++){
      switch(buf[5+i]){
        case '1':
          opengalaxy.galaxy().m_getAllAreasAlarmState[i] = Galaxy::area_alarm_state::alarm;
          break;
        case '2':
          opengalaxy.galaxy().m_getAllAreasAlarmState[i] = Galaxy::area_alarm_state::reset_required;
          break;
        default:
          opengalaxy.galaxy().m_getAllAreasAlarmState[i] = Galaxy::area_alarm_state::normal;
          break;
      }
    }
    opengalaxy.galaxy().m_getAllAreasAlarmStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllAreasAlarmState_cv.notify_one();
}

bool Galaxy::GetAllAreasAlarmState(Galaxy::area_alarm_state state[32])
{
  char buf[16];
  snprintf(buf, 16, "SA91");
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    GetAllAreasAlarmStateCallback 
  )==false) return false;
  m_getAllAreasAlarmState_cv.wait(*m_getAllAreasAlarmState_lock);
  if(m_getAllAreasAlarmStateRetv){
    for(int i=0; i<32; i++) state[i] = m_getAllAreasAlarmState[i];
  }
  return m_getAllAreasAlarmStateRetv;
}


// Get the ready status of all areas (Galaxy V4.00)

void Galaxy::GetAllAreasReadyStateCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllAreasReadyStateRetv = false;
  }
  else {
    // 'SA92*yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
    for(int i=0; i<32; i++){
      switch(buf[5+i]){
        case '1':
          opengalaxy.galaxy().m_getAllAreasReadyState[i] = Galaxy::area_ready_state::set;
          break;
        case '2':
          opengalaxy.galaxy().m_getAllAreasReadyState[i] = Galaxy::area_ready_state::part_set;
          break;
        case '3':
          opengalaxy.galaxy().m_getAllAreasReadyState[i] = Galaxy::area_ready_state::ready_to_set;
          break;
        case '4':
          opengalaxy.galaxy().m_getAllAreasReadyState[i] = Galaxy::area_ready_state::time_locked;
          break;
        default:
          opengalaxy.galaxy().m_getAllAreasReadyState[i] = Galaxy::area_ready_state::unset;
          break;
      }
    }
    opengalaxy.galaxy().m_getAllAreasReadyStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllAreasReadyState_cv.notify_one();
}

bool Galaxy::GetAllAreasReadyState(Galaxy::area_ready_state state[32])
{
  char buf[16];
  snprintf(buf, 16, "SA92");
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    GetAllAreasReadyStateCallback
  )==false) return false;
  m_getAllAreasReadyState_cv.wait(*m_getAllAreasReadyState_lock);
  if(m_getAllAreasReadyStateRetv){
    for(int i=0; i<32; i++) state[i] = m_getAllAreasReadyState[i];
  }
  return m_getAllAreasReadyStateRetv;
}

// Perform a zone action by zone number or zone type
//
// nr    : 4 digit zone number or zone type 1...100
// action: omit or un-omit

void Galaxy::ZoneActionCallback(openGalaxy& opengalaxy,char* buf, int len)
{
  if(buf==nullptr) opengalaxy.galaxy().m_zoneActionRetv = false;
  else opengalaxy.galaxy().m_zoneActionRetv = true;
  opengalaxy.galaxy().m_zoneAction_cv.notify_one();
}

bool Galaxy::ZoneAction(unsigned int nr, Galaxy::zone_action action)
{
  if(IsZone(nr)!=true) if(!(nr>=1 && nr<=100)) return false;
  char buf[16];
  snprintf(buf, 16, "SB%u*%u", nr, (unsigned int)action);
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    ZoneActionCallback
  )==false) return false;
  m_zoneAction_cv.wait(*m_zoneAction_lock);
  return m_zoneActionRetv;
}

// Get the omit status of a zone

void Galaxy::ZoneIsOmitCallback(openGalaxy& opengalaxy,char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_zoneIsOmitRetv = false;
  }
  else {
    // 'SBxxxx*y'
    *opengalaxy.galaxy().m_zoneIsOmitState = (Galaxy::zone_action)atoi((char*)&buf[7]);
    opengalaxy.galaxy().m_zoneIsOmitRetv = true;
  }
  opengalaxy.galaxy().m_zoneIsOmit_cv.notify_one();
}

bool Galaxy::ZoneIsOmit(unsigned int nr, Galaxy::zone_action *state)
{
  if(IsZone(nr)!= true) return false;
  char buf[16];
  snprintf(buf, 16, "SB%u", nr);
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    ZoneIsOmitCallback
  )==false) return false;
  m_zoneIsOmit_cv.wait(*m_zoneIsOmit_lock);
  return m_zoneIsOmitRetv;
}

// Perform an output action by 4 digit output number, type (1...100) or all outputs (0)
//
// nr    : output number, type number or 0 for all outputs
// state : on or off
// blknum: the area the output must belong to (1...32 or 0 for all areas) 
//         this value is ignored for zone numbers and only has effect when setting outputs by type

void Galaxy::OutputActionCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_outputActionRetv = false;
  }
  else {
    opengalaxy.galaxy().m_outputActionRetv = true;
  }
  opengalaxy.galaxy().m_outputAction_cv.notify_one();
}

bool Galaxy::OutputAction(unsigned int nr, bool state, unsigned int blknum)
{
  char buf[48];
  memset(buf, 0, sizeof(buf));

  if(IsOutput(nr)==true){ // set output state by number

    unsigned int line = 1 + (((nr / 1000) - 1) & 3);                   // Line nr
    unsigned int rio = ((nr - (line * 1000)) / 10) & 15;               // RIO nr
    unsigned int op = 1 + ((nr - (line * 1000) - (rio * 10) - 1) & 3); // Output nr on RIO
                 nr = ((line - 1) << 6) + (rio << 2) + op;             // Zone number in 3 digit format

    // Determine bit position and mask
    unsigned int output = 1 << (op - 1);
    unsigned int mask = output << 4;

    char *p = &buf[7];

    if(nr < 129) {
      snprintf(buf, sizeof(buf), "OR1000*");
      memset(p, 1, 34);
      p += rio;
      if(line > 1) p += 16;
      if(!(line==1 && rio<2)) p += 2; // 2 byte hole between onboard and external rio's
      *p = mask;
      if(state==true) *p |= output;
    }
    else {
      snprintf(buf, sizeof(buf), "OR1001*");
      memset(p, 1, 32);
      p += rio;
      if(line > 3) p += 16;
      *p = mask;
      if(state==true) *p |= output;
    }

  }
  else if(nr >= 1 && nr <= 100){ // set output by type and area
    if(blknum>32) return false;
    if(blknum==0) snprintf(buf, sizeof(buf), "OR%u*%u", nr, state);
    else snprintf(buf, sizeof(buf), "OR%u*%uG%u", nr, state, blknum);
  }
  else if(nr==0) { // set all outputs
    if(blknum>32) return false;
    if(blknum==0) snprintf(buf, sizeof(buf), "OR*%u", state);
    else snprintf(buf, sizeof(buf), "OR*%uG%u", state, blknum);
  }

  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    OutputActionCallback
  )==false) return false;
  m_outputAction_cv.wait(*m_outputAction_lock);

  return m_outputActionRetv;
}

// bool GalaxyGetAllOutputs( unsigned char outputs[32] )
//

void Galaxy::GetAllOutputsCallback(openGalaxy& opengalaxy,char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllOutputsRetv = false;
  }
  else {
    // 'OR1000*[32bytes]'
    memcpy((void*)opengalaxy.galaxy().m_getAllOutputsState, &buf[7], 32);
    opengalaxy.galaxy().m_getAllOutputsRetv = true;
  }
  opengalaxy.galaxy().m_getAllOutputs_cv.notify_one();
}

bool Galaxy::GetAllOutputs(unsigned char outputs[32])
{
  char buf[48];
  snprintf(buf, 48, "OR1000");
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::control,
    buf,
    strlen(buf),
    GetAllOutputsCallback
  )==false) return false;
  m_getAllOutputs_cv.wait(*m_getAllOutputs_lock);
  memcpy(outputs, (void*)m_getAllOutputsState, 32);
  return m_getAllOutputsRetv;
}

// bool GalaxyGetZoneState( unsigned int nr, galaxy_zone_state *state )

void Galaxy::GetZoneStateCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getZoneStateRetv = false;
  }
  else {
    // 'ZSxxxx*[state]'
    *opengalaxy.galaxy().m_getZoneStateState = (Galaxy::zone_state)atoi((char*)&buf[7]);
    opengalaxy.galaxy().m_getZoneStateRetv = true;
  }
  opengalaxy.galaxy().m_getZoneState_cv.notify_one();
}

bool Galaxy::GetZoneState(unsigned int nr, Galaxy::zone_state *state)
{
  if(IsZone(nr)==false) return false;
  char buf[16];
  snprintf(buf, 16, "ZS%u", nr);
  m_getZoneStateState = state;
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    GetZoneStateCallback
  )==false) return false;
  m_getZoneState_cv.wait(*m_getZoneState_lock);
  return m_getZoneStateRetv;
}

// bool GalaxyGetAllZonesReadyState( unsigned char zones_state[65] )

void Galaxy::GetAllZonesReadyStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesReadyStateRetv = false;
  }
  else {
    // buf = 'ZS1*[35bytes]'
    // 0 = low, high, closed (ready) / 1 = os, sc, open, mask, fault (not ready)
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +4
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +4
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesReadyState[0] = buf[5];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesReadyState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesReadyState[1] = buf[4]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesReadyState[2] = buf[7];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesReadyState[2] = buf[5]; // RIO 101
    }
    for(int i=3; i<33; i++){
      opengalaxy.galaxy().m_getAllZonesReadyState[i] = buf[i+5]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesReadyStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesReadyState_cv.notify_one();
}

void Galaxy::GetAllZonesReadyStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesReadyStateRetv = false;
  }
  else {
    // buf = 'ZS2*[33bytes]'
    // 0 = low, high, closed (ready) / 1 = os, sc, open, mask, fault (not ready)
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +4
    // 2001-4158    not-used
    //
    for(int i=33; i<65; i++) opengalaxy.galaxy().m_getAllZonesReadyState[i] = buf[i-33+4]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesReadyStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesReadyState_cv.notify_one();
}

bool Galaxy::GetAllZonesReadyState(unsigned char zones_state[65])
{
  // ZSx
  // 1: Zones 1 - 256
  // 2: Zones 257 - 512
  char buf[48];

  // Get the first block
  snprintf(buf, 48, "ZS1");
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    GetAllZonesReadyStateCallbackOne
  )==false) return false;
  m_getAllZonesReadyState_cv.wait(*m_getAllZonesReadyState_lock);
  if(m_getAllZonesReadyStateRetv==true){
    // Get the second block
    snprintf(buf, 48, "ZS2");
    if(opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesReadyStateCallbackTwo
    )==false) return false;
    m_getAllZonesReadyState_cv.wait(*m_getAllZonesReadyState_lock);
    if(m_getAllZonesReadyStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesReadyState, 65);
    }
  }
  return m_getAllZonesReadyStateRetv;
}

// bool GalaxyGetAllZonesAlarmState( unsigned char zones_state[65] )

void Galaxy::GetAllZonesAlarmStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesAlarmStateRetv = false;
  }
  else {
    // buf = 'ZS101*[35bytes]'
    // 0 = not used / 1 = alarm 
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +6
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +6
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesAlarmState[0] = buf[6+1];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesAlarmState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesAlarmState[1] = buf[6+0]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesAlarmState[2] = buf[6+3];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesAlarmState[2] = buf[6+1]; // RIO 101
    }
    for(int i=3; i<33; i++){
      opengalaxy.galaxy().m_getAllZonesAlarmState[i] = buf[i+7]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesAlarmStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesAlarmState_cv.notify_one();
}

void Galaxy::GetAllZonesAlarmStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesAlarmStateRetv = false;
  }
  else {
    // 'ZS102*[33bytes]'
    // 0 = not used / 1 = alarm 
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +6
    // 2001-4158    not-used
    //
    for(int i=33; i < 65; i++) opengalaxy.galaxy().m_getAllZonesAlarmState[i] = buf[i-33+6]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesAlarmStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesAlarmState_cv.notify_one();
}

bool Galaxy::GetAllZonesAlarmState( unsigned char zones_state[65] )
{
  // ZSx
  // 101: Zones 1 - 256
  // 102: Zones 257 - 512
  char buf[48];
  
  // Get the first block
  snprintf(buf, 48, "ZS101");
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    GetAllZonesAlarmStateCallbackOne
  )==false) return false;
  m_getAllZonesAlarmState_cv.wait(*m_getAllZonesAlarmState_lock);
  if(m_getAllZonesAlarmStateRetv==true){
    // Get the second block
      snprintf(buf, 48, "ZS102");
    if( opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesAlarmStateCallbackTwo
    )==false) return false;
    m_getAllZonesAlarmState_cv.wait(*m_getAllZonesAlarmState_lock);
    if(m_getAllZonesAlarmStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesAlarmState, 65);
    }
  }
  return m_getAllZonesAlarmStateRetv;
}

// bool GalaxyGetAllZonesOpenState( unsigned char zones_state[65] )

void Galaxy::GetAllZonesOpenStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesOpenStateRetv = false;
  }
  else {
    // buf = 'ZS201*[35bytes]'
    // 0 = not used / 1 = open 
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +6
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +6
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesOpenState[0] = buf[7];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesOpenState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesOpenState[1] = buf[6]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesOpenState[2] = buf[9];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesOpenState[2] = buf[7]; // RIO 101
    }
    for(int i=3; i<33; i++){
      opengalaxy.galaxy().m_getAllZonesOpenState[i] = buf[i+7]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesOpenStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesOpenState_cv.notify_one();
}

void Galaxy::GetAllZonesOpenStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesOpenStateRetv = false;
  }
  else {
    // 'ZS202*[33bytes]'
    // 0 = not used / 1 = open 
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +6
    // 2001-4158    not-used
    //
    for(int i=33; i<65; i++) opengalaxy.galaxy().m_getAllZonesOpenState[i] = buf[i-33+6]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesOpenStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesOpenState_cv.notify_one();
}

bool Galaxy::GetAllZonesOpenState(unsigned char zones_state[65])
{
  // ZSx
  // 201: Zones 1 - 256
  // 202: Zones 257 - 512
  char buf[48];
  // Get the first block
  snprintf(buf, 48, "ZS201");
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    GetAllZonesOpenStateCallbackOne
  )==false) return false;
  m_getAllZonesOpenState_cv.wait(*m_getAllZonesOpenState_lock);
  if(m_getAllZonesOpenStateRetv==true){
    // Get the second block
    snprintf(buf, 48, "ZS202");
    if(opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesOpenStateCallbackTwo
    )==false) return false;
    m_getAllZonesOpenState_cv.wait(*m_getAllZonesOpenState_lock);
    if(m_getAllZonesOpenStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesOpenState, 65);
    }
  }
  return m_getAllZonesOpenStateRetv;
}

// bool GalaxyGetAllZonesTamperState( unsigned char zones_state[65] )

void Galaxy::GetAllZonesTamperStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if( buf == nullptr ){
    opengalaxy.galaxy().m_getAllZonesTamperStateRetv = false;
  }
  else {
    // buf = 'ZS301*[35bytes]'
    // 0 = not used / 1 = oc or sc 
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +6
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +6
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesTamperState[0] = buf[7];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesTamperState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesTamperState[1] = buf[6]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesTamperState[2] = buf[9];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesTamperState[2] = buf[7]; // RIO 101
    }
    for(int i=3; i<33; i++){
      opengalaxy.galaxy().m_getAllZonesTamperState[i] = buf[i+7]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesTamperStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesTamperState_cv.notify_one();
}

void Galaxy::GetAllZonesTamperStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesTamperStateRetv = false;
  }
  else {
    // buf = 'ZS302*[33bytes]'
    // 0 = not used / 1 = oc or sc 
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +6
    // 2001-4158    not-used
    //
    for( int i=33; i<65; i++) opengalaxy.galaxy().m_getAllZonesTamperState[i] = buf[i-33+6]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesTamperStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesTamperState_cv.notify_one();
}

bool Galaxy::GetAllZonesTamperState(unsigned char zones_state[65])
{
  // ZSx
  // 301: Zones 1 - 256
  // 302: Zones 257 - 512
  char buf[48];

  // Get the first block
  snprintf(buf, 48, "ZS301");
  if(
    opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesTamperStateCallbackOne
    ) == false
  ) return false;
  m_getAllZonesTamperState_cv.wait(*m_getAllZonesTamperState_lock);
  if(m_getAllZonesTamperStateRetv==true){
    // Get the second block
    snprintf(buf, 48, "ZS302");
    if(
      opengalaxy().receiver().send(
        SiaBlock::FunctionCode::extended,
        buf,
        strlen(buf),
        GetAllZonesTamperStateCallbackTwo
      ) == false
    ) return false;
    m_getAllZonesTamperState_cv.wait(*m_getAllZonesTamperState_lock);
    if(m_getAllZonesTamperStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesTamperState, 65);
    }
  }
  return m_getAllZonesTamperStateRetv;
}

// bool GalaxyGetAllZonesRState( unsigned char zones_state[65] )

void Galaxy::GetAllZonesRStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesRStateRetv = false;
  }
  else {
    // buf = 'ZS401*[35bytes]'
    // 0 = not used / 1 = low or high R 
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +6
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +6
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesRState[0] = buf[7];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesRState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesRState[1] = buf[6]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesRState[2] = buf[9];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesRState[2] = buf[7]; // RIO 101
    }
    for(int i=3; i<33; i++){
      opengalaxy.galaxy().m_getAllZonesRState[i] = buf[i+7]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesRStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesRState_cv.notify_one();
}

void Galaxy::GetAllZonesRStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf == nullptr){
    opengalaxy.galaxy().m_getAllZonesRStateRetv = false;
  }
  else {
    // buf = 'ZS402*[33bytes]'
    // 0 = not used / 1 = low or high R 
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +6
    // 2001-4158    not-used
    //
    for(int i=33; i<65; i++) opengalaxy.galaxy().m_getAllZonesRState[i] = buf[i-33+6]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesRStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesRState_cv.notify_one();
}

bool Galaxy::GetAllZonesRState(unsigned char zones_state[65])
{
  // ZSx
  // 401: Zones 1 - 256
  // 402: Zones 257 - 512
  char buf[48];

  // Get the first block
  snprintf(buf, 48, "ZS401");
  if(
    opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesRStateCallbackOne
    ) == false
  ) return false;
  m_getAllZonesRState_cv.wait(*m_getAllZonesRState_lock);
  if(m_getAllZonesRStateRetv==true){
    // Get the second block
    snprintf(buf, 48, "ZS402");
    if(
      opengalaxy().receiver().send(
        SiaBlock::FunctionCode::extended,
        buf,
        strlen(buf),
        GetAllZonesRStateCallbackTwo
      ) == false
    ) return false;
    m_getAllZonesRState_cv.wait(*m_getAllZonesRState_lock);
    if(m_getAllZonesRStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesRState, 65);
    }
  }
  return m_getAllZonesRStateRetv;
}

// bool GalaxyGetAllZonesOmittedState( unsigned char zones_state[65] )

void Galaxy::GetAllZonesOmittedStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesOmittedStateRetv = false;
  }
  else {
    // buf = 'ZS501*[35bytes]'
    // 0 = not omitted / 1 = omitted
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +6
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +6
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesOmittedState[0] = buf[7];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesOmittedState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesOmittedState[1] = buf[6]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesOmittedState[2] = buf[9];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesOmittedState[2] = buf[7]; // RIO 101
    }
    for(int i=3; i < 33; i++){
      opengalaxy.galaxy().m_getAllZonesOmittedState[i] = buf[i+7]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesOmittedStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesOmittedState_cv.notify_one();
}

void Galaxy::GetAllZonesOmittedStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if( buf == nullptr ){
    opengalaxy.galaxy().m_getAllZonesOmittedStateRetv = false;
  }
  else {
    // buf = 'ZS502*[33bytes]'
    // 0 = not omitted / 1 = omitted
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +6
    // 2001-4158    not-used
    //
    for(int i=33; i<65; i++) opengalaxy.galaxy().m_getAllZonesOmittedState[i] = buf[i-33+6]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesOmittedStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesOmittedState_cv.notify_one();
}

bool Galaxy::GetAllZonesOmittedState(unsigned char zones_state[65])
{
  // ZSx
  // 501: Zones 1 - 256
  // 502: Zones 257 - 512
  char buf[48];

  // Get the first block
  snprintf(buf, 48, "ZS501");
  if(
    opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesOmittedStateCallbackOne
    ) == false
  ) return false;
  m_getAllZonesOmittedState_cv.wait(*m_getAllZonesOmittedState_lock);
  if(m_getAllZonesOmittedStateRetv==true){
    // Get the second block
    snprintf(buf, 48, "ZS502");
    if(
      opengalaxy().receiver().send(
        SiaBlock::FunctionCode::extended,
        buf,
        strlen(buf),
        GetAllZonesOmittedStateCallbackTwo
      ) == false
    ) return false;
    m_getAllZonesOmittedState_cv.wait(*m_getAllZonesOmittedState_lock);
    if(m_getAllZonesOmittedStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesOmittedState, 65);
    }
  }
  return m_getAllZonesOmittedStateRetv;
}

void Galaxy::GetAllZonesMaskedStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesMaskedStateRetv = false;
  }
  else {
    // buf = 'ZS601*[35bytes]'
    // 0 = not masked / 1 = masked
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +6
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +6
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesMaskedState[0] = buf[7];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesMaskedState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesMaskedState[1] = buf[6]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesMaskedState[2] = buf[9];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesMaskedState[2] = buf[7]; // RIO 101
    }
    for(int i=3; i < 33; i++){
      opengalaxy.galaxy().m_getAllZonesMaskedState[i] = buf[i+7]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesMaskedStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesMaskedState_cv.notify_one();
}

void Galaxy::GetAllZonesMaskedStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if( buf == nullptr ){
    opengalaxy.galaxy().m_getAllZonesMaskedStateRetv = false;
  }
  else {
    // buf = 'ZS602*[33bytes]'
    // 0 = not masked / 1 = masked
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +6
    // 2001-4158    not-used
    //
    for(int i=33; i<65; i++) opengalaxy.galaxy().m_getAllZonesMaskedState[i] = buf[i-33+6]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesMaskedStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesMaskedState_cv.notify_one();
}

bool Galaxy::GetAllZonesMaskedState(unsigned char zones_state[65])
{
  // ZSx
  // 601: Zones 1 - 256
  // 602: Zones 257 - 512
  char buf[48];

  // Get the first block
  snprintf(buf, 48, "ZS601");
  if(
    opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesMaskedStateCallbackOne
    ) == false
  ) return false;
  m_getAllZonesMaskedState_cv.wait(*m_getAllZonesMaskedState_lock);
  if(m_getAllZonesMaskedStateRetv==true){
    // Get the second block
    snprintf(buf, 48, "ZS602");
    if(
      opengalaxy().receiver().send(
        SiaBlock::FunctionCode::extended,
        buf,
        strlen(buf),
        GetAllZonesMaskedStateCallbackTwo
      ) == false
    ) return false;
    m_getAllZonesMaskedState_cv.wait(*m_getAllZonesMaskedState_lock);
    if(m_getAllZonesMaskedStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesMaskedState, 65);
    }
  }
  return m_getAllZonesMaskedStateRetv;
}

void Galaxy::GetAllZonesFaultStateCallbackOne(openGalaxy& opengalaxy, char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_getAllZonesFaultStateRetv = false;
  }
  else {
    // buf = 'ZS701*[35bytes]'
    // 0 = no fault / 1 = fault
    //
    // dip8 = 0
    //  byte 0     byte 1     byte 2    byte 3   byte 4-33   byte 34    +6
    // 1001-1008  1011-1018  not-used  not-used  1021-2158  not-used
    //
    // dip8 = 1
    //  byte 0     byte 1     byte 2    byte 3    byte 4-33   byte 34   +6
    // 1001-1008  0011-0018  not-used  1011-1018  1021-2158  not-used
    //
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesFaultState[0] = buf[7];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesFaultState[0] = 0; // RIO 001
    }
    opengalaxy.galaxy().m_getAllZonesFaultState[1] = buf[6]; // RIO 100
    if(opengalaxy.settings().galaxy_dip8 != 0){
      opengalaxy.galaxy().m_getAllZonesFaultState[2] = buf[9];
    }
    else {
      opengalaxy.galaxy().m_getAllZonesFaultState[2] = buf[7]; // RIO 101
    }
    for(int i=3; i < 33; i++){
      opengalaxy.galaxy().m_getAllZonesFaultState[i] = buf[i+7]; // RIOs 102 ... 215
    }
    opengalaxy.galaxy().m_getAllZonesFaultStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesFaultState_cv.notify_one();
}

void Galaxy::GetAllZonesFaultStateCallbackTwo(openGalaxy& opengalaxy, char* buf, int len)
{
  if( buf == nullptr ){
    opengalaxy.galaxy().m_getAllZonesFaultStateRetv = false;
  }
  else {
    // buf = 'ZS702*[33bytes]'
    // 0 = no fault / 1 = fault
    //
    // dip8 = 0/1
    //  byte 0-31   byte 32     +6
    // 2001-4158    not-used
    //
    for(int i=33; i<65; i++) opengalaxy.galaxy().m_getAllZonesFaultState[i] = buf[i-33+6]; // RIOs 300 ... 415
    opengalaxy.galaxy().m_getAllZonesFaultStateRetv = true;
  }
  opengalaxy.galaxy().m_getAllZonesFaultState_cv.notify_one();
}

bool Galaxy::GetAllZonesFaultState(unsigned char zones_state[65])
{
  // ZSx
  // 701: Zones 1 - 256
  // 702: Zones 257 - 512
  char buf[48];

  // Get the first block
  snprintf(buf, 48, "ZS701");
  if(
    opengalaxy().receiver().send(
      SiaBlock::FunctionCode::extended,
      buf,
      strlen(buf),
      GetAllZonesFaultStateCallbackOne
    ) == false
  ) return false;
  m_getAllZonesFaultState_cv.wait(*m_getAllZonesFaultState_lock);
  if(m_getAllZonesFaultStateRetv==true){
    // Get the second block
    snprintf(buf, 48, "ZS702");
    if(
      opengalaxy().receiver().send(
        SiaBlock::FunctionCode::extended,
        buf,
        strlen(buf),
        GetAllZonesFaultStateCallbackTwo
      ) == false
    ) return false;
    m_getAllZonesFaultState_cv.wait(*m_getAllZonesFaultState_lock);
    if(m_getAllZonesFaultStateRetv==true){
      memcpy(zones_state, (void*)m_getAllZonesFaultState, 65);
    }
  }
  return m_getAllZonesFaultStateRetv;
}


void Galaxy::ReprocessEventsCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  // Was the command successfull?
  if(buf == nullptr) opengalaxy.galaxy().m_reprocessEventsCallbackRetv = false;
  else opengalaxy.galaxy().m_reprocessEventsCallbackRetv = true;
  // Unblock
  opengalaxy.galaxy().m_reprocessEvents_cv.notify_one();
}

bool Galaxy::ReprocessEvents(unsigned int nr, Galaxy::sia_module module)
{
  // Reprocess nr (1-1000 or 0 for all) events for the given SIA module
  // EVx*y
  // 1: ack

  if(nr > 1000) nr = 0;

  char buf[16];
  if(module == Galaxy::sia_module::all){
    snprintf(buf, 16, "EV%u*", nr); // all modules
  }
  else {
    snprintf(buf, 16, "EV%u*%u", nr, (unsigned int)module); // selected module
  }

  // Let the receiver thread send the command
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    ReprocessEventsCallback
  )==false) return false;

  // and wait for the callback to finish
  m_reprocessEvents_cv.wait(*m_reprocessEvents_lock);
  return m_reprocessEventsCallbackRetv;
}


void Galaxy::FlushEventsCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  // Was the command successfull?
  if(buf == nullptr) opengalaxy.galaxy().m_flushEventsCallbackRetv = false;
  else opengalaxy.galaxy().m_flushEventsCallbackRetv = true;
  // Unblock
  opengalaxy.galaxy().m_flushEvents_cv.notify_one();
}

bool Galaxy::FlushEvents(Galaxy::sia_module module)
{
  // Flush all events for the given SIA module
  // EV*y
  // 1: ack

  char buf[16];
  if(module == Galaxy::sia_module::all){
    snprintf(buf, 16, "EV*"); // all modules
  }
  else {
    snprintf(buf, 16, "EV*%u", (unsigned int)module); // selected module
  }

  // Let the receiver thread send the command
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    FlushEventsCallback
  )==false) return false;

  // and wait for the callback to finish
  m_flushEvents_cv.wait(*m_flushEvents_lock);
  return m_flushEventsCallbackRetv;
}

void Galaxy::CheckEventsCallback(openGalaxy& opengalaxy,char* buf, int len)
{
  if(buf==nullptr){
    opengalaxy.galaxy().m_checkEventsCallbackResult = 0;
    opengalaxy.galaxy().m_checkEventsCallbackRetv = false;
  }
  else {
    // 'EVx*y'
    opengalaxy.galaxy().m_checkEventsCallbackResult = strtol(&buf[2], nullptr, 10);
    opengalaxy.galaxy().m_checkEventsCallbackRetv = true;
  }
  opengalaxy.galaxy().m_checkEvents_cv.notify_one();
}

bool Galaxy::CheckEvents(unsigned int& nr, Galaxy::sia_module module)
{
  // Get the number of events that the given SIA module needs tp process
  // EVy
  // 1: EVx*y

  char buf[16];
  if(module == Galaxy::sia_module::all){
    snprintf(buf, 16, "EV"); // all modules
  }
  else {
    snprintf(buf, 16, "EV%u", (unsigned int)module); // selected module
  }

  // Let the receiver thread send the command
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    CheckEventsCallback
  )==false) return false;

  // and wait for the callback to finish
  m_checkEvents_cv.wait(*m_checkEvents_lock);

  nr = (unsigned int)m_checkEventsCallbackResult;

  return m_checkEventsCallbackRetv;
}


void Galaxy::GenerateWrongCodeAlarmCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  // Was the command successfull?
  if(buf == nullptr) opengalaxy.galaxy().m_generateWrongCodeAlarmCallbackRetv = false;
  else opengalaxy.galaxy().m_generateWrongCodeAlarmCallbackRetv = true;
  // Unblock
  opengalaxy.galaxy().m_generateWrongCodeAlarm_cv.notify_one();
}

bool Galaxy::GenerateWrongCodeAlarm_nb(Galaxy::sia_module module, Receiver::transmit_callback callback)
{
  // Generate a wrong code alarm for the given SIA module
  // EV20000*y
  // 1: ack

  char buf[16];
  if(module == Galaxy::sia_module::all){
    snprintf(buf, 16, "EV20000*"); // all modules
  }
  else {
    snprintf(buf, 16, "EV20000*%u", (unsigned int)module); // selected module
  }

  // Let the receiver thread send the command
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    callback
  )==false) return false;

  return true;
}

bool Galaxy::GenerateWrongCodeAlarm(Galaxy::sia_module module)
{
  // Let the receiver thread send the command
  if(GenerateWrongCodeAlarm_nb(module, GenerateWrongCodeAlarmCallback) == false) return false;

  // and wait for the callback to finish
  m_generateWrongCodeAlarm_cv.wait(*m_generateWrongCodeAlarm_lock);
  return m_generateWrongCodeAlarmCallbackRetv;
}


void Galaxy::SetZoneStateCallback(openGalaxy& opengalaxy, char* buf, int len)
{
  // Was the command successfull?
  if(buf == nullptr) opengalaxy.galaxy().m_setZoneStateCallbackRetv = false;
  else opengalaxy.galaxy().m_setZoneStateCallbackRetv = true;
  // Unblock
  opengalaxy.galaxy().m_setZoneState_cv.notify_one();
}

// Set the state of a zone or zone type.
//
// Argument 'zone' may only be a zone type when
//  'prg' != zone_program::force_??? 
//
// Arguments 'blknum', 'zone_type' and 'desc' are optional and only valid when
//  'prg' == zone_program::force_??? 
//
// If 'blknum' or 'zone_type' are 0 then these arguments and
// the 'desc' argument will not be modified.
//
// The 'desc' argument is optional but requires a non 0
// value for the 'blknum' and 'zone_type' arguments.
//
bool Galaxy::SetZoneState(
  unsigned int zone,          // the zone (1001-4158) or zone type (1-100), 0 is all zones
  Galaxy::zone_program prg,   // the new zone flag or state
  unsigned int blknum,    // the area number (01-32, 0 = do not use)
  unsigned int zone_type, // the zone type (01-99, 0 = do not use)
  const char *desc  // zone description (optional, max. 16 chars)
){
  // ZSx*yz  ( where x=<zone>, y=<prg>, z=[<blknum><zone_type>[desc]] )

  char buf[48];

  // Sanity check
  switch(prg){
    case Galaxy::zone_program::soak_test_off:
    case Galaxy::zone_program::soak_test_on:
    case Galaxy::zone_program::part_set_off:
    case Galaxy::zone_program::part_set_on:
      if(zone > 100 && IsZone(zone) == false) return false;
      if(zone == 0){
        snprintf(buf, 48, "ZS*%1u", (unsigned int)prg);
      }
      else {
        snprintf(buf, 48, "ZS%u*%1u", zone, (unsigned int)prg);
      }
      break;
    case Galaxy::zone_program::force_open:
    case Galaxy::zone_program::force_closed:
    case Galaxy::zone_program::force_open_and_close:
    case Galaxy::zone_program::force_tamper:
      if(IsZone(zone) == false) return false;
      if(blknum == 0 || zone_type == 0){
        blknum = 0;
        zone_type = 0;
        desc = nullptr;
      }
      if(blknum != 0 && zone_type != 0){
        if(desc != nullptr){
          snprintf(buf, 48, "ZS%u*%1u%02u%02u%s", zone, (unsigned int)prg, blknum, zone_type, desc);
          // ZS0000*122334444444444444444
          // 01234567890123456789012345678
          buf[28] = '\0'; // use max 16 chatacters of desc
        }
        else {
          snprintf(buf, 48, "ZS%u*%1u%02u%02u", zone, (unsigned int)prg, blknum, zone_type);
        }
      }
      else {
        snprintf(buf, 48, "ZS%u*%1u", zone, (unsigned int)prg);
      }
      break;
    default:
      return false;
  }

  // Let the receiver thread send the command
  if(opengalaxy().receiver().send(
    SiaBlock::FunctionCode::extended,
    buf,
    strlen(buf),
    SetZoneStateCallback
  )==false) return false;

  // and wait for the callback to finish
  m_setZoneState_cv.wait(*m_setZoneState_lock);
  return m_setZoneStateCallbackRetv;
}


} // ends namespace openGalaxy

