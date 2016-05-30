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

#ifndef __OPENGALAXY_GALAXY_HPP__
#define __OPENGALAXY_GALAXY_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <condition_variable>

#include "opengalaxy.hpp"

namespace openGalaxy {

class Galaxy {
public:

  // Galaxy zone states:
  enum class zone_state : unsigned int {
    tamper_sc = 0, // 0 = Zone tamper S/C
    low_r,         // 1 = Low resistance
    closed,        // 2 = Zone closed
    high_r,        // 3 = High resistance
    open,          // 4 = Zone open
    tamper_oc,     // 5 = Zone tamper O/C
    masked,        // 6 = Zone masked
    tamper_cv,     // 7 = Zone tamper CV
    fault          // 8 = Zone fault
  };

  // Galaxy zone actions:
  enum class zone_action : unsigned int {
    unomit = 0, // 0 = Unomit
    omit        // 1 = Omit
  };

  // Galaxy area 'armed' states:
  enum class area_armed_state : unsigned int {
    unset = 0, // 0 = Area is not armed
    set,       // 1 = Area is armed
    part_set   // 2 = Area is partialy armed
  };

  // Galaxy area 'ready' states:
  enum class area_ready_state : unsigned int {
    unset = 0,    // 0 = Area is not armed
    set,          // 1 = Area is armed
    part_set,     // 2 = Area is partialy armed
    ready_to_set, // 3 = Area is ready to set (all zones closed)
    time_locked   // 4 = Area is time locked
  };

  // Galaxy area 'alarm' states:
  enum class area_alarm_state : unsigned int {
    normal = 0,     // 0 = Area is normal
    alarm,          // 1 = Area has an alarm
    reset_required, // 2 = Area needs to be reset
  };

  // Galaxy area actions:
  enum class area_action : unsigned int {
    unset = 0, // 0 = Disarm area
    set,       // 1 = Arm area
    part_set,  // 2 = Partialy arm area
    reset,     // 3 = Reset area
    abort_set, // 4 = Abort arming of area
    force_set  // 5 = Force arming of area
  };

  // Galaxy SIA modules:
  enum class sia_module : unsigned int {
    telecom = 0, // 0 = Telecom module
    rs232,       // 1 = RS232 module
    monitor,     // 2 = AlarmMonitor (Tel)
    all = 99     // (nothing) = All modules
  };

  // things we can do with SetZoneState()
  enum class zone_program : unsigned int {
    soak_test_off = 0,    // disable soak test flag for a (virtual) zone
    soak_test_on,         // enable soak test flag for a (virtual) zone
    part_set_off,         // disable the part set flag for a (virtual) zone
    part_set_on,          // enable the part set flag for a (virtual) zone
    force_open,           // force opening of a (virtual) zone
    force_closed,         // force closing of a (virtual) zone
    force_open_and_close, // force open, then close a (virtual) zone
    force_tamper          // force tamper of a (virtual) zone
  };

  // An entire byte represents 8 zones or outputs
  union alignas(1) GalaxyByte {
    unsigned char byte;
    struct {
      // bits 0...7: outputs for 2 RIO's
      unsigned char out1LSB :1;
      unsigned char out2LSB :1;
      unsigned char out3LSB :1;
      unsigned char out4LSB :1;
      unsigned char out1MSB :1;
      unsigned char out2MSB :1;
      unsigned char out3MSB :1;
      unsigned char out4MSB :1;
    };
    struct {
      // bits 0...7: zones for 1 RIO's
      unsigned char zone1 :1;
      unsigned char zone2 :1;
      unsigned char zone3 :1;
      unsigned char zone4 :1;
      unsigned char zone5 :1;
      unsigned char zone6 :1;
      unsigned char zone7 :1;
      unsigned char zone8 :1;
    };
  };

  struct alignas(1) GalaxyOutputs32 {
    GalaxyByte RIO100;   // byte 1  RIO 100 + 101
    GalaxyByte RIO102;   // byte 2  RIO 102 + 103
    GalaxyByte RIO104;   // byte 3  RIO 104 + 105
    GalaxyByte RIO106;   // byte 4  RIO 106 + 107
    GalaxyByte RIO108;   // byte 5  RIO 108 + 109
    GalaxyByte RIO110;   // byte 6  RIO 110 + 111
    GalaxyByte RIO112;   // byte 7  RIO 112 + 113
    GalaxyByte RIO114;   // byte 8  RIO 114 + 115
    GalaxyByte RIO200;   // byte 9  RIO 200 + 201
    GalaxyByte RIO202;   // byte 10 RIO 202 + 203
    GalaxyByte RIO204;   // byte 11 RIO 204 + 205
    GalaxyByte RIO206;   // byte 12 RIO 206 + 207
    GalaxyByte RIO208;   // byte 13 RIO 208 + 209
    GalaxyByte RIO210;   // byte 14 RIO 210 + 211
    GalaxyByte RIO212;   // byte 15 RIO 212 + 213
    GalaxyByte RIO214;   // byte 16 RIO 214 + 215
    GalaxyByte RIO300;   // byte 17 RIO 300 + 301
    GalaxyByte RIO302;   // byte 18 RIO 302 + 303
    GalaxyByte RIO304;   // byte 19 RIO 304 + 305
    GalaxyByte RIO306;   // byte 20 RIO 306 + 307
    GalaxyByte RIO308;   // byte 21 RIO 308 + 309
    GalaxyByte RIO310;   // byte 22 RIO 310 + 311
    GalaxyByte RIO312;   // byte 23 RIO 312 + 313
    GalaxyByte RIO314;   // byte 24 RIO 314 + 315
    GalaxyByte RIO400;   // byte 25 RIO 400 + 401
    GalaxyByte RIO402;   // byte 26 RIO 402 + 403
    GalaxyByte RIO404;   // byte 27 RIO 404 + 405
    GalaxyByte RIO406;   // byte 28 RIO 406 + 407
    GalaxyByte RIO408;   // byte 29 RIO 408 + 409
    GalaxyByte RIO410;   // byte 30 RIO 410 + 411
    GalaxyByte RIO412;   // byte 31 RIO 412 + 413
    GalaxyByte RIO414;   // byte 32 RIO 414 + 415
  };

  struct alignas(1) GalaxyZonesState {
    GalaxyByte RIO001;   // byte 0
    GalaxyByte RIO100;   // byte 1
    GalaxyByte RIO101;   // byte 2
    GalaxyByte RIO102;   // byte 3
    GalaxyByte RIO103;   // byte 4
    GalaxyByte RIO104;   // byte 5
    GalaxyByte RIO105;   // byte 6
    GalaxyByte RIO106;   // byte 7
    GalaxyByte RIO107;   // byte 8
    GalaxyByte RIO108;   // byte 9
    GalaxyByte RIO109;   // byte 10
    GalaxyByte RIO110;   // byte 11
    GalaxyByte RIO111;   // byte 12
    GalaxyByte RIO112;   // byte 13
    GalaxyByte RIO113;   // byte 14
    GalaxyByte RIO114;   // byte 15
    GalaxyByte RIO115;   // byte 16
    GalaxyByte RIO200;   // byte 17
    GalaxyByte RIO201;   // byte 18
    GalaxyByte RIO202;   // byte 19
    GalaxyByte RIO203;   // byte 20
    GalaxyByte RIO204;   // byte 21
    GalaxyByte RIO205;   // byte 22
    GalaxyByte RIO206;   // byte 23
    GalaxyByte RIO207;   // byte 24
    GalaxyByte RIO208;   // byte 25
    GalaxyByte RIO209;   // byte 26
    GalaxyByte RIO210;   // byte 27
    GalaxyByte RIO211;   // byte 28
    GalaxyByte RIO212;   // byte 29
    GalaxyByte RIO213;   // byte 30
    GalaxyByte RIO214;   // byte 31
    GalaxyByte RIO215;   // byte 32
    GalaxyByte RIO300;   // byte 33
    GalaxyByte RIO301;   // byte 34 
    GalaxyByte RIO302;   // byte 35
    GalaxyByte RIO303;   // byte 36
    GalaxyByte RIO304;   // byte 37
    GalaxyByte RIO305;   // byte 38
    GalaxyByte RIO306;   // byte 39
    GalaxyByte RIO307;   // byte 40
    GalaxyByte RIO308;   // byte 41
    GalaxyByte RIO309;   // byte 42
    GalaxyByte RIO310;   // byte 43
    GalaxyByte RIO311;   // byte 44
    GalaxyByte RIO312;   // byte 45
    GalaxyByte RIO313;   // byte 46
    GalaxyByte RIO314;   // byte 47
    GalaxyByte RIO315;   // byte 48
    GalaxyByte RIO400;   // byte 49
    GalaxyByte RIO401;   // byte 50
    GalaxyByte RIO402;   // byte 51
    GalaxyByte RIO403;   // byte 52
    GalaxyByte RIO404;   // byte 53
    GalaxyByte RIO405;   // byte 54
    GalaxyByte RIO406;   // byte 55
    GalaxyByte RIO407;   // byte 56
    GalaxyByte RIO408;   // byte 57
    GalaxyByte RIO409;   // byte 58
    GalaxyByte RIO410;   // byte 59
    GalaxyByte RIO411;   // byte 60
    GalaxyByte RIO412;   // byte 61
    GalaxyByte RIO413;   // byte 62
    GalaxyByte RIO414;   // byte 63
    GalaxyByte RIO415;   // byte 64
  };

  Galaxy(openGalaxy&);
  ~Galaxy();

  // The functions below:
  //
  //  - Sends one or more SiaBlock's to the transmitter and
  //    set a callback function to call when the receiver class has received a reply.
  //  - The functions then block by use of a condition variable, until that reply has been received.
  //  - Finally any received data is transferred to the calling function.

  // Perform a(n) area/zone/output action
  bool AreaAction              ( unsigned int blknum, area_action action );
  bool ZoneAction              ( unsigned int zone, zone_action action );
  bool OutputAction            ( unsigned int output, bool state, unsigned int area );

  // Get the status for a given area or all areas
  bool GetAreaArmedState       ( unsigned int blknum, area_armed_state* state );
  bool GetAllAreasArmedState   ( area_armed_state state[32] );
  bool GetAllAreasAlarmState   ( area_alarm_state state[32] );
  bool GetAllAreasReadyState   ( area_ready_state state[32] );

  // Check if a given zone is omitted
  bool ZoneIsOmit              ( unsigned int zone, zone_action *state );

  // Check the status of a given zone
  bool GetZoneState            ( unsigned int zone, zone_state *state );

  // Get the Ready/Alarm/Open/Tamper/Resistance/Omitted/Masked/Fault state 
  // for all zones, each bit in the 65 byte buffer represents a single zone
  // and may be casted to a struct GalaxyZonesState.
  bool GetAllZonesReadyState   ( unsigned char zones_state[65] );
  bool GetAllZonesAlarmState   ( unsigned char zones_state[65] );
  bool GetAllZonesOpenState    ( unsigned char zones_state[65] );
  bool GetAllZonesTamperState  ( unsigned char zones_state[65] );
  bool GetAllZonesRState       ( unsigned char zones_state[65] );
  bool GetAllZonesOmittedState ( unsigned char zones_state[65] );
  bool GetAllZonesMaskedState  ( unsigned char zones_state[65] );        // currently unused by commander
  bool GetAllZonesFaultState   ( unsigned char zones_state[65] );        // currently unused by commander

  // Get the state of all outputs, each bit in the 32 byte buffer represents
  // a single output and may be casted to a struct GalaxyOutputs32.
  bool GetAllOutputs           ( unsigned char outputs[32] );

  // Reprocess nr (1-1000 or 0 for all) events for the given SIA module
  bool ReprocessEvents         ( unsigned int nr, sia_module module);    // currently unused by commander

  // Flush all events for the given SIA module
  bool FlushEvents             (sia_module module);                      // currently unused by commander

  // Get the number of events that the given SIA module needs tp process
  bool CheckEvents             (unsigned int& nr, sia_module module);    // currently unused by commander

  // Generate a wrong code alarm for the given SIA module
  bool GenerateWrongCodeAlarm(sia_module module);
  bool GenerateWrongCodeAlarm_nb(Galaxy::sia_module module, Receiver::transmit_callback callback);

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
  bool SetZoneState(
    unsigned int zone,           // the zone (1001-4158) or zone type (1-100), 0 is all zones
    zone_program prg,            // the new zone flag or state
    unsigned int blknum = 0,     // the area number (01-32)
    unsigned int zone_type = 0,  // the zone type (01-99)
    const char *desc = nullptr   // zone description (optional, max. 16 chars)
  );

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }

private:

  class openGalaxy& m_openGalaxy;

  bool IsZone(int nr);
  bool IsOutput(int nr);

  // for AreaAction()
  static void AreaActionCallback(class openGalaxy&,char*,int len);
  volatile bool m_areaActionCallbackRetv;
  std::condition_variable m_areaAction_cv;
  std::unique_lock<std::mutex> *m_areaAction_lock;
  std::mutex m_areaAction_mutex;

  // for GetAreaArmedState()
  static void GetAreaArmedStateCallback(class openGalaxy&,char*,int);
  volatile bool m_getAreaArmedStateRetv;
  volatile area_armed_state* m_getAreaArmedStateState;
  volatile unsigned int m_getAreaArmedStateBlknum;
  std::condition_variable m_getAreaArmedState_cv;
  std::unique_lock<std::mutex> *m_getAreaArmedState_lock;
  std::mutex m_getAreaArmedState_mutex;

  // for GetAllAreasArmedState()
  static void GetAllAreasArmedStateCallback(class openGalaxy&,char*,int);
  volatile bool m_getAllAreasArmedStateRetv;
  volatile area_armed_state m_getAllAreasArmedState[32];
  std::condition_variable m_getAllAreasArmedState_cv;
  std::unique_lock<std::mutex> *m_getAllAreasArmedState_lock;
  std::mutex m_getAllAreasArmedState_mutex;

  // for GetAllAreasAlarmState()
  static void GetAllAreasAlarmStateCallback(class openGalaxy&,char* buf,int);
  volatile bool m_getAllAreasAlarmStateRetv;
  volatile area_alarm_state m_getAllAreasAlarmState[32];
  std::condition_variable m_getAllAreasAlarmState_cv;
  std::unique_lock<std::mutex> *m_getAllAreasAlarmState_lock;
  std::mutex m_getAllAreasAlarmState_mutex;

  // for GetAllAreasReadyState()
  static void GetAllAreasReadyStateCallback(class openGalaxy&,char* buf,int);
  volatile bool m_getAllAreasReadyStateRetv;
  volatile area_ready_state m_getAllAreasReadyState[32];
  std::condition_variable m_getAllAreasReadyState_cv;
  std::unique_lock<std::mutex> *m_getAllAreasReadyState_lock;
  std::mutex m_getAllAreasReadyState_mutex;

  // for ZoneAction()
  static void ZoneActionCallback(class openGalaxy&,char*,int);
  volatile bool m_zoneActionRetv;
  std::condition_variable m_zoneAction_cv;
  std::unique_lock<std::mutex> *m_zoneAction_lock;
  std::mutex m_zoneAction_mutex;

  // for ZoneIsOmit()
  static void ZoneIsOmitCallback(class openGalaxy&,char*,int);
  volatile bool m_zoneIsOmitRetv;
  volatile zone_action* m_zoneIsOmitState;
  std::condition_variable m_zoneIsOmit_cv;
  std::unique_lock<std::mutex> *m_zoneIsOmit_lock;
  std::mutex m_zoneIsOmit_mutex;

  // for OutputAction()
  static void OutputActionCallback(class openGalaxy&,char*, int);
  volatile bool m_outputActionRetv;
  std::condition_variable m_outputAction_cv;
  std::unique_lock<std::mutex> *m_outputAction_lock;
  std::mutex m_outputAction_mutex;

  // for GetAllOutputs()
  static void GetAllOutputsCallback(class openGalaxy&,char*, int);
  volatile bool m_getAllOutputsRetv;
  volatile unsigned char m_getAllOutputsState[32];
  std::condition_variable m_getAllOutputs_cv;
  std::unique_lock<std::mutex> *m_getAllOutputs_lock;
  std::mutex m_getAllOutputs_mutex;

  // for GetZoneState()
  static void GetZoneStateCallback(class openGalaxy&,char*,int);
  volatile bool m_getZoneStateRetv;
  volatile zone_state* m_getZoneStateState;
  std::condition_variable m_getZoneState_cv;
  std::unique_lock<std::mutex> *m_getZoneState_lock;
  std::mutex m_getZoneState_mutex;

  // for GetAllZonesReadyState()
  static void GetAllZonesReadyStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesReadyStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesReadyStateRetv;
  volatile unsigned char m_getAllZonesReadyState[65];
  std::condition_variable m_getAllZonesReadyState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesReadyState_lock;
  std::mutex m_getAllZonesReadyState_mutex;

  // for GetAllZonesAlarmState()
  static void GetAllZonesAlarmStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesAlarmStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesAlarmStateRetv;
  volatile unsigned char m_getAllZonesAlarmState[65];
  std::condition_variable m_getAllZonesAlarmState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesAlarmState_lock;
  std::mutex m_getAllZonesAlarmState_mutex;

  // for GetAllZonesOpenState()
  static void GetAllZonesOpenStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesOpenStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesOpenStateRetv;
  volatile unsigned char m_getAllZonesOpenState[65];
  std::condition_variable m_getAllZonesOpenState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesOpenState_lock;
  std::mutex m_getAllZonesOpenState_mutex;

  // for GetAllZonesTamperState()
  static void GetAllZonesTamperStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesTamperStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesTamperStateRetv;
  volatile unsigned char m_getAllZonesTamperState[65];
  std::condition_variable m_getAllZonesTamperState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesTamperState_lock;
  std::mutex m_getAllZonesTamperState_mutex;

  // for GetAllZonesRState()
  static void GetAllZonesRStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesRStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesRStateRetv;
  volatile unsigned char m_getAllZonesRState[65];
  std::condition_variable m_getAllZonesRState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesRState_lock;
  std::mutex m_getAllZonesRState_mutex;

  // for GetAllZonesOmittedState()
  static void GetAllZonesOmittedStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesOmittedStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesOmittedStateRetv;
  volatile unsigned char m_getAllZonesOmittedState[65];
  std::condition_variable m_getAllZonesOmittedState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesOmittedState_lock;
  std::mutex m_getAllZonesOmittedState_mutex;

  // for GetAllZonesMaskedState()
  static void GetAllZonesMaskedStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesMaskedStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesMaskedStateRetv;
  volatile unsigned char m_getAllZonesMaskedState[65];
  std::condition_variable m_getAllZonesMaskedState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesMaskedState_lock;
  std::mutex m_getAllZonesMaskedState_mutex;

  // for GetAllZonesFaultState()
  static void GetAllZonesFaultStateCallbackOne(class openGalaxy&,char*,int);
  static void GetAllZonesFaultStateCallbackTwo(class openGalaxy&,char*,int);
  volatile bool m_getAllZonesFaultStateRetv;
  volatile unsigned char m_getAllZonesFaultState[65];
  std::condition_variable m_getAllZonesFaultState_cv;
  std::unique_lock<std::mutex> *m_getAllZonesFaultState_lock;
  std::mutex m_getAllZonesFaultState_mutex;

  // for ReprocessEvents()
  static void ReprocessEventsCallback(class openGalaxy&,char*,int);
  volatile bool m_reprocessEventsCallbackRetv;
  std::condition_variable m_reprocessEvents_cv;
  std::unique_lock<std::mutex> *m_reprocessEvents_lock;
  std::mutex m_reprocessEvents_mutex;

  // for FlushEvents()
  static void FlushEventsCallback(class openGalaxy&,char*,int);
  volatile bool m_flushEventsCallbackRetv;
  std::condition_variable m_flushEvents_cv;
  std::unique_lock<std::mutex> *m_flushEvents_lock;
  std::mutex m_flushEvents_mutex;

  // for CheckEvents()
  static void CheckEventsCallback(class openGalaxy&,char*,int);
  volatile bool m_checkEventsCallbackRetv;
  volatile long m_checkEventsCallbackResult;
  std::condition_variable m_checkEvents_cv;
  std::unique_lock<std::mutex> *m_checkEvents_lock;
  std::mutex m_checkEvents_mutex;

  // for GenerateWrongCodeAlarm()
  static void GenerateWrongCodeAlarmCallback(class openGalaxy&,char*,int);
  volatile bool m_generateWrongCodeAlarmCallbackRetv;
  std::condition_variable m_generateWrongCodeAlarm_cv;
  std::unique_lock<std::mutex> *m_generateWrongCodeAlarm_lock;
  std::mutex m_generateWrongCodeAlarm_mutex;

  // for SetZoneState()
  static void SetZoneStateCallback(class openGalaxy&,char*,int);
  volatile bool m_setZoneStateCallbackRetv;
  std::condition_variable m_setZoneState_cv;
  std::unique_lock<std::mutex> *m_setZoneState_lock;
  std::mutex m_setZoneState_mutex;
};

} // ends namespace openGalaxy

#endif

