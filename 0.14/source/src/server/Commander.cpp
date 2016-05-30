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
#include "Commander.hpp"

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>

namespace openGalaxy {

Commander::command_t Commander::commands_list[] = {
  { Commander::cmd::help,       "HELP"       },
  { Commander::cmd::area,       "AREA"       },
  { Commander::cmd::zone,       "ZONE"       },
  { Commander::cmd::zones,      "ZONES"      },
  { Commander::cmd::output,     "OUTPUT"     },
  { Commander::cmd::poll,       "POLL"       },
  { Commander::cmd::code_alarm, "CODE-ALARM" },
  { Commander::cmd::count,      nullptr      }
};

struct Commander::area_action_t Commander::area_actions_list[] = {
  { Commander::area_action::unset,    "UNSET" },
  { Commander::area_action::set,      "SET" },
  { Commander::area_action::partset,  "PARTIAL" },
  { Commander::area_action::reset,    "RESET" },
  { Commander::area_action::abortset, "ABORT" },
  { Commander::area_action::forceset, "FORCE" },
  { Commander::area_action::state,    "STATE" },
  { Commander::area_action::alarm,    "ALARM" },
  { Commander::area_action::ready,    "READY" },
  { Commander::area_action::count, nullptr }
};

struct Commander::zone_typename_t Commander::zone_typenames[] = {
  { 1,  "FINAL"           }, { 2,  "EXIT"            }, { 3,  "INTRUDER"        }, { 4,  "24-HOURS"        },
  { 5,  "SECURITY"        }, { 6,  "DUAL"            }, { 7,  "ENTRY"           }, { 8,  "PUSH-SET"        },
  { 9,  "KEYSWITCH"       }, { 10, "SECURE-FINAL"    }, { 11, "PART-FINAL"      }, { 12, "PART-ENTRY"      },
  { 13, "PA"              }, { 14, "PA-SILENT"       }, { 15, "PA-DELAY"        }, { 16, "PA-DELAY-SILENT" },
  { 17, "LINK"            }, { 18, "SPARE"           }, { 19, "FIRE"            }, { 20, "TAMPER"          },
  { 21, "BELL-TAMPER"     }, { 22, "BEAM-PAIR"       }, { 23, "BATTERY-LOW"     }, { 24, "LINE-FAIL"       },
  { 25, "AC-FAIL"         }, { 26, "LOG"             }, { 27, "REMOTE-ACCESS"   }, { 28, "VIDEO"           },
  { 29, "VIDEO-EXIT"      }, { 30, "INTRUDER-DELAY"  }, { 31, "LOG-DELAY"       }, { 32, "SET-LOG"         },
  { 33, "CUSTOM-A"        }, { 34, "CUSTOM-B"        }, { 35, "EXITGUARD"       }, { 36, "MASK"            },
  { 37, "URGENT"          }, { 38, "PA-UNSET"        }, { 39, "KEYSWITCH-RESET" }, { 40, "BELL-FAIL"       },
  { 41, "INTR-LOW"        }, { 42, "INTR-HIGH"       }, { 43, "PSU-FAULT"       }, { 47, "VIBRATION"       },
  { 48, "ATM-1"           }, { 49, "ATM-2"           }, { 50, "ATM-3"           }, { 51, "ATM-4"           },
  { 52, "ALARM-EXTEND"    },

  { 1,  "LAATSTE"         }, { 2,  "VOLGZONE"        }, { 3,  "INBRAAK"         }, { 4,  "24-UUR"          },
  { 6,  "INBR.DUBB"       }, { 7,  "IN/UIT"          }, { 8,  "PULS-AAN"        }, { 9,  "SLEUTEL"         },
  { 10, "SEC/LTSTE"       }, { 11, "DL/LTSTE"        }, { 12, "DL/IN-UIT"       }, { 13, "PANIEK"          },
  { 14, "PA-STIL"         }, { 15, "PA-VERT."        }, { 16, "PA-VER/ST"       }, { 17, "LINK-ING."       },
  { 18, "RESERVE"         }, { 19, "BRAND"           }, { 20, "SABOTAGE"        }, { 21, "SIR.-SAB."       },
  { 22, "BEAMPAAR"        }, { 23, "ACCU-LAAG"       }, { 24, "LIJN-FOUT"       }, { 25, "230VAC"          },
  { 26, "GEHEUGEN"        }, { 27, "RS-TOEG."        }, { 29, "VIDEOVOLG"       }, { 30, "INBR-VERT"       },
  { 31, "GEH-VERTR"       }, { 32, "GEH.-ING."       }, { 35, "BEWAKING"        }, { 36, "AFDEK"           },
  { 38, "PA-UIT"          }, { 39, "SLS-RESET"       }, { 40, "SIR-FOUT"        }, { 41, "INBR-LAAG"       },
  { 42, "INBR-HOOG"       }, { 43, "PSU-FOUT"        }, { 47, "KLUISDET."       }, { 52, "ALARM-EXT"       },

  { 4,  "24UUR"           }, { 6,  "INBR-DUBB"       }, { 7,  "IN-UIT"          }, { 10, "SEC-LTSTE"       },
  { 11, "DL-LTSTE"        }, { 12, "DL-IN-UIT"       }, { 15, "PA-VERT"         }, { 17, "LINK-ING"        },
  { 21, "SIR-SAB"         }, { 27, "RS-TOEG"         }, { 32, "GEH-ING"         }, { 47, "KLUISDET"        },

  { 0, nullptr }
};

struct Commander::zone_action_t Commander::zone_actions_list[] = {
  { Commander::zone_action::unomit,     "UNOMIT" },
  { Commander::zone_action::omit,       "OMIT" },
  { Commander::zone_action::isomit,     "ISOMIT" },
  { Commander::zone_action::zone_state, "STATE" },
  { Commander::zone_action::parameter,  "PARAMETER" },
  { Commander::zone_action::set       , "SET" },
  { Commander::zone_action::count, nullptr }
};

struct Commander::zone_parameter_option_t Commander::zone_parameter_options_list[] = {
  { Commander::zone_parameter_option::soak_test, "SOAK-TEST" },
  { Commander::zone_parameter_option::part_set,  "PART-SET" },
  { Commander::zone_parameter_option::count, nullptr },
};

struct Commander::zone_parameter_flag_t Commander::zone_parameter_flags_list[] = {
  { Commander::zone_parameter_flag::off, "OFF" },
  { Commander::zone_parameter_flag::on,  "ON" },
  { Commander::zone_parameter_flag::count, nullptr }
};

struct Commander::zone_set_state_t Commander::zone_set_states_list[] = {
  { Commander::zone_set_state::open,           "OPEN" },
  { Commander::zone_set_state::closed,         "CLOSED" },
  { Commander::zone_set_state::open_and_close, "OPEN-CLOSE" },
  { Commander::zone_set_state::tamper,         "TAMPER" },
  { Commander::zone_set_state::count, nullptr },
};

struct Commander::zones_action_t Commander::zones_actions_list[] = {
  { Commander::zs_action::ready,   "READY" },
  { Commander::zs_action::alarm,   "ALARM" },
  { Commander::zs_action::open,    "OPEN" },
  { Commander::zs_action::tamper,  "TAMPER" },
  { Commander::zs_action::rstate,  "RSTATE" },
  { Commander::zs_action::omitted, "OMITTED" },
  { Commander::zs_action::count, nullptr }
};

struct Commander::output_action_t Commander::output_actions_list[] = {
  { Commander::output_action::off, "OFF" },
  { Commander::output_action::on,  "ON" },
  { Commander::output_action::count, nullptr }
};

struct Commander::poll_action_t Commander::poll_actions_list[] = {
  { Commander::poll_action::off,      "OFF" },
  { Commander::poll_action::on,       "ON" },
  { Commander::poll_action::add,      "ADD" },
  { Commander::poll_action::remove,   "REMOVE" },
  { Commander::poll_action::one_shot, "ONCE" },
  { Commander::poll_action::count, nullptr }
};

struct Commander::poll_item_t Commander::poll_items_list[] = {
  { Commander::poll_item::nothing,    "NONE",    Poll::possible_items::nothing },
  { Commander::poll_item::areas,      "AREAS",   Poll::possible_items::areas },
  { Commander::poll_item::zones,      "ZONES",   Poll::possible_items::zones },
  { Commander::poll_item::outputs,    "OUTPUTS", Poll::possible_items::outputs },
  { Commander::poll_item::everything, "ALL",     Poll::possible_items::everything },
  { Commander::poll_item::count, nullptr,   Poll::possible_items::nothing }
};

struct Commander::code_alarm_module_t Commander::code_alarm_modules_list[] = {
  { Commander::code_alarm_module::telecom, "TELECOM" },
  { Commander::code_alarm_module::rs232,   "RS232" },
  { Commander::code_alarm_module::monitor, "MONITOR" },
  { Commander::code_alarm_module::all,     "ALL" },
  { Commander::code_alarm_module::count, nullptr }
};

const char Commander::json_standard_reply_fmt[]  = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"success\":%u,\"command\":\"%s\",\"replyText\":\"\"}";
const char Commander::json_command_error_fmt[]   = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"success\":%u,\"command\":\"%s\",\"replyText\":\"%s\"}";
const char Commander::json_command_help_fmt[]    = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"success\":%u,\"command\":\"%s\",\"helpText\":\"%s\"}";
const char Commander::json_command_list_fmt[]    = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"success\":%u,\"command\":\"%s\",\"helpText\":\"";
const char Commander::json_all_area_fmt[]        = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"areaState\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]}";
const char Commander::json_single_area_fmt[]     = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"areaState\":%u}";
const char Commander::json_zone_omit_state_fmt[] = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"zoneNumber\":%u,\"omitState\":%u}";
const char Commander::json_zone_state_fmt[]      = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"zoneNumber\":%u,\"zoneState\":%u}";
const char Commander::json_all_zone_state_fmt[]  = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"zoneState\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]}";
const char Commander::json_output_state_fmt[]    = "{\"typeId\":%u,\"typeDesc\":\"%s\",\"outputState\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]}";

const char Commander::poll_all_area_fmt[]        = "[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]";
const char Commander::poll_all_zone_state_fmt[]  = "[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]";
const char Commander::poll_output_state_fmt[]    = "[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]";

const char Commander::json_authorization_required_fmt[] = "{\"typeId\":%u,\"typeDesc\":\"%llX\",\"replyText\":\"%s\"}"; // hack: typeDesc == session_id && replyText = user full name
const char Commander::json_authentication_accepted_fmt[] = "{\"typeId\":%u,\"typeDesc\":\"%s\"}";

const char* Commander::CommanderTypeDesc[] = {
  "reserved",
  "default",
  "help command",
  "area armed state",
  "areas armed states",
  "area alarm state",
  "areas alarm states",
  "area ready state",
  "areas ready states",
  "zone omitted state",
  "zone state",
  "zones ready state",
  "zones alarm state",
  "zones open state",
  "zones tamper state",
  "zones low/high resistance state",
  "zones omitted state",
  "output states",
  "polling loop",
  "authorization required",
  "authentication accepted"
};

Commander::Commander(openGalaxy& openGalaxy)
 : m_openGalaxy(openGalaxy)
{
  m_thread = new std::thread(Commander::Thread, this);
}

Commander::~Commander()
{
  delete m_thread;
}

void Commander::notify()
{
  m_cv_notified = true;
  m_request_cv.notify_one();
}

// Helper function for the default JSON formatted reply to a command
bool Commander::ReportCommandExec(bool retv, const char* cmd)
{
  snprintf(
    (char*)commander_output_buffer,
    sizeof(commander_output_buffer),
    json_standard_reply_fmt,
    static_cast<unsigned int>(json_reply_id::standard),
    CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
    retv,
    cmd
  );
  return retv;
}

// Determine if the value in string s contains a valid area number (decimal or A1, B1, ... format)
// Returns the area number or -1.
int Commander::isArea(const char *s)
{
  int t = 0;

  switch( s[0] ) {
    case 'A':
      t = strtoul( &s[1], nullptr, 10 );
      break;

    case 'B':
      t = strtoul( &s[1], nullptr, 10 ) + 8;
      break;

    case 'C':
      t = strtoul( &s[1], nullptr, 10 ) + 16;
      break;

    case 'D':
      t = strtoul( &s[1], nullptr, 10 ) + 24;
      break;

    default:
      t = strtoul( s, nullptr, 10 );
      break;
  }
  if( (t<0) || (t>32) ) return -1;
  return t;
}

// Determine if the value in string s contains a zone type number or zone type string.
// If the number is larger than 1000 it is assumed to be a valid zone number
// Returns the type number (0-99) or -1.
int Commander::isZoneType(const char *s)
{
  if(strlen(s)==1 && s[0]=='0') return 0;
  int retv = -1;
  int number;

  for(int t=0; zone_typenames[t].number != 0; t++){
    if(strcmp(zone_typenames[t].string, s) == 0){
      retv = zone_typenames[t].number;
      break;
    }
  }
  if(retv < 0){
    // not found in the list, is the 1st char a digit?
    if(s[0]>='0' && s[0]<='9'){
      number = strtoul(s, nullptr, 10);
      if((number>=0 && number<100) || number > 999) retv = number;
    }
  }
  return retv;
}

// TODO: Split this up into nice little sub-functions (one 'command' per function)
bool Commander::ExecCmd(PendingCommand& cmd)
{
  // \ \t<command>\ \t[arg1]\ \t[argn]\ \t

  unsigned int t, len;
  const char delim[] = " \t";
  char *saveptr, *command, *arg1, *arg2, *arg3, *arg4, *arg5, *argn;
  bool retv = false;

  // Put (some of) these in unions to save a little memory because
  // only one of these variables is used at a time
  union {
    struct area_action_t *area;
    struct zone_action_t *zone;
    struct zones_action_t *zones;
    struct output_action_t *output;
    struct poll_action_t *poll;
    struct code_alarm_module_t *code_alarm;
  } action = { nullptr };
  union {
    Galaxy::area_armed_state armed[32];
    Galaxy::area_alarm_state alarm[32];
    Galaxy::area_ready_state ready[32];
    Galaxy::zone_action omit;
    Galaxy::zone_state zone;
    unsigned char zones[65];
    unsigned char outputs[32];
  } state;
  struct zone_parameter_option_t *zone_parameter_options;
  struct zone_parameter_flag_t *zone_parameter_flags;
  struct zone_set_state_t *zone_set_states;

  // Compose the command string to echo back together with a standard JSON reply
  // (Hopefully, this filters any ASCII characters that will choke the javascript JSON.parse() command)
  const char *_command = cmd.command.c_str();

  // Copy the command to a local buffer so strtok_r() can safely modify it
  char cmdbuf[cmd.command.size()+1];
  strcpy(cmdbuf, cmd.command.data());
  if(cmdbuf == nullptr){
    retv = false;
    goto exit;
  }

  // Get the name of the command to execute and its arguments
  command = strtok_r(cmdbuf, delim, &saveptr);
  if(command == nullptr){
    retv = false;
    goto exit;
  }
  arg1 = strtok_r(nullptr, delim, &saveptr);
  arg2 = strtok_r(nullptr, delim, &saveptr);
  arg3 = strtok_r(nullptr, delim, &saveptr);
  arg4 = strtok_r(nullptr, delim, &saveptr);
  arg5 = strtok_r(nullptr, delim, &saveptr);
  argn = saveptr;
  if(argn && strlen(argn) == 0) argn = nullptr;

  // convert command and arg1 .. arg5 to uppercase 
  if(command) for(t=0; t<strlen(command); t++) command[t] = toupper( command[t] );
  if(arg1) for(t=0; t<strlen(arg1); t++) arg1[t] = toupper( arg1[t] );
  if(arg2) for(t=0; t<strlen(arg2); t++) arg2[t] = toupper( arg2[t] );
  if(arg3) for(t=0; t<strlen(arg3); t++) arg3[t] = toupper( arg3[t] );
  if(arg4) for(t=0; t<strlen(arg4); t++) arg4[t] = toupper( arg4[t] );
  if(arg5) for(t=0; t<strlen(arg5); t++) arg5[t] = toupper( arg5[t] );

  // Locate the index for the command in the list of commands
  for(t=0; commands_list[t].index != Commander::cmd::count; t++){
    if(strcmp(commands_list[t].command, command) == 0) break;
  }

  // Parse the rest of the command
  switch(commands_list[t].index) {

    case Commander::cmd::help: // HELP
      len = snprintf(
        (char*)commander_output_buffer,
        sizeof(commander_output_buffer),
        json_command_list_fmt,
        static_cast<unsigned int>(json_reply_id::help),
        CommanderTypeDesc[static_cast<int>(json_reply_id::help)],
        true,
        _command
      );
      len += snprintf(
        (char*)&commander_output_buffer[len],
        sizeof(commander_output_buffer) - len,
        "For help about commands and some examples read the file API.TXT that comes with openGalaxy."
        "\"}"
      );
      retv = true;
      break;

    case Commander::cmd::area: // AREA <partnum> <action>

      // Check arguments
      if(arg1 == nullptr || arg2 == nullptr){
        len = snprintf(
          (char*)commander_output_buffer,
          sizeof(commander_output_buffer),
          json_command_error_fmt,
          static_cast<unsigned int>(json_reply_id::standard),
          CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
          false,
          _command,
          "requires an (other) argument!"
        );
        retv = false;
        break;
      }

      // Find the index of the action in the list actions for this command
      for(t=0; area_actions_list[t].index != Commander::area_action::count; t++){
        if(strcmp(area_actions_list[t].action, arg2) == 0) break;
      }

      action.area = &area_actions_list[t];
      t = isArea(arg1);

      switch(action.area->index){
        case Commander::area_action::unset:
          retv = ReportCommandExec(opengalaxy().galaxy().AreaAction(t, Galaxy::area_action::unset), _command);
          break;
        case Commander::area_action::set:
          retv = ReportCommandExec(opengalaxy().galaxy().AreaAction(t, Galaxy::area_action::set), _command);
          break;

        case Commander::area_action::partset:
          retv = ReportCommandExec(opengalaxy().galaxy().AreaAction( t, Galaxy::area_action::part_set), _command);
          break;
        case Commander::area_action::reset:
          retv = ReportCommandExec(opengalaxy().galaxy().AreaAction( t, Galaxy::area_action::reset), _command);
          break;
        case Commander::area_action::abortset:
          retv = ReportCommandExec(opengalaxy().galaxy().AreaAction( t, Galaxy::area_action::abort_set), _command);
          break;
        case Commander::area_action::forceset:
          retv = ReportCommandExec(opengalaxy().galaxy().AreaAction( t, Galaxy::area_action::force_set), _command);
          break;
        case Commander::area_action::state:
          if( t == 0 ) {
            retv = opengalaxy().galaxy().GetAllAreasArmedState(state.armed);
            if(retv == true){
              // Command called from the polling thread?
              if(cmd.user != nullptr){
                // Yes, format the output so poll_callback() can use it without having to decode a JSON object
                struct Poll::poll_userdata *user = (struct Poll::poll_userdata*)cmd.user;
                user->item = Poll::possible_items::areas; // signal to poll_callback() that these are area states
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  poll_all_area_fmt,
                  static_cast<unsigned int>(state.armed[0]), static_cast<unsigned int>(state.armed[1]), static_cast<unsigned int>(state.armed[2]), static_cast<unsigned int>(state.armed[3]), static_cast<unsigned int>(state.armed[4]), static_cast<unsigned int>(state.armed[5]),
                  static_cast<unsigned int>(state.armed[6]), static_cast<unsigned int>(state.armed[7]), static_cast<unsigned int>(state.armed[8]), static_cast<unsigned int>(state.armed[9]), static_cast<unsigned int>(state.armed[10]), static_cast<unsigned int>(state.armed[11]),
                  static_cast<unsigned int>(state.armed[12]), static_cast<unsigned int>(state.armed[13]), static_cast<unsigned int>(state.armed[14]), static_cast<unsigned int>(state.armed[15]), static_cast<unsigned int>(state.armed[16]), static_cast<unsigned int>(state.armed[17]),
                  static_cast<unsigned int>(state.armed[18]), static_cast<unsigned int>(state.armed[19]), static_cast<unsigned int>(state.armed[20]), static_cast<unsigned int>(state.armed[21]), static_cast<unsigned int>(state.armed[22]), static_cast<unsigned int>(state.armed[23]),
                  static_cast<unsigned int>(state.armed[24]), static_cast<unsigned int>(state.armed[25]), static_cast<unsigned int>(state.armed[26]), static_cast<unsigned int>(state.armed[27]), static_cast<unsigned int>(state.armed[28]), static_cast<unsigned int>(state.armed[29]),
                  static_cast<unsigned int>(state.armed[30]), static_cast<unsigned int>(state.armed[31])
                );
              }
              else {
                // No, send a JSON object to the client
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  json_all_area_fmt,
                  static_cast<unsigned int>(json_reply_id::all_areas_armed_states),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::all_areas_armed_states)],
                  static_cast<unsigned int>(state.armed[0]), static_cast<unsigned int>(state.armed[1]), static_cast<unsigned int>(state.armed[2]), static_cast<unsigned int>(state.armed[3]), static_cast<unsigned int>(state.armed[4]), static_cast<unsigned int>(state.armed[5]),
                  static_cast<unsigned int>(state.armed[6]), static_cast<unsigned int>(state.armed[7]), static_cast<unsigned int>(state.armed[8]), static_cast<unsigned int>(state.armed[9]), static_cast<unsigned int>(state.armed[10]), static_cast<unsigned int>(state.armed[11]),
                  static_cast<unsigned int>(state.armed[12]), static_cast<unsigned int>(state.armed[13]), static_cast<unsigned int>(state.armed[14]), static_cast<unsigned int>(state.armed[15]), static_cast<unsigned int>(state.armed[16]), static_cast<unsigned int>(state.armed[17]),
                  static_cast<unsigned int>(state.armed[18]), static_cast<unsigned int>(state.armed[19]), static_cast<unsigned int>(state.armed[20]), static_cast<unsigned int>(state.armed[21]), static_cast<unsigned int>(state.armed[22]), static_cast<unsigned int>(state.armed[23]),
                  static_cast<unsigned int>(state.armed[24]), static_cast<unsigned int>(state.armed[25]), static_cast<unsigned int>(state.armed[26]), static_cast<unsigned int>(state.armed[27]), static_cast<unsigned int>(state.armed[28]), static_cast<unsigned int>(state.armed[29]),
                  static_cast<unsigned int>(state.armed[30]), static_cast<unsigned int>(state.armed[31])
                );
              }
            }
            else ReportCommandExec(retv, _command);
          }
          else {
            retv = opengalaxy().galaxy().GetAreaArmedState(t, &state.armed[0]);
            if(retv == true){
              len = snprintf(
                (char*)commander_output_buffer,
                sizeof(commander_output_buffer),
                json_single_area_fmt,
                static_cast<unsigned int>(json_reply_id::area_armed_state),
                CommanderTypeDesc[static_cast<int>(json_reply_id::area_armed_state)],
                static_cast<unsigned int>(state.armed[0])
              );
            }
            else ReportCommandExec(retv, _command);
          }
          break;
        case Commander::area_action::alarm:
          retv = opengalaxy().galaxy().GetAllAreasAlarmState(state.alarm);
          if(retv == true){
            if(t == 0){
              // Command called from the polling thread?
              if(cmd.user != nullptr){
                // Yes, format the output so poll_callback() can use it without having to decode a JSON object
                struct Poll::poll_userdata *user = (struct Poll::poll_userdata*)cmd.user;
                user->item = Poll::possible_items::areas; // signal to poll_callback() that these are area states
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  poll_all_area_fmt,
                  static_cast<unsigned int>(state.alarm[0]), static_cast<unsigned int>(state.alarm[1]), static_cast<unsigned int>(state.alarm[2]), static_cast<unsigned int>(state.alarm[3]), static_cast<unsigned int>(state.alarm[4]), static_cast<unsigned int>(state.alarm[5]),
                  static_cast<unsigned int>(state.alarm[6]), static_cast<unsigned int>(state.alarm[7]), static_cast<unsigned int>(state.alarm[8]), static_cast<unsigned int>(state.alarm[9]), static_cast<unsigned int>(state.alarm[10]), static_cast<unsigned int>(state.alarm[11]),
                  static_cast<unsigned int>(state.alarm[12]), static_cast<unsigned int>(state.alarm[13]), static_cast<unsigned int>(state.alarm[14]), static_cast<unsigned int>(state.alarm[15]), static_cast<unsigned int>(state.alarm[16]), static_cast<unsigned int>(state.alarm[17]),
                  static_cast<unsigned int>(state.alarm[18]), static_cast<unsigned int>(state.alarm[19]), static_cast<unsigned int>(state.alarm[20]), static_cast<unsigned int>(state.alarm[21]), static_cast<unsigned int>(state.alarm[22]), static_cast<unsigned int>(state.alarm[23]),
                  static_cast<unsigned int>(state.alarm[24]), static_cast<unsigned int>(state.alarm[25]), static_cast<unsigned int>(state.alarm[26]), static_cast<unsigned int>(state.alarm[27]), static_cast<unsigned int>(state.alarm[28]), static_cast<unsigned int>(state.alarm[29]),
                  static_cast<unsigned int>(state.alarm[30]), static_cast<unsigned int>(state.alarm[31])
                );
              }
              else {
                // No, send a JSON object to the client
                len = snprintf(
                  (char*)&commander_output_buffer[0],
                  sizeof(commander_output_buffer),
                  json_all_area_fmt,
                  static_cast<unsigned int>(json_reply_id::all_areas_alarm_states),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::all_areas_alarm_states)],
                  static_cast<unsigned int>(state.alarm[0]), static_cast<unsigned int>(state.alarm[1]), static_cast<unsigned int>(state.alarm[2]), static_cast<unsigned int>(state.alarm[3]), static_cast<unsigned int>(state.alarm[4]), static_cast<unsigned int>(state.alarm[5]),
                  static_cast<unsigned int>(state.alarm[6]), static_cast<unsigned int>(state.alarm[7]), static_cast<unsigned int>(state.alarm[8]), static_cast<unsigned int>(state.alarm[9]), static_cast<unsigned int>(state.alarm[10]), static_cast<unsigned int>(state.alarm[11]),
                  static_cast<unsigned int>(state.alarm[12]), static_cast<unsigned int>(state.alarm[13]), static_cast<unsigned int>(state.alarm[14]), static_cast<unsigned int>(state.alarm[15]), static_cast<unsigned int>(state.alarm[16]), static_cast<unsigned int>(state.alarm[17]),
                  static_cast<unsigned int>(state.alarm[18]), static_cast<unsigned int>(state.alarm[19]), static_cast<unsigned int>(state.alarm[20]), static_cast<unsigned int>(state.alarm[21]), static_cast<unsigned int>(state.alarm[22]), static_cast<unsigned int>(state.alarm[23]),
                  static_cast<unsigned int>(state.alarm[24]), static_cast<unsigned int>(state.alarm[25]), static_cast<unsigned int>(state.alarm[26]), static_cast<unsigned int>(state.alarm[27]), static_cast<unsigned int>(state.alarm[28]), static_cast<unsigned int>(state.alarm[29]),
                  static_cast<unsigned int>(state.alarm[30]), static_cast<unsigned int>(state.alarm[31])
                );
              }
            }
            else {
              if(t > 32) retv = false;
              else len = snprintf(
                (char*)commander_output_buffer,
                sizeof(commander_output_buffer),
                json_single_area_fmt,
                static_cast<unsigned int>(json_reply_id::area_alarm_state),
                CommanderTypeDesc[static_cast<int>(json_reply_id::area_alarm_state)],
                static_cast<unsigned int>(state.alarm[t-1])
              );
            }
          }
          else ReportCommandExec(retv, _command);
          break;
        case Commander::area_action::ready:
          retv = opengalaxy().galaxy().GetAllAreasReadyState(state.ready);
          if(retv == true){
            if(t == 0){
              // Command called from the polling thread?
              if(cmd.user != nullptr){
                // Yes, format the output so poll_callback() can use it without having to decode a JSON object
                struct Poll::poll_userdata *user = (struct Poll::poll_userdata*)cmd.user;
                user->item = Poll::possible_items::areas; // signal to poll_callback() that these are area states
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  poll_all_area_fmt,
                  static_cast<unsigned int>(state.ready[0]), static_cast<unsigned int>(state.ready[1]), static_cast<unsigned int>(state.ready[2]), static_cast<unsigned int>(state.ready[3]), static_cast<unsigned int>(state.ready[4]), static_cast<unsigned int>(state.ready[5]),
                  static_cast<unsigned int>(state.ready[6]), static_cast<unsigned int>(state.ready[7]), static_cast<unsigned int>(state.ready[8]), static_cast<unsigned int>(state.ready[9]), static_cast<unsigned int>(state.ready[10]), static_cast<unsigned int>(state.ready[11]),
                  static_cast<unsigned int>(state.ready[12]), static_cast<unsigned int>(state.ready[13]), static_cast<unsigned int>(state.ready[14]), static_cast<unsigned int>(state.ready[15]), static_cast<unsigned int>(state.ready[16]), static_cast<unsigned int>(state.ready[17]),
                  static_cast<unsigned int>(state.ready[18]), static_cast<unsigned int>(state.ready[19]), static_cast<unsigned int>(state.ready[20]), static_cast<unsigned int>(state.ready[21]), static_cast<unsigned int>(state.ready[22]), static_cast<unsigned int>(state.ready[23]),
                  static_cast<unsigned int>(state.ready[24]), static_cast<unsigned int>(state.ready[25]), static_cast<unsigned int>(state.ready[26]), static_cast<unsigned int>(state.ready[27]), static_cast<unsigned int>(state.ready[28]), static_cast<unsigned int>(state.ready[29]),
                  static_cast<unsigned int>(state.ready[30]), static_cast<unsigned int>(state.ready[31])
                );
              }
              else {
                // No, send a JSON object to the client
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  json_all_area_fmt,
                  static_cast<unsigned int>(json_reply_id::all_areas_ready_states),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::all_areas_ready_states)],
                  static_cast<unsigned int>(state.ready[0]), static_cast<unsigned int>(state.ready[1]), static_cast<unsigned int>(state.ready[2]), static_cast<unsigned int>(state.ready[3]), static_cast<unsigned int>(state.ready[4]), static_cast<unsigned int>(state.ready[5]),
                  static_cast<unsigned int>(state.ready[6]), static_cast<unsigned int>(state.ready[7]), static_cast<unsigned int>(state.ready[8]), static_cast<unsigned int>(state.ready[9]), static_cast<unsigned int>(state.ready[10]), static_cast<unsigned int>(state.ready[11]),
                  static_cast<unsigned int>(state.ready[12]), static_cast<unsigned int>(state.ready[13]), static_cast<unsigned int>(state.ready[14]), static_cast<unsigned int>(state.ready[15]), static_cast<unsigned int>(state.ready[16]), static_cast<unsigned int>(state.ready[17]),
                  static_cast<unsigned int>(state.ready[18]), static_cast<unsigned int>(state.ready[19]), static_cast<unsigned int>(state.ready[20]), static_cast<unsigned int>(state.ready[21]), static_cast<unsigned int>(state.ready[22]), static_cast<unsigned int>(state.ready[23]),
                  static_cast<unsigned int>(state.ready[24]), static_cast<unsigned int>(state.ready[25]), static_cast<unsigned int>(state.ready[26]), static_cast<unsigned int>(state.ready[27]), static_cast<unsigned int>(state.ready[28]), static_cast<unsigned int>(state.ready[29]),
                  static_cast<unsigned int>(state.ready[30]), static_cast<unsigned int>(state.ready[31])
                );
              }
            }
            else {
              if(t > 32) retv = false;
              else len = snprintf(
                (char*)commander_output_buffer,
                sizeof(commander_output_buffer),
                json_single_area_fmt,
                static_cast<unsigned int>(json_reply_id::area_ready_state),
                CommanderTypeDesc[static_cast<int>(json_reply_id::area_ready_state)],
                static_cast<unsigned int>(state.ready[t-1])
              );
            }
          }
          else ReportCommandExec(retv, _command);
          break;
        default:
          len = snprintf(
            (char*)commander_output_buffer,
            sizeof(commander_output_buffer),
            json_command_error_fmt,
            static_cast<unsigned int>(json_reply_id::standard),
            CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
            false,
            _command,
            "No such area action!"
          );
          retv = false;
          break;
      }

      break;

    case Commander::cmd::zone: // ZONE <nr> <action>

      // Check arguments
      if(arg1 == nullptr || arg2 == nullptr){
        len = snprintf(
          (char*)commander_output_buffer,
          sizeof(commander_output_buffer),
          json_command_error_fmt,
          static_cast<unsigned int>(json_reply_id::standard),
          CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
          false,
          _command,
          "requires an (other) argument!"
        );
        retv = false;
        break;
      }

      // Find the index of the action in the list actions for this command
      for(t=0; zone_actions_list[t].index != Commander::zone_action::count; t++ ) {
        if(strcmp(zone_actions_list[t].action, arg2) == 0) break;
      }

      action.zone = &zone_actions_list[t];
      t = isZoneType(arg1); // translate arg1 into zone number or zone type number

      switch(action.zone->index){
        case Commander::zone_action::unomit:
          retv = ReportCommandExec( opengalaxy().galaxy().ZoneAction(t, Galaxy::zone_action::unomit), _command);
          break;
        case Commander::zone_action::omit:
          retv = ReportCommandExec( opengalaxy().galaxy().ZoneAction(t, Galaxy::zone_action::omit), _command);
          break;
        case Commander::zone_action::isomit:
          retv = opengalaxy().galaxy().ZoneIsOmit(t, &state.omit);
          if(retv == true) {
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_zone_omit_state_fmt,
              static_cast<unsigned int>(json_reply_id::zone_omitted_state),
              CommanderTypeDesc[static_cast<int>(json_reply_id::zone_omitted_state)],
              t,
              static_cast<unsigned int>(state.omit)
            );
          }
          else ReportCommandExec(retv, _command);
          break;
        case Commander::zone_action::zone_state:
          retv = opengalaxy().galaxy().GetZoneState(t, &state.zone);
          if(retv == true){
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_zone_state_fmt,
              static_cast<unsigned int>(json_reply_id::single_zone_state),
              CommanderTypeDesc[static_cast<int>(json_reply_id::single_zone_state)],
              t,
              static_cast<unsigned int>(state.zone)
            );
          }
          else ReportCommandExec(retv, _command);
          break;
        case Commander::zone_action::parameter: // ZONE <nr> PARAMETER <option> <flag>
          {
            int i, j;
            Galaxy::zone_program prg;
            //
            // Find the index of the zone parameter option in the list options for this command
            for(i=0; zone_parameter_options_list[i].index != Commander::zone_parameter_option::count; i++ ) {
              if(strcmp(zone_parameter_options_list[i].action, arg3) == 0) break;
            }
            zone_parameter_options = &zone_parameter_options_list[i];
            //
            // Find the index of the zone parameter flag in the list of flags for the zone parameter command
            for(j=0; zone_parameter_flags_list[j].index != Commander::zone_parameter_flag::count; j++ ) {
              if(strcmp(zone_parameter_flags_list[j].action, arg4) == 0) break;
            }
            zone_parameter_flags = &zone_parameter_flags_list[j];
            //
            switch( zone_parameter_flags->index ){
              case Commander::zone_parameter_flag::on:
                j = 1;
                break;
              case Commander::zone_parameter_flag::off:
                j = 0;
                break;
              default:
                j = -1;
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  json_command_error_fmt,
                  static_cast<unsigned int>(json_reply_id::standard),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
                  false,
                  _command,
                  "invalid ZONE PARAMETER flag!"
                );
                retv = false;
                break;
            }
            if(j<0) break;
            //
            switch( zone_parameter_options->index ){
              case Commander::zone_parameter_option::soak_test:
                if(j!=0){
                  prg = Galaxy::zone_program::soak_test_on;
                }
                else {
                  prg = Galaxy::zone_program::soak_test_off;
                }
                break;
              case Commander::zone_parameter_option::part_set:
                if(j!=0){
                  prg = Galaxy::zone_program::part_set_on;
                }
                else {
                  prg = Galaxy::zone_program::part_set_off;
                }
                break;
              default:
                prg = (Galaxy::zone_program) -1;
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  json_command_error_fmt,
                  static_cast<unsigned int>(json_reply_id::standard),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
                  false,
                  _command,
                  "invalid ZONE PARAMETER option!"
                );
                retv = false;
                break;
            }
            if(prg < (Galaxy::zone_program)0) break;
            //
            // (Re-)Set the requested parameter for zone t
            retv = ReportCommandExec(opengalaxy().galaxy().SetZoneState(t, prg), _command);
          }
          break;
        case Commander::zone_action::set: // ZONE <nr> SET <state> [<blknum> <type> [desc]]
          {
            int i, blknum = 0, type = 0;
            char *desc = argn;
            Galaxy::zone_program prg;
            //
            // Find the index of the zone set state in the list of zone set states
            for(i=0; zone_set_states_list[i].index != Commander::zone_set_state::count; i++ ) {
              if(strcmp(zone_set_states_list[i].action, arg3) == 0) break;
            }
            zone_set_states = &zone_set_states_list[i];

            if(arg4 != nullptr){
              blknum = isArea(arg4);
              if(blknum < 0){
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  json_command_error_fmt,
                  static_cast<unsigned int>(json_reply_id::standard),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
                  false,
                  _command,
                  "argument 4 must be a valid area!"
                );
                retv = false;
                break;
              }
              if(arg5 != nullptr) type = isZoneType(arg5); // translate arg5 into zone number or zone type number
              if((type <= 0 || type >= 100) || (type != 0 && blknum == 0)){
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  json_command_error_fmt,
                  static_cast<unsigned int>(json_reply_id::standard),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
                  false,
                  _command,
                  "invalid argument!"
                );
                retv = false;
                break;
              }
            }

            switch( zone_set_states->index ){
              case Commander::zone_set_state::open:
                prg = Galaxy::zone_program::force_open;
                break;
              case Commander::zone_set_state::closed:
                prg = Galaxy::zone_program::force_closed;
                break;
              case Commander::zone_set_state::open_and_close:
                prg = Galaxy::zone_program::force_open_and_close;
                break;
              case Commander::zone_set_state::tamper:
                prg = Galaxy::zone_program::force_tamper;
                break;
              default:
                len = snprintf(
                  (char*)commander_output_buffer,
                  sizeof(commander_output_buffer),
                  json_command_error_fmt,
                  static_cast<unsigned int>(json_reply_id::standard),
                  CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
                  false,
                  _command,
                  "invalid ZONE SET state!"
                );
                retv = false;
                prg = (Galaxy::zone_program) -1;
                break;
            }
            if(prg < (Galaxy::zone_program)0) break;
            // Set the requested state for zone t
            retv = ReportCommandExec(opengalaxy().galaxy().SetZoneState(t, prg, blknum, type, desc), _command);
          }
          break;

        default:
          len = snprintf(
            (char*)&commander_output_buffer[0],
            sizeof(commander_output_buffer),
            json_command_error_fmt,
            static_cast<unsigned int>(json_reply_id::standard),
            CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
            false,
            _command,
            "No such zone action!"
          );
          retv = false;
          break;
      }

      retv = false;
      break;

    case Commander::cmd::zones:  // ZONES <action>
      {
        // Check arguments
        if(arg1 == nullptr){
          len = snprintf(
            (char*)commander_output_buffer,
            sizeof(commander_output_buffer),
            json_command_error_fmt,
            static_cast<unsigned int>(json_reply_id::standard),
            CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
            false,
            _command,
            "requires an (other) argument!"
          );
          retv = false;
          break;
        }

        // Find the index of the action in the list actions for this command
        for(t=0; zones_actions_list[t].index != Commander::zs_action::count; t++) {
          if(strcmp(zones_actions_list[t].action, arg1) == 0) break;
        }

        action.zones = &zones_actions_list[t];

        Poll::possible_items item;

        // Get the requested states
        switch( action.zones->index ) {
          case Commander::zs_action::ready:
            item = Poll::possible_items::zones;
            retv = opengalaxy().galaxy().GetAllZonesReadyState(state.zones);
            break;
          case Commander::zs_action::alarm:
            item = Poll::possible_items::zones;
            retv = opengalaxy().galaxy().GetAllZonesAlarmState(state.zones);
            break;
          case Commander::zs_action::open:
            item = Poll::possible_items::zones;
            retv = opengalaxy().galaxy().GetAllZonesOpenState(state.zones);
            break;
          case Commander::zs_action::tamper:
            item = Poll::possible_items::zones;
            retv = opengalaxy().galaxy().GetAllZonesTamperState(state.zones);
            break;
          case Commander::zs_action::rstate:
            item = Poll::possible_items::zones;
            retv = opengalaxy().galaxy().GetAllZonesRState(state.zones);
            break;
          case Commander::zs_action::omitted:
            item = Poll::possible_items::zones;
            retv = opengalaxy().galaxy().GetAllZonesOmittedState(state.zones);
            break;
          default:
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_command_error_fmt,
              static_cast<unsigned int>(json_reply_id::standard),
              CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
              false,
              _command,
              "No such zones action!"
            );
            retv = false;
            break;
        }
        // Print them if successfull
        if(retv == true){
          // Command called from the polling thread?
          if(cmd.user != nullptr){
            // Yes, format the output so poll_callback() can use it without having to decode a JSON object
            struct Poll::poll_userdata *user = (struct Poll::poll_userdata*)cmd.user;
            user->item = item; // signal to poll_callback() that these are zone states
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              poll_all_zone_state_fmt,
              state.zones[0],  state.zones[1],  state.zones[2],  state.zones[3],  state.zones[4],  state.zones[5],  state.zones[6],  state.zones[7],
              state.zones[8],  state.zones[9],  state.zones[10], state.zones[11], state.zones[12], state.zones[13], state.zones[14], state.zones[15],
              state.zones[16], state.zones[17], state.zones[18], state.zones[19], state.zones[20], state.zones[21], state.zones[22], state.zones[23],
              state.zones[24], state.zones[25], state.zones[26], state.zones[27], state.zones[28], state.zones[29], state.zones[30], state.zones[31],
              state.zones[32], state.zones[33], state.zones[34], state.zones[35], state.zones[36], state.zones[37], state.zones[38], state.zones[39],
              state.zones[40], state.zones[41], state.zones[42], state.zones[43], state.zones[44], state.zones[45], state.zones[46], state.zones[47],
              state.zones[48], state.zones[49], state.zones[50], state.zones[51], state.zones[52], state.zones[53], state.zones[54], state.zones[55],
              state.zones[56], state.zones[57], state.zones[58], state.zones[59], state.zones[60], state.zones[61], state.zones[62], state.zones[63],
              state.zones[64]
            );
          }
          else {
            // No, send a JSON object to the client
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_all_zone_state_fmt,
              static_cast<int>(json_reply_id::all_zones_state_base) + static_cast<int>(action.zones->index),
              CommanderTypeDesc[static_cast<int>(json_reply_id::all_zones_state_base) + static_cast<int>(action.zones->index)],
              state.zones[0],  state.zones[1],  state.zones[2],  state.zones[3],  state.zones[4],  state.zones[5],  state.zones[6],  state.zones[7],
              state.zones[8],  state.zones[9],  state.zones[10], state.zones[11], state.zones[12], state.zones[13], state.zones[14], state.zones[15],
              state.zones[16], state.zones[17], state.zones[18], state.zones[19], state.zones[20], state.zones[21], state.zones[22], state.zones[23],
              state.zones[24], state.zones[25], state.zones[26], state.zones[27], state.zones[28], state.zones[29], state.zones[30], state.zones[31],
              state.zones[32], state.zones[33], state.zones[34], state.zones[35], state.zones[36], state.zones[37], state.zones[38], state.zones[39],
              state.zones[40], state.zones[41], state.zones[42], state.zones[43], state.zones[44], state.zones[45], state.zones[46], state.zones[47],
              state.zones[48], state.zones[49], state.zones[50], state.zones[51], state.zones[52], state.zones[53], state.zones[54], state.zones[55],
              state.zones[56], state.zones[57], state.zones[58], state.zones[59], state.zones[60], state.zones[61], state.zones[62], state.zones[63],
              state.zones[64]
            );
          }
        }
        else ReportCommandExec(retv, _command);
      }
      break;

    case Commander::cmd::output: // OUTPUT <nr> <action> [blknum]
      {
        if(arg1 != nullptr) if(strcmp(arg1, "GETALL") == 0){ // get output state
          retv = opengalaxy().galaxy().GetAllOutputs(state.outputs);
          if(retv == true){
            // Command called from the polling thread?
            if(cmd.user != nullptr){
              // Yes, format the output so poll_callback() can use it without having to decode a JSON object
              struct Poll::poll_userdata *user = (struct Poll::poll_userdata*)cmd.user;
              user->item = Poll::possible_items::outputs; // signal to poll_callback() that these are output states
              len = snprintf(
                (char*)commander_output_buffer,
                sizeof(commander_output_buffer),
                poll_output_state_fmt,
                state.outputs[0],  state.outputs[1],  state.outputs[2],  state.outputs[3],  state.outputs[4],  state.outputs[5],  state.outputs[6],  state.outputs[7],
                state.outputs[8],  state.outputs[9],  state.outputs[10], state.outputs[11], state.outputs[12], state.outputs[13], state.outputs[14], state.outputs[15],
                state.outputs[16], state.outputs[17], state.outputs[18], state.outputs[19], state.outputs[20], state.outputs[21], state.outputs[22], state.outputs[23],
                state.outputs[24], state.outputs[25], state.outputs[26], state.outputs[27], state.outputs[28], state.outputs[29], state.outputs[30], state.outputs[31]
              );
            }
            else {
              // No, send a JSON object to the client
              len = snprintf(
                (char*)commander_output_buffer,
                sizeof(commander_output_buffer),
                json_output_state_fmt,
                static_cast<unsigned int>(json_reply_id::all_output_states),
                CommanderTypeDesc[static_cast<int>(json_reply_id::all_output_states)],
                state.outputs[0],  state.outputs[1],  state.outputs[2],  state.outputs[3],  state.outputs[4],  state.outputs[5],  state.outputs[6],  state.outputs[7],
                state.outputs[8],  state.outputs[9],  state.outputs[10], state.outputs[11], state.outputs[12], state.outputs[13], state.outputs[14], state.outputs[15],
                state.outputs[16], state.outputs[17], state.outputs[18], state.outputs[19], state.outputs[20], state.outputs[21], state.outputs[22], state.outputs[23],
                state.outputs[24], state.outputs[25], state.outputs[26], state.outputs[27], state.outputs[28], state.outputs[29], state.outputs[30], state.outputs[31]
              );
            }
          }
          else ReportCommandExec(retv, _command);
          break;
        }

        // Check arguments
        if(arg1 == nullptr || arg2 == nullptr){
          len = snprintf(
            (char*)commander_output_buffer,
            sizeof(commander_output_buffer),
            json_command_error_fmt,
            static_cast<unsigned int>(json_reply_id::standard),
            CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
            false,
            _command,
            "requires an (other) argument!"
          );
          retv = false;
          break;
        }

        // Assume all areas if not specified
        if(arg3 == nullptr) arg3 = (char*)"0";

        // Find the index of the action in the list actions for this command
        for(t=0; output_actions_list[t].index != Commander::output_action::count; t++){
          if(strcmp(output_actions_list[t].action, arg2) == 0) break;
        }

        action.output = &output_actions_list[t];
        t = strtoul(arg1, nullptr, 10);

        int a = isArea(arg3);
        if((a < 0) || (a > 32)){
          len = snprintf(
            (char*)&commander_output_buffer[0],
            sizeof(commander_output_buffer),
            json_command_error_fmt,
            static_cast<unsigned int>(json_reply_id::standard),
            CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
            false,
            _command,
            "No such area!"
          );
          retv = false;
          break;
        }

        switch(action.output->index){
          case Commander::output_action::on:
            retv = ReportCommandExec(opengalaxy().galaxy().OutputAction(t, true, a), _command);
            break;
          case Commander::output_action::off:
            retv = ReportCommandExec(opengalaxy().galaxy().OutputAction(t, false, a), _command);
            break;
          default:
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_command_error_fmt,
              static_cast<unsigned int>(json_reply_id::standard),
              CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
              false,
              _command,
              "No such output action!"
            );
            retv = false;
            break;
        }

        retv = false;
      }
      break;

    case Commander::cmd::poll: // POLL <action> [interval]|<item>
      {
        struct poll_item_t *item;
        int interval = 0;
        class Poll::_ws_info socket(opengalaxy().m_options);

        // Check first argument (action)
        if(arg1 == nullptr){
          len = snprintf(
            (char*)commander_output_buffer,
            sizeof(commander_output_buffer),
            json_command_error_fmt,
            static_cast<unsigned int>(json_reply_id::standard),
            CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
            false,
            _command,
            "requires an (other) argument!"
          );
          retv = false;
          break;
        }

        // Find the index of the action in the list actions for this command
        for(t=0; poll_actions_list[t].index != Commander::poll_action::count; t++){
          if(strcmp(poll_actions_list[t].action, arg1) == 0) break;
        }
        action.poll = &poll_actions_list[t];

        // Do we explicitly need another argument?
        if( action.poll->index == Commander::poll_action::add || action.poll->index == Commander::poll_action::remove ){
          // Yes
          if(arg2 == nullptr){
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_command_error_fmt,
              static_cast<unsigned int>(json_reply_id::standard),
              CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
              false,
              _command,
              "requires an (other) argument!"
            );
            retv = false;
            break;
          }
        }
        else {
          // Maybe, so set it to an empty string if arg2 is nullptr
          if(arg2 == nullptr) arg2 = (char*)"";
        }

        // Find the index of the item in the list items for this command
        for(t=0; poll_items_list[t].index != Commander::poll_item::count; t++){
          if(strcmp(poll_items_list[t].item, arg2) == 0) break;
        }
        item = &poll_items_list[t];
        if(item->index == Commander::poll_item::count){
          // if it was not an item, get the interval for the command
          interval = strtoul(arg2, nullptr, 10);
        }

        // Prepare the websocket information needed by the poll functions

        // This is a 'special' case, do not use the copy operator (=) to copy
        // the session id.
        // cmd does not have a valid reference to the websocket in
        // the session id because it does not belong to any particular session.
        // So copy just the puplic members of the session id and keep the
        // m_websocket from the _ws_info we instantiated here...
        socket.session.id = cmd.session.id;
        strcpy(socket.session.sha256str, cmd.session.sha256str);
        socket.session.websocket_wsi = cmd.session.websocket_wsi;

        socket.user = (Poll::poll_userdata*)cmd.user;
        socket.callback = cmd.callback;

        switch(action.poll->index){
          case Commander::poll_action::off:
            retv = ReportCommandExec(opengalaxy().poll().disable(cmd.session), _command);
            break;
          case Commander::poll_action::on:
            if(interval == 0){
              retv = ReportCommandExec(false, _command);
            }
            else {
              opengalaxy().poll().setInterval(&socket, interval);
              retv = ReportCommandExec(opengalaxy().poll().enable(&socket), _command);
            }
            break;
          case Commander::poll_action::add:
            retv = ReportCommandExec(opengalaxy().poll().setItems(&socket, (Poll::possible_items)item->id), _command);
            break;
          case Commander::poll_action::remove:
            retv = ReportCommandExec(opengalaxy().poll().clearItems(&socket, (Poll::possible_items)item->id), _command);
            break;
          case Commander::poll_action::one_shot:
            retv = ReportCommandExec(opengalaxy().poll().oneShot(&socket), _command);
            break;
          default:
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_command_error_fmt,
              static_cast<unsigned int>(json_reply_id::standard),
              CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
              false,
              _command,
              "No such poll action!"
            );
            retv = false;
            break;
        }
        break;
      }

    case Commander::cmd::code_alarm: // CODE-ALARM <module>
      {
        // Check first argument (module)
        if(arg1 == nullptr){
          len = snprintf(
            (char*)commander_output_buffer,
            sizeof(commander_output_buffer),
            json_command_error_fmt,
            static_cast<unsigned int>(json_reply_id::standard),
            CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
            false,
            _command,
            "requires an (other) argument!"
          );
          retv = false;
          break;
        }
        // Find the index of the module in the list modules for this command
        for(t=0; code_alarm_modules_list[t].index != Commander::code_alarm_module::count; t++){
          if(strcmp(code_alarm_modules_list[t].module, arg1) == 0) break;
        }
        action.code_alarm = &code_alarm_modules_list[t];
        // Generate the alarm
        switch( action.code_alarm->index ){
          case code_alarm_module::telecom:
            retv = ReportCommandExec(opengalaxy().galaxy().GenerateWrongCodeAlarm(Galaxy::sia_module::telecom), _command);
            break;
          case code_alarm_module::rs232:
            retv = ReportCommandExec(opengalaxy().galaxy().GenerateWrongCodeAlarm(Galaxy::sia_module::rs232), _command);
            break;
          case code_alarm_module::monitor:
            retv = ReportCommandExec(opengalaxy().galaxy().GenerateWrongCodeAlarm(Galaxy::sia_module::monitor), _command);
            break;
          case code_alarm_module::all:
            retv = ReportCommandExec(opengalaxy().galaxy().GenerateWrongCodeAlarm(Galaxy::sia_module::all), _command);
            break;
          default:
            len = snprintf(
              (char*)commander_output_buffer,
              sizeof(commander_output_buffer),
              json_command_error_fmt,
              static_cast<unsigned int>(json_reply_id::standard),
              CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
              false,
              _command,
              "No such comm. module!"
            );
            retv = false;
            break;
        }
      }
      break;

    default:
      len = snprintf(
        (char*)commander_output_buffer,
        sizeof(commander_output_buffer),
        json_command_error_fmt,
        static_cast<unsigned int>(json_reply_id::standard),
        CommanderTypeDesc[static_cast<int>(json_reply_id::standard)],
        false,
        _command,
        "No such command!"
      );
      retv = false;
      break;

  } // ends switch(commands_list[t].index)

exit:
  // When user is not a nullptr we know the
  // command originated from the polling thread.
  // If so, put the return value in the userdata so the polling thread can
  // easely detect it without having to decode the JSON message.
  if(cmd.user != nullptr){
    struct Poll::poll_userdata *user = (struct Poll::poll_userdata*)cmd.user;
    user->retv = retv;
  }
  return retv;
}

void Commander::execute(class openGalaxy *opengalaxy, session_id *session, void *user, const char *command, callback_ptr callback)
{
  PendingCommand *c = new PendingCommand(opengalaxy->m_options);
  c->opengalaxy = opengalaxy;
  c->command.assign(command);
  if(session) c->session = *session;
  c->user = user;
  c->callback = callback;

  m_mutex.lock();
  pending_commands.append(c);
  m_mutex.unlock();
  notify();
}

// return true when command_list is not empty (ie. we are sending commands)
//
bool Commander::isBusy()
{
  m_mutex.lock();
  bool retv = (pending_commands.size() > 0) ? true : false;
  m_mutex.unlock();
  return retv;
}

void Commander::Thread(Commander* commander)
{
  using namespace std::chrono;
  try {
    int loop_delay = 1;
    std::unique_lock<std::mutex> lck(commander->m_request_mutex);

    // The outer loop only exits if the openGalaxy object is being destroyed.
    // The inner loop iterates once every 'loop_delay' seconds, 
    // or sooner when Commander::NotifyWorkerThread() is called.

    // Outer loop: test if it is time to exit
    while(commander->opengalaxy().isQuit()==false){
      // Inner loop: test if we were notified (or otherwise sleep untill we timeout) and do a loop iteration if we were/did
      while(commander->m_cv_notified || commander->m_request_cv.wait_for(lck,seconds(loop_delay))==std::cv_status::timeout){
        // reset our notification variable
        commander->m_cv_notified = false;
        // Test if we need to exit the thread.
        if(commander->opengalaxy().isQuit()==true) break;

        // while there are pending commands
        // (safe to access without locking since the value can
        // only increase outside of this thread)
        while(commander->pending_commands.size()>0 && !commander->opengalaxy().isQuit()){
          // 'pop' the next command from the list,
          commander->m_mutex.lock();
          PendingCommand *c = new PendingCommand(*commander->pending_commands[0]);
          commander->pending_commands.remove(0);
          commander->m_mutex.unlock();
          // and execute it.
          commander->ExecCmd(*c);
          // Send any output back using the callback function
          if(strlen((char*)commander->commander_output_buffer)){
            c->callback(*c->opengalaxy, &c->session, c->user, (char*)commander->commander_output_buffer);
          }
          // delete the original command data
          // this includes the reference to the auth of the now possibly disconnected client
          // (that would make its wsi an invalid pointer)
          delete c;
          std::this_thread::yield();
        }

      } // ends inner loop
    } // ends outer loop
    commander->opengalaxy().syslog().debug("Commander::Thread exited normally");
  }
  catch(...){
    // pass the exception on to the main() thread
    commander->opengalaxy().m_Commander_exptr = std::current_exception();
    commander->opengalaxy().exit();
  }
}

} // ends namespace openGalaxy

