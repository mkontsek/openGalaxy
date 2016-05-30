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
#ifndef __OPENGALAXY_COMMANDER_HPP__
#define __OPENGALAXY_COMMANDER_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <condition_variable>

#include "Array.hpp"
#include "opengalaxy.hpp"

namespace openGalaxy {

class Commander {

public:
  typedef void(*callback_ptr)(class openGalaxy&, session_id*, void*, char*);

private:

  class PendingCommand {
  public:
    class openGalaxy* opengalaxy;
    std::string command;           // the command to send
    session_id session;            // the session that executes the command
    void *user;                    // poll data
    callback_ptr callback;         // function to call in response to any reply to the command
    PendingCommand(class context_options& options) : session(options) {}
  };

  // Array of pending commands
  ObjectArray<PendingCommand*> pending_commands;

  // Enum to refer to a command through an index value
  enum class cmd : unsigned int {
   help = 0,
   area,
   zone,
   zones,
   output,
   poll,
   code_alarm,
   count // last one, to count the number of indexes
  };

  // List of available commands
  struct command_t {
    enum cmd index;             // Index in the array
    const char *command;        // The command
  };
  static struct command_t commands_list[];

  // Translation list from zone 'type name' to zone 'type number'
  struct zone_typename_t {
    int number;
    const char *string;
  };
  static struct zone_typename_t zone_typenames[];

  // Enum to refer to an area action through an index value
  enum class area_action : unsigned int {
    unset = 0,
    set,
    partset,
    reset,
    abortset,
    forceset,
    state,
    alarm,
    ready,
    count
  };

  // Enum to refer to a zone action through an index value
  enum class zone_action : unsigned int {
    unomit = 0,
    omit,
    isomit,
    zone_state,
    parameter,
    set,
    count
  };

  // Enum to refer to a zone parameter option through an index value
  enum class zone_parameter_option : unsigned int {
    soak_test = 0,
    part_set,
    count
  };

  // Enum to refer to a zone parameter flag through an index value
  enum class zone_parameter_flag : unsigned int {
    on = 0,
    off,
    count
  };

  // Enum to refer to a zone set state command through an index value
  enum class zone_set_state : unsigned int {
    open = 0,
    closed,
    open_and_close,
    tamper,
    count
  };

  // Enum to refer to a zones state action through an index value
  enum class zs_action : unsigned int {
    ready = 0,
    alarm,
    open,
    tamper,
    rstate,
    omitted,
    count
  };

  // Enum to refer to an output action through an index value
  enum class output_action : unsigned int {
    off = 0,
    on,
    count
  };

  // Enum to refer to a poll action through an index value
  enum class poll_action : unsigned int {
    off = 0,
    on,
    add,
    remove,
    one_shot,
    count
  };

  // Enum to refer to a poll item through an index value
  enum class poll_item : unsigned int {
    nothing = 0,
    areas,
    zones,
    outputs,
    everything,
    count
  };

  enum class code_alarm_module : unsigned int {
    telecom = 0,
    rs232,
    monitor,
    all,
    count
  };

  // List of actions for the AREA command
  struct area_action_t {
    area_action index;
    const char *action;
  };
  static struct area_action_t area_actions_list[];

  // List of actions for the ZONE command
  struct zone_action_t {
    zone_action index;
    const char *action;
  };
  static struct zone_action_t zone_actions_list[];

  // List of options for the ZONE PARAMETER command
  struct zone_parameter_option_t {
    zone_parameter_option index;
    const char *action;
  };
  static struct zone_parameter_option_t zone_parameter_options_list[];

  // List of flags for the ZONE PARAMETER command
  struct zone_parameter_flag_t {
    zone_parameter_flag index;
    const char *action;
  };
  static struct zone_parameter_flag_t zone_parameter_flags_list[];

  // List of states for the ZONE SET command
  struct zone_set_state_t {
    zone_set_state index;
    const char *action;
  };
  static struct zone_set_state_t zone_set_states_list[];

  // List of actions for the ZONES command
  struct zones_action_t {
    zs_action index;
    const char *action;
  };
  static struct zones_action_t zones_actions_list[];

  // List of actions for the OUTPUT command
  struct output_action_t {
    output_action index;
    const char *action;
  };
  static struct output_action_t output_actions_list[];

  // List of actions for the POLL command
  struct poll_action_t {
    poll_action index;
    const char *action;
  };
  static struct poll_action_t poll_actions_list[];

  // List of items for the POLL command
  struct poll_item_t {
    poll_item index;
    const char *item;
    int id;
  };
  static struct poll_item_t poll_items_list[];

  struct code_alarm_module_t {
    code_alarm_module index;
    const char *module;
  };
  static struct code_alarm_module_t code_alarm_modules_list[];

  openGalaxy& m_openGalaxy;
  std::thread *m_thread;             // the worker thread for this receiver instance
  std::mutex m_mutex;                // data mutex
  std::mutex m_request_mutex;        // mutex and condition variable used to timeout and wakeup the worker thread
  std::condition_variable m_request_cv;
  volatile bool m_cv_notified = false; // Set to true when Commander::NotifyWorkerThread() is called

  // Temporary storage for command output text
  unsigned char commander_output_buffer[Websocket::WS_BUFFER_SIZE];

  bool ReportCommandExec(bool retv, const char* cmd);

  static void Thread(class Commander*);
  bool ExecCmd(PendingCommand& cmd);

public:

  // Strings used to format the output of a command into a JSON formatted reply
  static const char json_standard_reply_fmt[];
  static const char json_command_error_fmt[];
  static const char json_command_help_fmt[];
  static const char json_command_list_fmt[];
  static const char json_all_area_fmt[];
  static const char json_single_area_fmt[];
  static const char json_zone_omit_state_fmt[];
  static const char json_zone_state_fmt[];
  static const char json_all_zone_state_fmt[];
  static const char json_output_state_fmt[];

  // Strings used to format the output of a command when the polling thread executed it
  static const char poll_all_area_fmt[];
  static const char poll_all_zone_state_fmt[];
  static const char poll_output_state_fmt[];

  // This json reply is send by class Websocket when a client needs authorization before using the commander.
  static const char json_authorization_required_fmt[];

  // This json reply is only send by class Websocket when a client has upgraded the http protocol to a websocket.
  // It lets the client know the credentials it send were accepted and successfully validated.
  // See Websocket::http_callback::LWS_CALLBACK_RECEIVE
  static const char json_authentication_accepted_fmt[];

  /// Values send as 'typeId' with JSON formatted replies
  ///
  enum class json_reply_id : unsigned int {
    sia = 0,
    standard,
    help,
    area_armed_state,
    all_areas_armed_states,
    area_alarm_state,
    all_areas_alarm_states,
    area_ready_state,
    all_areas_ready_states,
    zone_omitted_state,
    single_zone_state,
    all_zones_state_base,  // Add an enum zs_action value to this for ready/alarm/open/tamper/rstate/omitted states 
    all_zones_ready_states = all_zones_state_base,
    all_zones_alarm_states,
    all_zones_open_states,
    all_zones_tamper_states,
    all_zones_resistance_states,
    all_zones_omitted_states,
    all_output_states,
    poll_reply,
    authorization_required,
    authentication_accepted,
    count
  };

  // Descriptive strings for JSON formatted reply typeId's
  static const char* CommanderTypeDesc[];

  // Notifies the worker thread to end the current sleeping period and immediately starts it's next mainloop iteration
  void notify();

  // joins the thread (used by openGalaxy::exit)
  void join() { m_thread->join(); }

  Commander(openGalaxy& openGalaxy);
  ~Commander();

  static int isArea(const char *s);
  int isZoneType(const char *s);

  void execute(
    class openGalaxy *opengalaxy,
    session_id *session,
    void *user,
    const char *command,
    callback_ptr callback
  );

  bool isBusy();

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }

}; // ends class Commander

} // ends namespace openGalaxy

#endif

