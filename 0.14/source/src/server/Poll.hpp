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

#ifndef __OPENGALAXY_SERVER_POLL_HPP__
#define __OPENGALAXY_SERVER_POLL_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <condition_variable>

#include "Array.hpp"

#include "opengalaxy.hpp"

namespace openGalaxy {

class Poll {
public:
  // A list of 'items' that we could poll
  enum possible_items {
    nothing    = 0,
    areas      = 1 << 0,
    zones      = 1 << 1,
    outputs    = 1 << 2,
    everything = 1 << 0 | 1 << 1 | 1 << 2
  };

  // Poll userdata for each command send to the commander thread
  struct poll_userdata {
    bool retv;           // the return value of CommanderExecCmd(), false when the command failed, true when successfull
    possible_items item; // the item returned by CommanderExecCmd() (poll_areas, poll_zones or poll_outputs)
  };

  // Instance data for each polling client
  class _ws_info {
  public:
    session_id session;
    poll_userdata *user; // Poll userdata
    void (*callback)(class openGalaxy&, session_id*, void*, char*); // commander callback
    void copy_from(_ws_info& i){
      user = i.user;
      session = i.session;
      callback = i.callback;
    }
    _ws_info(class context_options& options) : session(options) {}
    _ws_info(_ws_info& i) : session(i.session) {
      user = i.user;
      callback = i.callback;
    }
  };

private:

  constexpr static const int DEFAULT_POLL_INTERVAL_SECONDS = 60;
  constexpr static const int POLL_INTERVAL_IDLE = 180;

  // Define a list of clients that have requested to poll the panel
  class Client {
  public:
    _ws_info socket;
    int on;
    int interval;
    int one_shot;
    possible_items items;
    Client(class context_options& options) : socket(options) {}
    Client(Client& c) : socket(c.socket) {
      on = c.on;
      interval = c.interval;
      one_shot = c.one_shot;
      items = c.items;
    }
  };

  class ClientList : public ObjectArray<Client*> {
  public:
    Client* search(session_id& session){
      for(int i=0; i<ObjectArray<Client*>::size(); i++){
        Client *c= ObjectArray<Client*>::operator[](i);
        if(c->socket.session == session){
          return c;
        }
      }
      return nullptr;
    }
  };

  class openGalaxy& m_openGalaxy;

  std::thread *m_thread;             // the worker thread for this receiver instance
  std::mutex m_mutex;                // data mutex
  std::mutex m_request_mutex;        // mutex and condition variable used to timeout and wakeup the worker thread
  std::condition_variable m_request_cv;
  volatile bool m_cv_notified = false; // Set to true when Poll::NotifyWorkerThread() is called


  int m_interval_seconds = DEFAULT_POLL_INTERVAL_SECONDS;
  int m_interval_changed = 0;

  int m_poll_on = 0;       // non-zero when we are actively polling
  int m_poll_one_shot = 0; // set to non-zero to poll once

  int m_poll_busy = 0; // The number of items that (still) waiting to receive a result from the commander thread.

  int m_is_pauzed = 0;

  // The default is to nothing
  possible_items m_poll_items = possible_items::nothing;
  int m_items_changed = 1;

  ClientList m_client_list;

  constexpr static const char *json_poll_state_fmt = 
    "{"
    "\"typeId\":%d,"
    "\"typeDesc\":\"%s\","
    "\"panelIsOnline\":%d,"
    "\"haveAreaState\":%d,"
    "\"haveZoneState\":%d,"
    "\"haveOutputState\":%d,"
    "\"areaState\":%s,"
    "\"zoneState\":%s,"
    "\"outputState\":%s"
    "}";

  // buffers/data used by poll_callback() and cb_online()
  char m_buffer[1024];
  const char *m_emptyArray = "[0]";
  char m_bufferAreas[1024];
  bool m_haveAreas = false;
  char m_bufferZones[1024];
  bool m_haveZones = false;
  char m_bufferOutputs[1024];
  bool m_haveOutputs = false;

  static void Thread(class Poll *_this);

  // This is the function that polls the galaxy panel.
  bool poll_once();

  static void Commander_Callback(class openGalaxy&, session_id *session, void*, char*);
  static void Receiver_Callback(class openGalaxy&,char*,int);

  void ClientAdd(_ws_info *socket);
  bool ClientRemove(session_id& session);

public:
  Poll(openGalaxy& openGalaxy);
  ~Poll();

  // Notifies the worker thread to end the current sleeping period and immediately starts the next mainloop iteration
  void notify();

  // joins the thread (used by openGalaxy::exit)
  void join() { m_thread->join(); }

  bool enable(_ws_info *socket);
  bool disable(/*Websocket::*/session_id& session);
  bool setInterval(_ws_info *socket, int interval_in_seconds);
  int  getInterval();
  bool setItems(_ws_info *socket, possible_items items);
  bool clearItems(_ws_info *socket, possible_items items);
  possible_items getItems();
  bool oneShot(_ws_info *socket);

  void pauze();  // pauze polling the panel (while the receiver is executing a command)
  void resume(); // resume polling the panel

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }
};


// implement some operators for Poll::possible_items
inline Poll::possible_items& operator|=(Poll::possible_items& a, Poll::possible_items b){
  return a= (Poll::possible_items)( (int)a | (int)b );
}

inline Poll::possible_items& operator&=(Poll::possible_items& a, Poll::possible_items b){
  return a= (Poll::possible_items)( (int)a & (int)b );
}

inline Poll::possible_items& operator~(Poll::possible_items& a){
  return a=  (Poll::possible_items)( ~(int)a );
}

} // ends namespace openGalaxy

#endif

