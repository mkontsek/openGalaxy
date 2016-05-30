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

// This class is a big mess and should be reworked.
// For now it seems to work....

// for one: the poll thread need its own 'global' class Websocket::session_id

#include "atomic.h"

#include "Syslog.hpp"
#include "Settings.hpp"
#include "Poll.hpp"

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>

namespace openGalaxy {

void PollThread_Receiver_Callback(Websocket& websocket, char* s, int l);
void PollThread_Commander_Callback(Commander&, session_id *session, void *user, char *out);

Poll::Poll(openGalaxy& openGalaxy)
 : m_openGalaxy(openGalaxy)
{
  m_thread = new std::thread(Poll::Thread, this);
}

Poll::~Poll()
{
  delete m_thread;
}

bool Poll::poll_once()
{
  bool retv = true;

  if( m_poll_items == possible_items::nothing ){
    // Nothing to poll, test if the panel is online.
    if( m_poll_on || m_poll_one_shot ){
      m_poll_busy = 1;
      const char *msg = "EV*"; // flush all events for all modules
      opengalaxy().receiver().send( SiaBlock::FunctionCode::extended, (char*)msg, strlen( msg ) + 1/*include the 0 byte*/, Poll::Receiver_Callback );
    }
  }
  else{
    if(opengalaxy().isQuit()==true) return false;
    if( m_poll_items & possible_items::areas ){
      // Poll areas alarm state
      opengalaxy().syslog().debug("Poll: polling areas ready state...");
      poll_userdata *user = new poll_userdata();
      user->retv = 0;
      user->item = possible_items::nothing;
      opengalaxy().commander().execute(
        &m_openGalaxy,
        nullptr,
        user,
        (char*)"AREA 0 READY",
        Poll::Commander_Callback
      );
    }
    if(opengalaxy().isQuit()==true) return false;
    if( m_poll_items & possible_items::zones ){
      // poll zones
      opengalaxy().syslog().debug("Poll: polling zones...");
      poll_userdata *user = new poll_userdata();
      user->retv = 0;
      user->item = possible_items::nothing;
      opengalaxy().commander().execute(
        &m_openGalaxy,
        nullptr,
        user,
        (char*)"ZONES ALARM",
        Poll::Commander_Callback
      );
    }
    if(opengalaxy().isQuit()==true) return false;
    if( m_poll_items & possible_items::outputs ){
      // poll outputs
      opengalaxy().syslog().debug("Poll: polling outputs..." );
      poll_userdata *user = new poll_userdata();
      user->retv = 0;
      user->item = possible_items::nothing;
      opengalaxy().commander().execute(
        &m_openGalaxy,
        nullptr,
        user,
        (char*)"OUTPUT GETALL",
        Poll::Commander_Callback
      );
    }
  }

  return retv;
}

void Poll::notify()
{
  m_cv_notified = true;
  m_request_cv.notify_one();
}

bool Poll::enable(_ws_info *socket)
{
  m_mutex.lock();
  ClientAdd(socket);

  Poll::Client *c = m_client_list.search(socket->session);
  if(c==nullptr){
    m_mutex.unlock();
    return false;
  }

  c->on = 1;
  m_poll_on = 1;

  m_mutex.unlock();
  notify();
  return true;
}

bool Poll::disable(session_id& session)
{
  m_mutex.lock();
  bool retv = ClientRemove(session);
  m_mutex.unlock();
  return retv;
}

bool Poll::setInterval(_ws_info *socket, int interval_in_seconds)
{
  assert(interval_in_seconds>0);

  m_mutex.lock();
  ClientAdd(socket);
  Poll::Client *c = m_client_list.search(socket->session);
  if(c==nullptr){
    m_mutex.unlock();
    return false;
  }

  c->interval = interval_in_seconds;
  m_interval_changed = 1; // signal change, reset by thread main()
  int wakeup = c->on;

  m_mutex.unlock();
  if(wakeup) notify();

  return true;
}

int Poll::getInterval()
{
  m_mutex.lock();
  int interval = m_interval_seconds;
  m_mutex.unlock();
  return interval;
}

bool Poll::setItems(_ws_info *socket, Poll::possible_items items)
{
  m_mutex.lock();
  ClientAdd(socket);
  Poll::Client *c = m_client_list.search(socket->session);
  if(c==nullptr){
    m_mutex.unlock();
    return false;
  }
  if(items == Poll::possible_items::nothing){
    c->items = Poll::possible_items::nothing;
  }
  else if(items == Poll::possible_items::everything){
    c->items = Poll::possible_items::everything;
  }
  else {
    c->items |= items;
  }
  m_items_changed = 1; // signal change, reset by thread main()
  m_mutex.unlock();
  return true;
}

bool Poll::clearItems(_ws_info *socket, possible_items items)
{
  m_mutex.lock();
  ClientAdd(socket);
  Poll::Client *c = m_client_list.search(socket->session);
  if(c==nullptr){
    m_mutex.unlock();
    return false;
  }
  if(items == Poll::possible_items::nothing){
    c->items = Poll::possible_items::everything;
  }
  else if(items == Poll::possible_items::everything){
    c->items = Poll::possible_items::nothing;
  }
  else {
    c->items &= ~items;
  }
  m_items_changed = 1; // signal change, reset by thread main()
  m_mutex.unlock();
  return true;
}

Poll::possible_items Poll::getItems()
{
  m_mutex.lock();
  Poll::possible_items items = m_poll_items;
  m_mutex.unlock();
  return items;
}

bool Poll::oneShot(_ws_info *socket)
{
  m_mutex.lock();

  // Get the client
  Poll::Client *c = m_client_list.search(socket->session);
  if(c!=nullptr){
    // existing client, allready polling?
    if(c->on){
      // yes, immediately wake the thread and do the next poll iteration
      m_mutex.unlock();
      notify();
      return true;
    }
  }

  // Add the client if it was not in the client list yet
  if(c==nullptr){
    ClientAdd(socket);
    c = m_client_list.search(socket->session);
    if(c==nullptr){
      m_mutex.unlock();
      return false;
    }
  }

  // ...and set it to be removed after the next poll iteration
  c->one_shot = 1;
  m_poll_one_shot = 1;

  m_mutex.unlock();
  notify();
  return true;
}

// Adds a client to the list of clients that have requested to poll the panel
void Poll::ClientAdd(Poll::_ws_info *socket)
{
  Poll::Client *c = m_client_list.search(socket->session);
  if(c==nullptr){
    c = new Poll::Client(opengalaxy().m_options);
    c->socket.copy_from(*socket);
    c->on = 0;
    c->interval = Poll::DEFAULT_POLL_INTERVAL_SECONDS;
    c->one_shot = 0;
    c->items = Poll::possible_items::nothing;
    m_client_list.append(c);
  }
}

// Removes a client from the list of clients that have requested to poll the panel
bool Poll::ClientRemove(session_id& session)
{
  bool retv = false;
  for(int i=0; i<m_client_list.size(); i++){
    Client *c = m_client_list[i];
    if(c->socket.session == session){
      m_client_list.remove(i);
      retv = true;
      break;
    }
  }
  if(m_client_list.size() == 0){
    m_poll_on = 0; // no more clients, stop polling
    m_interval_seconds = Poll::DEFAULT_POLL_INTERVAL_SECONDS;
    m_poll_busy = 0;
  }
  m_items_changed = 1; // removing a client may change what items need to be polled...
  m_interval_changed = 1; // removing a client may change the polling interval
  if(m_poll_busy > 0) m_poll_busy--;
  return retv;
}


// This callback is called by the commander thread with the results of each item that was polled
void Poll::Commander_Callback(class openGalaxy& opengalaxy, session_id *session, void *user, char *out)
{
  Poll *poll = &opengalaxy.poll();

  poll->m_mutex.lock();

  Poll::Client c(opengalaxy.m_options);
  Poll::possible_items item = Poll::possible_items::nothing;

  // Get/Free the user data and determine if the command we tried to execute failed
  Poll::poll_userdata *usr = (Poll::poll_userdata*)user;
  if(usr){
    if(usr->retv == false){
      // the command failed. this means the panel is offline.
      poll->opengalaxy().syslog().debug("Poll: Panel is offline!");
      delete usr;
      poll->m_poll_busy = 0;
      snprintf(
        poll->m_buffer, sizeof( poll->m_buffer ),
        poll->json_poll_state_fmt,
        static_cast<unsigned int>(Commander::json_reply_id::poll_reply),
        Commander::CommanderTypeDesc[static_cast<int>(Commander::json_reply_id::poll_reply)],
        0, 0, 0, 0,
        poll->m_emptyArray, poll->m_emptyArray, poll->m_emptyArray
      );
      goto notify;
    }
    item = usr->item;
    delete usr;
  }
  else {
    poll->opengalaxy().syslog().debug("Poll: Missing userdata!");
  }
  // The command was successfull.

  // Copy the formatted output to a temporary buffer depending on the item returned
  switch( item ){
    case Poll::possible_items::areas:
      strncpy( poll->m_bufferAreas, out, sizeof( poll->m_bufferAreas ) );
      poll->m_haveAreas = true;
      break;
    case Poll::possible_items::zones:
      strncpy( poll->m_bufferZones, out, sizeof( poll->m_bufferZones ) );
      poll->m_haveZones = true;
      break;
    case Poll::possible_items::outputs:
      strncpy( poll->m_bufferOutputs, out, sizeof( poll->m_bufferOutputs ) );
      poll->m_haveOutputs = true;
      break;
    default:
      break;
  }

  // Are we waiting for a reply to a command?
  if( poll->m_poll_busy == 0 ){
    // No, this is unexpected and should not happen. (unless a client disapeared)
    poll->opengalaxy().syslog().error("Poll: client disapeared!?");
    poll->m_mutex.unlock();
    return;
  }
  // Yes.

  // one less item result to wait for until we can start a next polling loop.
  for(int i=0; i<poll->m_client_list.size(); i++){
    c = *poll->m_client_list[i];
    if( ( c.on || c.one_shot ) && poll->m_poll_busy > 0 ) poll->m_poll_busy--;
  }

  // Did we get the result for all items?
  if( poll->m_poll_busy == 0 ){
    // Yes, compile and send the final result to all listening clients

    snprintf(
      poll->m_buffer,
      sizeof( poll->m_buffer ),
      poll->json_poll_state_fmt,
      static_cast<unsigned int>(Commander::json_reply_id::poll_reply),
      Commander::CommanderTypeDesc[static_cast<int>(Commander::json_reply_id::poll_reply)],
      1, // online
      ( poll->m_haveAreas == true   ) ? 1 : 0, // have areas
      ( poll->m_haveZones == true   ) ? 1 : 0, // have zones
      ( poll->m_haveOutputs == true ) ? 1 : 0, // have outputs
      ( poll->m_haveAreas == true   ) ? poll->m_bufferAreas   : poll->m_emptyArray, // area states
      ( poll->m_haveZones == true   ) ? poll->m_bufferZones   : poll->m_emptyArray, // zone states
      ( poll->m_haveOutputs == true ) ? poll->m_bufferOutputs : poll->m_emptyArray  // output states
    );

notify:
    poll->m_haveAreas = false; // reset
    poll->m_haveZones = false;
    poll->m_haveOutputs = false;

    // Send the results to all listening clients
    for(int i=0; i<poll->m_client_list.size(); i++){
      c = *poll->m_client_list[i];
      if( c.on || c.one_shot ){
        c.socket.callback(
          poll->m_openGalaxy,
          &c.socket.session,
          c.socket.user,
          poll->m_buffer
        );
      }
      // Remove any one-shot clients
      if( c.one_shot ){
        poll->ClientRemove( c.socket.session );
        poll->m_poll_one_shot = 0;
      }
    }
  }
  poll->m_mutex.unlock();
}

// called by Receiversend()
void Poll::Receiver_Callback(openGalaxy& opengalaxy, char* s, int l)
{
  Poll& poll = opengalaxy.poll();
  Syslog& syslog = opengalaxy.syslog();

  poll.m_mutex.lock();
  int online = 0;


  if(s == nullptr){
    switch(l){
      case 0: // Command failed but login was ok (panel is online)
      case 1: // remote login was rejected (panel is online)
        online = 1;
        break;
      default: // remote login rejected (panel is offline)
        online = 0;
        break;
    }
  }
  else {
    // the command executed correctly
    online = 1;
  }

  syslog.debug("Poll: Galaxy is %s", (online) ? "online" : "offline!");

  snprintf(
    poll.m_buffer, sizeof( poll.m_buffer ),
    poll.json_poll_state_fmt,
    static_cast<unsigned int>(Commander::json_reply_id::poll_reply),
    Commander::CommanderTypeDesc[static_cast<int>(Commander::json_reply_id::poll_reply)],
    online, 0, 0, 0,
    poll.m_emptyArray, poll.m_emptyArray, poll.m_emptyArray
  );

  // Send the results to all listening clients
  for(int i=0; i<poll.m_client_list.size(); i++){
    Poll::Client& c = *poll.m_client_list[i];
    if( c.on || c.one_shot ){
      c.socket.callback(
        poll.m_openGalaxy,
        &c.socket.session,
        c.socket.user,
        poll.m_buffer
      );
    }
    // Remove any one-shot clients
    if( c.one_shot ){
      poll.ClientRemove( c.socket.session );
      poll.m_poll_one_shot = 0;
    }
  }

  if( poll.m_poll_busy > 0 ) poll.m_poll_busy--;

  poll.m_mutex.unlock();
}

void Poll::pauze()
{
//  m_mutex.lock();
  m_is_pauzed = 1;
//  m_mutex.unlock();
}

void Poll::resume()
{
//  m_mutex.lock();
  m_is_pauzed = 0;
//  m_mutex.unlock();
}

void Poll::Thread(Poll* poll)
{
  using namespace std::chrono;
  try {

    Poll::possible_items items;
    static int nr_of_items = 0;
    int delayed = 0;

    int loop_delay = 1;
    std::unique_lock<std::mutex> lck(poll->m_request_mutex);

    // The outer loop only exits if the openGalaxy object is being destroyed.
    // The inner loop iterates once every 'loop_delay' seconds, 
    // or sooner when Commander::NotifyWorkerThread() is called.

    // Outer loop: test if it is time to exit
    while(poll->opengalaxy().isQuit()==false){
      // Inner loop: test if we were notified or if we need to sleep
      while(poll->m_cv_notified || poll->m_request_cv.wait_for(lck,seconds(loop_delay))==std::cv_status::timeout){
        // reset our notification variable
        poll->m_cv_notified = false;
        // Test if we need to exit the thread.
        if(poll->opengalaxy().isQuit()==true) break;
        // Lock the (data access) mutex
        poll->m_mutex.lock();
        //////////////////////////////////////////////////
        //////////////////////////////////////////////////
        //////////////////////////////////////////////////

        // Has the previous loop received results for all the items it polled?
        if( poll->m_poll_busy != 0 ){
          // No, delay the next poll by 'delayed' seconds to prevent a buildup of unprocessed commands
          delayed = 10;
          poll->opengalaxy().syslog().error("Poll: Previous poll is still waiting for data, wait...");
        }
        else {
          // Yes, we're clear to poll (again)

          // Test if we need to exit the thread.
          if(poll->opengalaxy().isQuit()==true) break;

          if( poll->opengalaxy().commander().isBusy() == false ){
            if( poll->opengalaxy().receiver().isTransmitting() == false ){
              if( poll->opengalaxy().receiver().IsReceiving() == false ){

                // determine what items to poll by combining flags from each client
                if( poll->m_items_changed ){
                  nr_of_items = 0;
                  items = Poll::possible_items::nothing;

                  if( poll->m_client_list.size() == 0 ){
                    items = Poll::possible_items::nothing;
                    nr_of_items = 0;
                  }
                  else {
                    for(int i=0; i<poll->m_client_list.size(); i++){
                      Poll::Client& c = *poll->m_client_list[i];
                      if( c.items & Poll::possible_items::areas ){
                        items |= Poll::possible_items::areas;
                        nr_of_items++;
                      }
                      if( c.items & Poll::possible_items::zones ){
                        items |= Poll::possible_items::zones;
                        nr_of_items++;
                      }
                      if( c.items & Poll::possible_items::outputs ){
                        items |= Poll::possible_items::outputs;
                        nr_of_items++;
                      }
                    }
                  }

                  poll->m_poll_items = items;
                  poll->m_items_changed = 0;
                }

//poll->opengalaxy().syslog().error("Poll: list=%d m_poll_on=%d m_poll_one_shot=%d",
//poll->m_client_list.size(), poll->m_poll_on, poll->m_poll_one_shot);

               // Poll the panel once if wanted
                if(poll->m_client_list.size()){
                  if( poll->m_poll_on || poll->m_poll_one_shot ){
                    if(poll->m_is_pauzed == 0){
//poll->opengalaxy().syslog().print("m_poll_on == %d", poll->m_poll_on);
                      poll->m_poll_busy = nr_of_items; // reset the number of items (still) to get
                      poll->poll_once(); // fetch the items, reset m_poll_busy to 0 and send a reply to all listening clients
                    }
                  }
                }
                else {
                  poll->m_poll_on = 0;
                  poll->m_poll_one_shot = 0;
                }

                // Use the client with the shortest interval as the new m_interval_seconds.
                // Also check if we should continue to poll for any client
                if( poll->m_interval_changed || poll->m_poll_one_shot || poll->m_poll_on ){
                  int interval = poll->m_interval_seconds;
                  int on = 0;
                  // loop through the clients
                  for(int i=0; i<poll->m_client_list.size(); i++){
                    Poll::Client& c = *poll->m_client_list[i];
                    // otherwise if this client has polling turned on, then check its interval value
                    if( c.on ){
                      if( c.interval < interval ) interval = c.interval;
                      on = 1;
                    }
                  }

                  // Set the new interval
                  poll->m_interval_seconds = interval;
                  // Reset the 'interval has changed' flag
                  poll->m_interval_changed = 0;
                  // Continue polling only if at least one client wants us to
                  poll->m_poll_on = on;
                }

              }
              else {
                poll->opengalaxy().syslog().debug("Poll: Receiver is receiving, delaying this iteration!");
                delayed = 10;
              }
            }
            else {
              poll->opengalaxy().syslog().debug("Poll: Receiver is transmitting, delaying this iteration!");
              delayed = 10;
            }
          }
          else {
            poll->opengalaxy().syslog().debug("Poll: Commander is busy, delaying this iteration!");
            delayed = 10;
          }

        }

        // Decide for how long to sleep
        if( poll->m_poll_on ){
          if( delayed ){
            loop_delay = delayed;
          }
          else {
            loop_delay = poll->m_interval_seconds;
          }
        }
        else {
          // If no clients are listening, the timeout can be a very long time
          loop_delay = Poll::POLL_INTERVAL_IDLE;
        }

        // unlock the (data access) mutex while we are sleeping
        poll->m_mutex.unlock();
      } // ends inner loop
    } // ends outer loop
    poll->opengalaxy().syslog().debug("Poll::Thread exited normally");
  }
  catch(...){
    // pass the exception on to the main() thread
    poll->opengalaxy().m_Poll_exptr = std::current_exception();
    poll->opengalaxy().exit();
  }
}


} // ends namespace openGalaxy

