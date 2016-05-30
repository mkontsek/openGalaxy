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
#ifndef __OPENGALAXY_SERVER_SIGNAL_HPP__
#define __OPENGALAXY_SERVER_SIGNAL_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <signal.h>

namespace openGalaxy {

class Signals {
//
// Class Signals handles external signals that can be send to a program.
// There may be only one Signals instance, and it should be created 
// before any threads are created.
//
private:

  static void *m_userdata;                     // the user data send to the callback
  static std::mutex m_mutex;
  static void(*m_callback)(void*,int);         // the user defined callback upon receiving a signal
  static void dummycb( void*, int signum );    // Dummy callback set when the default ctor is used

#ifdef __linux__
  static volatile bool m_quit;                 // set to true to exit m_thread
  static std::thread* m_thread;                // the thread for this Signals
  static volatile bool m_handled;              // false while a pending signal has not been handled yet
  static sigset_t m_signals;                   // our set of signals
  static void dummy( int signum );             // Dummy signal handler that does nothing.
  static void Thread( Signals* _this );        // the main() function for the Signals thread
  static void setup();
#endif

#if _WIN32
  static BOOL WINAPI HandlerRoutine( DWORD dwCtrlType );
#endif

public:

  // ctor
  Signals();
  Signals(void(*callback)(void*,int),void *userdata);

  // dtor
  ~Signals();

  // !! do not use, throw an exception instead !!
  // Thread safe raise() function that blocks until the signal is handled
  static int raise( int signum ); 

  // Set the callback function and the usedata to pass to it
  static void set_callback(void(*callback)(void*,int), void *userdata);
};

} // ends namespace openGalaxy

#endif

