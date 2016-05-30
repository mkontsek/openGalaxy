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

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include "Signal.hpp"
#include <thread>
#include <type_traits>
#include <exception>
#include <signal.h>
#include <iostream>

#ifdef __linux__
static_assert(std::is_same<std::thread::native_handle_type, pthread_t>::value,
  "libstdc++ thread implementation does not use the POSIX threads library (pthread_t) !");
#endif

namespace openGalaxy {

void *Signals::m_userdata;                            // the user data send to the callback
std::mutex Signals::m_mutex;
void(*Signals::m_callback)(void*,int);                // the user defined callback upon receiving a signal

// Dummy signal handler that does nothing.
void Signals::dummycb( void*, int signum )
{
  // Do nothing
}

#ifdef __linux__

volatile bool Signals::m_quit;                        // set to true to exit m_thread
volatile bool Signals::m_handled;                     // false while a pending signal has not been handled yet
sigset_t Signals::m_signals;                          // our set of signals
std::thread* Signals::m_thread;                       // the thread for this Signals

// Dummy signal handler that does nothing.
void Signals::dummy( int signum )
{
  // Do nothing
}

// This thread processes all relevant signals.
void Signals::Thread( Signals* _this )
{
  if( signal( SIGINT,  dummy ) == SIG_IGN ){ signal( SIGINT,  SIG_IGN ); }
  if( signal( SIGABRT, dummy ) == SIG_IGN ){ signal( SIGABRT, SIG_IGN ); }
  if( signal( SIGTERM, dummy ) == SIG_IGN ){ signal( SIGTERM, SIG_IGN ); }
  if( signal( SIGQUIT, dummy ) == SIG_IGN ){ signal( SIGQUIT, SIG_IGN ); }
  if( signal( SIGHUP,  dummy ) == SIG_IGN ){ signal( SIGHUP,  SIG_IGN ); }
  if( signal( SIGUSR1, dummy ) == SIG_IGN ){ signal( SIGUSR1, SIG_IGN ); }
  if( signal( SIGUSR2, dummy ) == SIG_IGN ){ signal( SIGUSR2, SIG_IGN ); }

  // loop until we need to quit
  m_mutex.lock();
  while( _this->m_quit == false ){
    sigset_t pending;
    int signum = 0;

    // Check for pending signals
    if( sigpending( &pending ) == 0 ){
      // If a signal is pending
      if(
        sigismember( &pending, SIGINT  ) > 0 ||
        sigismember( &pending, SIGABRT ) > 0 ||
        sigismember( &pending, SIGTERM ) > 0 ||
        sigismember( &pending, SIGQUIT ) > 0 ||
        sigismember( &pending, SIGHUP  ) > 0 ||
        sigismember( &pending, SIGUSR1 ) > 0 ||
        sigismember( &pending, SIGUSR2 ) > 0 
      ){
        // Remove the pending signal and call the user defined handler function
        sigwait( &_this->m_signals, &signum );
        if( signum != 0 && _this->m_callback != nullptr){
          _this->m_callback( _this->m_userdata, signum );
        }
      }
    }
    else {
      _this->m_quit = true;
      throw new std::runtime_error( "openGalaxy::Signals cannot poll for pending signals!" );
    }

    // Signal that we are done handling this signal (Set by Raise())
    _this->m_handled = true;  

    // Sleep for a while before the next loop
    m_mutex.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    m_mutex.lock();
  }
}

void Signals::set_callback(void(*callback)(void*,int), void *userdata)
{
  m_mutex.lock();
  m_userdata = userdata;
  m_callback = callback;
  m_mutex.unlock();
}

void Signals::setup()
{
  sigemptyset( &m_signals );

 // Add the desired signal to the set
  if( sigaddset( &m_signals, SIGABRT ) != 0 ||
      sigaddset( &m_signals, SIGHUP ) != 0 ||
      sigaddset( &m_signals, SIGINT ) != 0 ||
      sigaddset( &m_signals, SIGQUIT ) != 0 ||
      sigaddset( &m_signals, SIGTERM ) != 0 ||
      sigaddset( &m_signals, SIGUSR1 ) != 0 ||
      sigaddset( &m_signals, SIGUSR2 ) != 0 ||
      // Block out these signals.
      pthread_sigmask( SIG_BLOCK, &m_signals, nullptr) != 0
  ){
    throw new std::runtime_error( "openGalaxy::Signals: could not set signal mask!" );
  }
}

Signals::Signals()
{
  m_mutex.lock();
  m_userdata = nullptr;
  m_quit = false;
  m_handled = true;
  m_callback = dummycb;
  setup();
  m_mutex.unlock();
  m_thread = new std::thread( Thread, this );
}

Signals::Signals(void(*callback)(void*,int), void *userdata)
{
  m_mutex.lock();
  m_userdata = userdata;
  m_quit = false;
  m_handled = true;
  m_callback = callback;
  setup();
  m_mutex.unlock();
  m_thread = new std::thread( Thread, this );
}

Signals::~Signals(){
  m_mutex.lock();
  m_quit = true;
  m_mutex.unlock();
  m_thread->join();
  delete m_thread;
}


// Thread safe raise() function that blocks until the signal is handled
int Signals::raise( int signum )
{
  if( sigismember( &m_signals, signum ) > 0 ){
    m_handled = false;
    int retv = pthread_kill( m_thread->native_handle(), signum );
    while( m_handled == false ) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    return retv;
  }
  return pthread_kill( m_thread->native_handle(), signum );
}

#endif // ends IF __linux__

#if _WIN32

BOOL WINAPI Signals::HandlerRoutine( DWORD dwCtrlType )
{
  switch( dwCtrlType ){
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
      m_mutex.lock();
      m_callback( m_userdata, SIGINT );
      m_mutex.unlock();
      return TRUE;
  }
  return FALSE;
}

Signals::Signals()
{
  m_mutex.lock();
  m_userdata = nullptr;
  m_callback = dummycb;
  m_mutex.unlock();

  if( 0 == SetConsoleCtrlHandler( HandlerRoutine, TRUE )){
    throw new std::runtime_error( "openGalaxy::Signals: could not set CTRL handler!" );
  }
}

Signals::Signals(void(*callback)(void*,int), void *userdata)
{
  m_mutex.lock();
  m_userdata = userdata;
  m_callback = callback;
  m_mutex.unlock();

  if( 0 == SetConsoleCtrlHandler( HandlerRoutine, TRUE )){
    throw new std::runtime_error( "openGalaxy::Signals: could not set CTRL handler!" );
  }
}

Signals::~Signals(){
}

void Signals::set_callback(void(*callback)(void*,int), void *userdata)
{
  m_mutex.lock();
  m_userdata = userdata;
  m_callback = callback;
  m_mutex.unlock();
}

// Thread safe raise() function that blocks until the signal is handled
int Signals::raise( int signum )
{
  throw new std::runtime_error( "openGalaxy::Signals: raise() not implemented!" );
  return -1;
}

#endif // ends IF _WIN32

} // ends namespace openGalaxy

