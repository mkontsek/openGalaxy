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

#ifndef __OPENGALAXY_OPENGALAXY_HPP__
#define __OPENGALAXY_OPENGALAXY_HPP__

#include "atomic.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#endif

#include <thread>
#include <mutex>
#include <condition_variable>

#include <chrono>
#include <exception>
#include <fstream>
#include <iomanip>
#include <ratio>
#include <sstream>
#include <string>
#include <system_error>
#include <cassert>
#include <cctype>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#ifndef _WIN32
#include <termios.h>
#endif
#include <unistd.h>

#include "Syslog.hpp"
#include "Settings.hpp"
#include "Serial.hpp"
#include "Sia.hpp"
#include "Receiver.hpp"
#include "Websocket.hpp"
#include "Commander.hpp"
#include "Output.hpp"
#include "Poll.hpp"
#include "Galaxy.hpp"
#include "context_options.hpp"

namespace openGalaxy {

class openGalaxy {

private:

  // These are used by member functions exit(), wait() and isQuit().
  //
  // exit() notifies openGalaxy to stop and exit.
  // wait() blocks and sleeps until exit() has been called.
  // isQuit() does not block and returns true when exit() has been called
  //
  std::condition_variable m_lock_cv;    // notified by exit() to signal wait() to exit.
  std::unique_lock<std::mutex> *m_lock; // the unique_lock used by m_lock_cv
  std::mutex m_lock_mutex;              // the mutex used by m_lock
  volatile bool m_quit;                 // locked until it is time to exit (ie. exit() is called)
  std::mutex m_mutex;

  // Provide a logging facility and settings management
  class Syslog *m_Syslog = nullptr;
  class Settings *m_Settings = nullptr;

  // These classes have worker threads
  class Receiver *m_Receiver = nullptr;
  class Websocket *m_Websocket = nullptr;
  class Commander *m_Commander = nullptr;
  class Output *m_Output = nullptr;
  class Poll *m_Poll = nullptr;

  // These classes do NOT have worker threads
  class Galaxy *m_Galaxy = nullptr;
  class SerialPort *m_Serial = nullptr;
  class SIA *m_SIA = nullptr;

  // re-throws exceptions caught in the worker threads
  void rethrow_thread_exceptions();

public:

  // Options specified on the commandline
  context_options m_options;

  // ctor
  openGalaxy(context_options& options);

  // dtor
  ~openGalaxy();

  // Signal that you wish to quit
  void exit();

  // the reason why opengalaxy exited
  enum {
    EXIT_STATUS_AS_REQUESTED = 0, // the normal exit status
    EXIT_STATUS_CERTS_UPDATED     // the SSL certificates were updated
  };
  int exit_status;

  // Blocks until exit() is called (internally or externally)
  void wait();

  // Returns false as long as exit() has not been called
  volatile bool isQuit();

  inline class Syslog&     syslog()     { return *m_Syslog; }
  inline class Settings&   settings()   { return *m_Settings; }
  inline class Receiver&   receiver()   { return *m_Receiver; }
  inline class Websocket&  websocket()  { return *m_Websocket; }
  inline class Commander&  commander()  { return *m_Commander; }
  inline class Output&     output()     { return *m_Output; }
  inline class Poll&       poll()       { return *m_Poll; }
  inline class Galaxy&     galaxy()     { return *m_Galaxy; }
  inline class SerialPort& serialport() { return *m_Serial; }
  inline class SIA&        sia()        { return *m_SIA; }

  // worker threads store any thrown exception here
  std::exception_ptr m_Receiver_exptr;
  std::exception_ptr m_Websocket_exptr;
  std::exception_ptr m_Commander_exptr;
  std::exception_ptr m_Output_exptr;
  std::exception_ptr m_Poll_exptr;

}; // ends class openGalaxy

} // ends namespace openGalaxy

#endif

