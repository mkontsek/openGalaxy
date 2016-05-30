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

#ifndef __OPENGALAXY_SERVER_OUTPUT_HPP__
#define __OPENGALAXY_SERVER_OUTPUT_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <condition_variable>

#include "Array.hpp"

#include "opengalaxy.hpp"

namespace openGalaxy {

// All output plugins must inherit this base class
class OutputPlugin {

protected:
  class openGalaxy& m_openGalaxy;

public:
  OutputPlugin(class openGalaxy& opengalaxy) : m_openGalaxy(opengalaxy) {}
  virtual ~OutputPlugin() {}

  virtual bool write(class SiaEvent& msg) {
    throw new std::runtime_error( "Output: Error, no write() method in plugin implemenation!" );
  }

  virtual const char *name() { return nullptr; }
  virtual const char *description() { return nullptr; }

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }
};


class NullOutput : public virtual OutputPlugin {
public:
  NullOutput(class openGalaxy& opengalaxy) : OutputPlugin(opengalaxy) {}
  bool write(class SiaEvent& msg);
  const char *name();
  const char *description();
};


class Output {
private:

  std::thread *m_thread;                      // the worker thread
  std::mutex m_mutex;                         // data mutex (protecting variable 'transmit_list')
  std::mutex m_request_mutex;                 // mutex and condition variable used to timeout and wakeup the worker thread
  std::condition_variable m_request_cv;
  volatile bool m_cv_notified = false;        // Set to true when NotifyWorkerThread() is called

  class openGalaxy& m_openGalaxy;             // The openGalaxy object we are outputting messages for
  class ObjectArray<OutputPlugin*> m_plugins; // The list of registered output plugins
  class ObjectArray<SiaEvent*> m_messages;    // The list of messages to outpput

  void json_encode(std::stringstream& json, SiaEvent& msg);

  static void Thread(class Output*);

public:

  // ctor
  Output(class openGalaxy& opengalaxy);

  // dtor
  ~Output();

  // Add a message to the que of messages to send to the output
  void write(SiaEvent& msg);

  // Notifies the worker thread to break the current delay loop and immediately start the next loop iteration
  void notify();

  // joins the thread (used by openGalaxy::exit)
  void join();

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }

  // Output plugins that utilize a thread may store a thrown exception here
  std::exception_ptr m_Plugin_exptr;
};

} // Ends namespace openGalaxy

#endif

