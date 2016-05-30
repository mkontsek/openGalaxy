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

#ifndef __OPENGALAXY_SERVER_OUTPUT_MYSQL_HPP__
#define __OPENGALAXY_SERVER_OUTPUT_MYSQL_HPP__

#include "atomic.h"
#include "Array.hpp"
#include "Output.hpp"
#include "opengalaxy.hpp"
#include <mysql.h>

namespace openGalaxy {

class MySqlOutput : public virtual OutputPlugin {
private:
  // a worker thread
  std::thread *m_thread;
  static void Thread(class MySqlOutput*);

  // mutex and condition variable used to wakeup the worker thread
  std::mutex m_request_mutex;
  std::condition_variable m_request_cv;

  // Set to true when notify() is called, used to signal to the worker thread
  // that it did not timeout while sleeping but that we woke it up with m_request_cv
  volatile bool m_cv_notified = false;

  // List of SiaEvents to write to the database
  class ObjectArray<SiaEvent*> m_messages;

  // data mutex (protecting 'm_messages')
  std::mutex m_mutex;

  // Notifies the worker thread to break the current
  // delay loop and immediately start the next loop iteration
  void notify(); 

  // Our MySQL (library) instance
  MYSQL *connector;

  // This function actually writes data to the database
  bool write_db(class SiaEvent& msg);

public:
  // Overloaded functions from class OutputPlugin
  MySqlOutput(class openGalaxy& opengalaxy);
  ~MySqlOutput();
  bool write(class SiaEvent& msg);
  const char *name();
  const char *description();
};

} // Ends namespace openGalaxy

#endif

