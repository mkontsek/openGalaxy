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

#ifndef __OPENGALAXY_SERVER_SERIAL_HPP__
#define __OPENGALAXY_SERVER_SERIAL_HPP__

#include "atomic.h"

#if _WIN32
#include <windows.h>
#endif

#include <thread>
#include <mutex>
#include <condition_variable>

#include "opengalaxy.hpp"

namespace openGalaxy {

class SerialPort {
private:
  class openGalaxy& m_openGalaxy;
  volatile bool m_bIsOpen;
#if _WIN32
  HANDLE m_nTTY;
#else
  int m_nTTY;
  struct termios m_oldtio, m_tio;
#endif
public:
  SerialPort(openGalaxy& opengalaxy) : m_openGalaxy(opengalaxy) { m_bIsOpen = false; open(); }
  ~SerialPort() { SerialPort::close(); }
  bool isOpen() { return m_bIsOpen; }
  bool open(void);
  void close(void);
  size_t read(void* buf, size_t count);
  size_t write(void* buf, size_t count);

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }
};

} // ends namespace openGalaxy

#endif

