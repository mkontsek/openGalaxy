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

#ifndef __OPENGALAXY_SERVER_RECEIVER_HPP__
#define __OPENGALAXY_SERVER_RECEIVER_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <condition_variable>

#include "Array.hpp"
#include "tmalloc.hpp"

#include "opengalaxy.hpp"

namespace openGalaxy {

// transmitter === field equipments modem/rs232
// receiver    === our modem/rs232

class Receiver {
public:

  // TransmitSiaBlock is used to store SIA data that will
  // be send data to the transmitter.
  // Data is pushed into the array by member functions
  // SendToTransmitter() and SendToTransmitterFirst() and
  // pulled from the array by the send/receive loop in
  // the worker thread.

  // Description of a function to call with the transmitter's answer or error status
  //  - callback( object ref, receive_buffer, receive_buffer_len ) === success
  //  - callback( object ref, nullptr, 0 ) === command failed/rejected
  //  - callback( object ref, nullptr, 1 ) === login rejected
  //  - callback( object ref, nullptr, 2 ) === login timed out
  typedef void(*transmit_callback)(class openGalaxy&, char*, int);

private:
  class TransmitSiaBlock {
  public:
    SiaBlock::FunctionCode fc;  // Function code
    char *data;                 // Data payload
    int len;                    // Length of data member in bytes
    transmit_callback callback; // The function to call with the transmitters answer or error status

    TransmitSiaBlock(SiaBlock::FunctionCode c, const char *data_ptr, size_t data_size, transmit_callback cb){
      fc = c;
      data = (char*)thread_safe_malloc(data_size);
      memcpy(data, data_ptr, data_size);
      len = data_size;
      callback = cb;
    }
    ~TransmitSiaBlock() {
      if(data) thread_safe_free(data);
    }
  };

  // Maximum number of times to retry sending a SIA datablock
  constexpr static const int retry_max = SiaBlock::block_retries;

  class openGalaxy& m_openGalaxy;    // our openGalaxy instance
  std::thread *m_thread;             // the worker thread for this receiver instance
  std::mutex m_mutex;                // data mutex (protecting variable 'transmit_list')
  std::mutex m_request_mutex;        // mutex and condition variable used to timeout and wakeup the worker thread
  std::condition_variable m_request_cv;

  volatile bool wait_write = false;  // true while a SIA block is being received, used to block sending data to the reveiver
  volatile bool waiting = false;     // True while we are waiting for a response from the transmitter
  volatile bool rejected = false;    // True when the transmitter rejected the SIA block
  volatile bool success = false;     // True when the transmitter accepted the SIA block
  volatile bool extended = false;    // True when the transmitter returned an extended datablock (function code 'X')

  ObjectArray<TransmitSiaBlock*> transmit_list; // A list of commands yet to be send to the transmitter
  unsigned char receive_buffer[256]; // buffer with received SIA data
  int receive_buffer_len = 0;        // number of bytes presently stored in receive_buffer

  static char *filter_non_printable(char* str, int len);
  static void Thread(class Receiver* receiver);

public:

  // constructor/destructor

  Receiver(class openGalaxy& opengalaxy);
  ~Receiver();

  // public member functions

  bool send(SiaBlock::FunctionCode fc, char *data, int len, transmit_callback);
  bool sendFirst(SiaBlock::FunctionCode fc, char *data, int len, transmit_callback);
  bool isTransmitting();
  bool IsReceiving();

  // These are called from class SIA when it receives a(n) Ack/Reject/Config/Control/Extended datablock
  void TriggerAcknoledge();
  void TriggerReject();
  void TriggerConfiguration();
  void TriggerControl(char *msg);
  void TriggerExtended(char *msg, size_t len);

  // Notifies the worker thread to break the current delay loop and immediately start the next loop iteration
  void notify() { m_request_cv.notify_one(); }

  // joins the thread (used by openGalaxy::exit)
  void join() { m_thread->join(); }

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }
}; // ends class Receiver

} // ends namespace openGalaxy

#endif

