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

#include <thread>
#include <mutex>
#include <condition_variable>

#include "opengalaxy.hpp"

#include "Syslog.hpp"
#include "Settings.hpp"
#include "Receiver.hpp"

namespace openGalaxy {

Receiver::Receiver(openGalaxy& opengalaxy) : m_openGalaxy(opengalaxy)
{
  // Create a new instance of the receiver thread
  m_thread = new std::thread(Receiver::Thread, this);
}

Receiver::~Receiver()
{
  delete m_thread;
}

// Send any type of SIA block to the transmitter
//
// fc       = SIA function code
// data     = data to send (may include \0 bytes)
// len      = length of data in bytes
// callback = function to call with error status or data returned by the transmitter
bool Receiver::send(SiaBlock::FunctionCode fc, char *data, int len, Receiver::transmit_callback callback)
{
  if( data==nullptr ){
    throw new std::runtime_error("Receiver::send(): data = null.");
  }
  if( callback==nullptr ){
    throw new std::runtime_error("Receiver::send(): callback = null.");
  }
  if( len<0 ){
    throw new std::runtime_error("Receiver::send(): len < 0.");
  }
  m_mutex.lock();
  transmit_list.append(new TransmitSiaBlock(fc, data, len, callback));
  m_mutex.unlock();
  opengalaxy().syslog().debug("Receiver: Command que append: %s", filter_non_printable(data,len));
  return true;
}

// Send any type of SIA block to the transmitter at the first opportunity (for use from another thread)
//
// fc       = SIA function code
// data     = data to send (may include \0 bytes)
// len      = length of data in bytes
// callback = function to call with error status or data returned by the transmitter
bool Receiver::sendFirst(SiaBlock::FunctionCode fc, char *data, int len, Receiver::transmit_callback callback)
{
  if( data==nullptr ){
    throw new std::runtime_error("Receiver::sendFirst(): data = null.");
  }
  if( callback==nullptr ){
    throw new std::runtime_error("Receiver::sendFirst(): callback = null.");
  }
  if( len<0 ){
    throw new std::runtime_error("Receiver::sendFirst(): len < 0.");
  }
  m_mutex.lock();
  transmit_list.prepend(new TransmitSiaBlock(fc, data, len, callback));
  m_mutex.unlock();
  opengalaxy().syslog().debug("Receiver: Command que prepend: %s", filter_non_printable(data,len));
  return true;
}

// return true when transmit_list is not empty (ie. we are sending data)
bool Receiver::isTransmitting()
{
  bool retv = false;
  m_mutex.lock();
  if(transmit_list.size() > 0) retv = true;
  m_mutex.unlock();
  return retv;
}


// return true when we are receiving data
bool Receiver::IsReceiving()
{
  bool retv = false;
  m_mutex.lock();
  if(wait_write == true) retv = true;
  if(waiting == true) retv = true;
  m_mutex.unlock();
  return retv;
}

// Called by SIA::Decode() when a SIA positive acknoledge block was received
void Receiver::TriggerAcknoledge()
{
  if(waiting == true){
    waiting = false;
    rejected = false;
    extended = false;
    success = true;
  }
}

// Called by SIA::Decode() when a SIA reject block was received
void Receiver::TriggerReject()
{
  if(waiting == true){
    waiting = false;
    rejected = true;
    extended = false;
    success = false;
  }
}

// Called by SIA::Decode() when a SIA configuration block was received
void Receiver::TriggerConfiguration()
{
  if(waiting == true){
    waiting = false;
    rejected = false;
    extended = false;
    success = false; // not the final block
  }
}

// Called by SIA::Decode() when a SIA control block was received
void Receiver::TriggerControl(char *msg)
{
  if(waiting == true){
    waiting = false;
    rejected = false;
    extended = false;
    success = true;
    memset(receive_buffer, 0, sizeof(receive_buffer));
    strncpy((char*)receive_buffer, msg, sizeof(receive_buffer)-1);  
    receive_buffer_len = strlen((char*)receive_buffer);
  }
  opengalaxy().syslog().debug("Receiver: Received from panel: C: %s", filter_non_printable(msg, strlen(msg)));
}

// Called by SIA::Decode() when a SIA extended block was received
void Receiver::TriggerExtended(char *msg, size_t len )
{
  if(waiting == true){
    waiting = false;
    rejected = false;
    extended = true;
    success = true;
    memset(receive_buffer, 0xFF, sizeof(receive_buffer));
    memcpy(receive_buffer, msg, (len > sizeof(receive_buffer)) ? sizeof(receive_buffer) : len);
    receive_buffer_len = len;
  }
  opengalaxy().syslog().debug("Receiver: Received from panel: X: %s", filter_non_printable(msg, len));
}

// helper function that filters non-printable characters from a C string.
// unprintable character are replaced with the '.' character.
char *Receiver::filter_non_printable(char* str, int len)
{
  static char buf[SiaBlock::datablock_max+1];
  int l = ( len <= SiaBlock::datablock_max ) ? len : SiaBlock::datablock_max;
  memset(buf, 0, SiaBlock::datablock_max+1);
  memcpy(buf, str, l);
  for(int t=0; t<l; t++) if(!(buf[t] & 0x60)) buf[t] = '.';
  return buf;
}

/*
// prints the content of sia_buffer
static void pbuffer(const unsigned char *buf, int l)
{
  int t, c=0;
  unsigned char b16[16];
  for( int t=0; t<l; t++) {
    printf(  "%02X ", buf[t] );
    b16[c++]=buf[t];
    if( c==16 ){
      printf(
        "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
        (b16[0]>31 && b16[0]<127) ? b16[0] : '.' ,
        (b16[1]>31 && b16[1]<127) ? b16[1] : '.' ,
        (b16[2]>31 && b16[2]<127) ? b16[2] : '.' ,
        (b16[3]>31 && b16[3]<127) ? b16[3] : '.' ,
        (b16[4]>31 && b16[4]<127) ? b16[4] : '.' ,
        (b16[5]>31 && b16[5]<127) ? b16[5] : '.' ,
        (b16[6]>31 && b16[6]<127) ? b16[6] : '.' ,
        (b16[7]>31 && b16[7]<127) ? b16[7] : '.' ,
        (b16[8]>31 && b16[8]<127) ? b16[8] : '.' ,
        (b16[9]>31 && b16[9]<127) ? b16[9] : '.' ,
        (b16[10]>31 && b16[10]<127) ? b16[10] : '.' ,
        (b16[11]>31 && b16[11]<127) ? b16[11] : '.' ,
        (b16[12]>31 && b16[12]<127) ? b16[12] : '.' ,
        (b16[13]>31 && b16[13]<127) ? b16[13] : '.' ,
        (b16[14]>31 && b16[14]<127) ? b16[14] : '.' ,
        (b16[15]>31 && b16[15]<127) ? b16[15] : '.'
      );
      c=0;
    }
  }
	
  if( c!=0 ){
    for(  t=c; t<16;t++ ) printf(  "-- "  );
    for( int t=0; t<c; t++ ){
      printf("%c",(b16[t]>31 && b16[t]<127) ? b16[t] : '.' );
    }
    printf( "\n" );
  }
}
*/

// the main() function for (all) the receiver thread(s)
void Receiver::Thread(Receiver* receiver)
{
  using namespace std::chrono;
  try {

    unsigned char buf[256];          // rs232 received data
    bool wait_login = false;         // true when a login block has been send and we are waiting for a response (config or reject block)
    bool wait_fc = false;            // true when a block has been send and we are waiting for a response
    int retry = 0;                   // The number of times a command was retried

    high_resolution_clock::time_point
      tpStart, tpEnd,                // used to time how long it takes to do a single send/receive loop
      tpTimeoutStart, tpTimeoutEnd;  // used to detect timeouts while sending data

    int loop_delay_ms_default = 100; // (maximum) time in between consecutive send/receive loop iterations (milliseconds)
    int loop_delay_ms_minimum = 50; // minimum time in between consecutive send/receive loop iterations (milliseconds)

    // current time in between consecutive send/receive loop iterations (milliseconds)
    int loop_delay_ms = loop_delay_ms_default;

    std::unique_lock<std::mutex> lck(receiver->m_request_mutex);

    // Loop here until quitting time
    while(receiver->opengalaxy().isQuit()==false){
      // (When running on Windows (MSYS/MinGW) the previous while() also seems to fix a strange issue
      // where m_request_cv is notified a lot of times by somebody other then us!?
      // That in turn causes the program to break out of the next while loop)
      //
      // Start the main send/receive loop.
      //
      // This loop sleeps for 'loop_delay_ms' milliseconds before timing out and starting a new loop iteration.
      // At the end of each loop, the time it took to execute (it) is calculated and subtracted from the
      // 'loop_delay_ms_default' delay value. That new delay value is used to time the next loop iteration.
      // This new delay shal not be smaller then 'loop_delay_ms_minimum'.
      // While the thread is waiting for a response to a command that was send the 'loop_delay_ms_minimum' is used.
      //
      // A std::condition_variable (and associated std::mutex) is used to time the loop.
      //
      while(receiver->m_request_cv.wait_for(lck,milliseconds(loop_delay_ms))==std::cv_status::timeout){

        // Begin timing this send/receive loop iteration
        tpStart = high_resolution_clock::now();

        // Test if we need to exit the thread.
        if(receiver->opengalaxy().isQuit()==true) break;

        // Lock our (data access) mutex
        receiver->m_mutex.lock();

        // Read a maximum of 255 bytes from the serial port
        // (this function is non-blocking)
        size_t l = receiver->opengalaxy().serialport().read(buf, 255);

        // Received at least 1 byte?
        if(l > 0){
          //pbuffer(buf, l);
          // Yes, so decode the data.
          SiaEvent *sia = receiver->opengalaxy().sia().Decode(buf, l);
          // Complete SIA message decoded?
          if ( sia != nullptr ){
            std::string fc;
            receiver->opengalaxy().syslog().info("Receiver: %s (0x%02X) %s %s", sia->raw.FunctionCodeToString(fc), sia->raw.block.function_code, sia->raw.block.message, sia->ascii.data());
            // Yes, a complete message was received, send it to the output thread
            receiver->opengalaxy().output().write(*sia);
            // No more need to keep the message, free it's memory
            delete sia; sia = nullptr;
          }
        }
        else {
          // No, we have not received any data...
          //
          // Are we currently blocking writes, or in the middle of receiving a message?
          if((receiver->wait_write == false) && (receiver->opengalaxy().sia().sia_current_HaveAccountID == false)){
            // Not blocking writes
            //
            // Are we waiting for the response to a remote login block send earlier?
            if(wait_login==true){
              // Yes we are waiting for a configuration block, did we receive a configuration or reject block?
              if(receiver->waiting==false){
                // Yes, accepted or reject?
                wait_login = false;
                if(receiver->rejected==true){
                  // Rejected, remove the transmit_list entry after retry_max retries
                  receiver->opengalaxy().syslog().error("Receiver: Remote login attempt rejected, trying again... (%u)", retry);
                  retry++;
                  if(retry>receiver->retry_max){
                    if(receiver->transmit_list.size()>0){
                      receiver->opengalaxy().syslog().error("Receiver: Remote login attempt rejected, droppping command!");
                      receiver->transmit_list[0]->callback(receiver->m_openGalaxy,nullptr,1);
                      receiver->transmit_list.remove(0);
                    }
                  }
                }
                else {
                  // Accepted, send the topmost command in the transmit_list
                  SiaBlock siablock;
                  siablock.block.function_code = receiver->transmit_list[0]->fc;
                  siablock.block.header.block_length = receiver->transmit_list[0]->len;
                  siablock.block.header.acknoledge_request = 1;
                  memcpy(
                    siablock.block.message,
                    receiver->transmit_list[0]->data,
                    receiver->transmit_list[0]->len
                  );
                  siablock.GenerateParity();

                  wait_fc = true;
                  receiver->waiting = true;
                  receiver->rejected = true;
                  receiver->success = false;
                  receiver->extended = false;

                  receiver->opengalaxy().syslog().debug("Receiver: Sending command: %s", filter_non_printable((char*)siablock.block.message, siablock.block.header.block_length));
                  if(receiver->opengalaxy().sia().SendBlock(siablock)==false){
                    wait_fc = false;
                    receiver->waiting = false;
                    receiver->opengalaxy().syslog().error("Receiver: Failed to send a command to the transmitter!");
                    receiver->transmit_list.remove(0);
                  }
                  // Start a new timer to calculate when waiting for
                  // the response to the block we just send times out.
                  retry = 0;
                  tpTimeoutStart = high_resolution_clock::now();
                }
              }
              else {
                // No we did not receive a configuration/reject block but are waiting for one.
                //
                // Did we timeout while waiting for the configuration/reject block?
                tpTimeoutEnd = high_resolution_clock::now();
                duration<long long,std::milli> delta = duration_cast<duration<long long,std::milli>>(tpTimeoutEnd-tpTimeoutStart);
                if((delta.count()<0)||(delta.count()>=SiaBlock::block_ack_timeout_ms)){
                  // Yes
                  retry++;
                  if(retry>=receiver->retry_max){           
                    receiver->opengalaxy().syslog().error("Receiver: Remote login timed out after %d milliseconds, dropping command... (%d)", delta.count(), retry);
                    // Notify the callback function accociated with the command we send.
                    if(receiver->transmit_list.size()>0){
                      receiver->transmit_list[0]->callback(receiver->m_openGalaxy,nullptr,2);
                      receiver->transmit_list.remove(0);
                    }
                    retry = 0;
                  }
                  else {
                    receiver->opengalaxy().syslog().error("Receiver: Remote login timed out after %d milliseconds, trying again... (%u)", delta.count(), retry);
                  }
                  wait_login = false;
                  receiver->waiting = false;
                }
                // No, we did not timeout while waiting for a configuartion/reject block but are still waiting...
              }
            }
            // No we are not blocking write (and have not received any data)
            //
            // Are we waiting for the response to a command (SIA block) we last send (ie. after the login was accepted)?
            else if(wait_fc==true){
              // Yes, did we receive a response (via one of the 'trigger' functions)?
              if(receiver->waiting==false){
                // Yes, success or failure?
                if(receiver->success==true){
                  // Success!
                  // Pass the received data to the callback function accociated with the command we send.
                  receiver->transmit_list[0]->callback(receiver->m_openGalaxy,(char*)receiver->receive_buffer,receiver->receive_buffer_len);
                  receiver->receive_buffer_len = 0;
                }
                else {
                  // Failure!
                  receiver->opengalaxy().syslog().error("Receiver: Command execution failed!" );
                  // Notify the callback function accociated with the command we send.
                  receiver->transmit_list[0]->callback(receiver->m_openGalaxy,nullptr,0);
                }
                retry = 0;
                receiver->transmit_list.remove(0);
              }
              else {
                // No response to the (last send) command, did we timeout?
                tpTimeoutEnd = high_resolution_clock::now();
                duration<long long,std::milli> delta = duration_cast<duration<long long,std::milli>>(tpTimeoutEnd-tpTimeoutStart);
                if((delta.count() < 0) || (delta.count() >= SiaBlock::block_ack_timeout_ms)){
                  // Yes, do nothing and try (to login) again on the next loop..
                  retry++;
                  receiver->opengalaxy().syslog().debug("Receiver: Sending command timed out after %d milliseconds, trying again... (%u)", delta.count(),retry);
                  receiver->waiting = false;
                }
                // No, wait some more
              }
              wait_fc = false; 
            }
            //
            // We are not receiving data or waiting for anything,
            //  start sending the next command in the list (if any)
            //
            else if(receiver->transmit_list.size() > 0){
              receiver->opengalaxy().poll().pauze();
              memset(receiver->receive_buffer, 0, sizeof(receiver->receive_buffer));
              receiver->receive_buffer_len = 0;
              receiver->waiting = true;
              receiver->rejected = true;
              receiver->success = false;
              wait_login = true;
              receiver->opengalaxy().sia().SendBlock_RemoteLogin();
              tpTimeoutStart = high_resolution_clock::now();
            }
            else receiver->opengalaxy().poll().resume();
          }
        }

        // If we are waiting for a response then use the minimum delay value for loop_delay_ms
        if(receiver->waiting==true){
          loop_delay_ms = loop_delay_ms_minimum;
        }
        else {
          // Calculate how long it took to do this send/receive loop iteration
          tpEnd = high_resolution_clock::now();
          duration<long long,std::milli> time_span_ms = duration_cast<duration<long long,std::milli>>(tpEnd - tpStart);

          // Prepare the (new) timeout for sleeping
          if(time_span_ms.count() >= 0 && time_span_ms.count() < loop_delay_ms_default){
            loop_delay_ms = loop_delay_ms_default - time_span_ms.count();
            if(loop_delay_ms < loop_delay_ms_minimum) loop_delay_ms = loop_delay_ms_minimum;
          }
          else loop_delay_ms = loop_delay_ms_minimum;
        }    

        // unlock the (data access) mutex while we are sleeping
        receiver->m_mutex.unlock();
      } // Ends send/receive loop iteration

    } // Ends while ! opengalaxy().isQuit()

    // Free any entries left in transmit_list
    while(receiver->transmit_list.size()>0) receiver->transmit_list.remove(0);

    receiver->opengalaxy().syslog().debug("Receiver::Thread exited normally");
  }
  catch(...){
    // pass the exception on to the main() thread
    receiver->opengalaxy().m_Receiver_exptr = std::current_exception();
    receiver->opengalaxy().exit();
  }
}

} // ends namespace openGalaxy

