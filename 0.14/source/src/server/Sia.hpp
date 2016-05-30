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

#ifndef __OPENGALAXY_SERVER_SIA_HPP__
#define __OPENGALAXY_SERVER_SIA_HPP__

#include "atomic.h"
#include <thread>
#include <mutex>
#include <condition_variable>

#include "Array.hpp"
#include "SiaEvent.hpp"

#include "opengalaxy.hpp"

namespace openGalaxy {


class SIA {
private:
  // points to our openGalaxy object
  class openGalaxy& m_openGalaxy;

  // An array of all possible SiaEventCode's
  Array<SiaEventCode*> m_SiaEvents;

  // Fills the m_SiaEvents array (called from constructor)
  void fillSiaEventCodeArray(void);

  // SIA::Decode() uses this buffer to store incoming data
  unsigned char sia_buffer[SiaBlock::block_max*2];

  // Used by SIA::Decode() to see how many bytes are left in the in-buffer,
  int sia_buffer_counter = 0;

  // SIA level of the transmitter (value is autodetected by received configuration blocks)
  int sia_level = 2;

  // Used by SIA::Decode() to as temporary storage
  class SiaBlock remember_me;
  class SiaEvent sia_current, sia_prev;

public:

  // Used by ReceiverThreadsMain() to check if we are in the middle of receiving
  // a message (ie. account block + event block [ + asci block ])
  // Set by SIA::Decode()
  bool sia_current_HaveAccountID=false;

  // SIA DATA groups
  // ---------------
  //
  // - Data groups are multiple blocks of data that are send or received without
  //   individual acknoledgements.
  //
  // - The total number of bytes transmitted (excluding header, function and parity bytes)
  //   must not exceed 500 for TX to RX communications and
  //   300 for RX to TX communications
  constexpr static const int datagroup_tx_max = 500; //#define SIA_DATAGROUP_TX_MAX 500
  constexpr static const int datagroup_rx_max = 300; //#define SIA_DATAGROUP_RX_MAX 300

  // Block Timing, Blocks in data groups may be seperated by a maximum of 4 seconds.
  constexpr static const int datagroup_block_timeout_ms = 4000; //#define SIA_DATAGROUP_BLOCK_TIMEOUT_MS 4000

  // TODO: move this to SiaEvent
  constexpr static const unsigned char packet_separator = 0x2F; // #define SIA_CODEPACKET_SEPARATOR 0x2F

  // constructor
  SIA(openGalaxy& opengalaxy);

  void SetLevel(int lvl);
  int GetLevel();
  bool SendBlock(SiaBlock& b);
  bool SendBlock_AcknoledgeAndStandby();
  bool SendBlock_AcknoledgeAndDisconnect();
  bool SendBlock_Acknoledge();
  bool SendBlock_Reject();
  bool SendBlock_RemoteLogin();
  bool SendBlock_Configuration();
  bool DecodeBlock_EndOfData();
  bool DecodeBlock_Wait();
  bool DecodeBlock_Abort();
  bool DecodeBlock_Reserved();
  bool DecodeBlock_AcknoledgeAndStandby();
  bool DecodeBlock_AcknoledgeAndDisconnect();
  bool DecodeBlock_Acknoledge();
  bool DecodeBlock_Reject();
  bool DecodeBlock_Control();
  bool DecodeBlock_Environmental();
  bool DecodeBlock_NewEvent();
  bool DecodeBlock_OldEvent();
  bool DecodeBlock_Program();
  bool DecodeBlock_Configuration();
  bool DecodeBlock_RemoteLogin();
  bool DecodeBlock_AccountId();
  bool DecodeBlock_OriginId();
  bool DecodeBlock_ASCII();
  bool DecodeBlock_Extended();
  bool DecodeBlock_ListenIn();
  bool DecodeBlock_VideoChannelRequest();
  bool DecodeBlock_VideoChannelFrame();
  bool DecodeBlock_Video();
  bool DecodePacket(std::string& packet);
  SiaEvent* Decode(unsigned char* data, size_t size);

  // Provide a method that refers to the top openGalaxy class
  inline class openGalaxy& opengalaxy(){ return m_openGalaxy; }
};

} // ends namespace openGalaxy

#endif

