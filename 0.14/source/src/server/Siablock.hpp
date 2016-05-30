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

#ifndef __OPENGALAXY_SERVER_SIABLOCK_HPP__
#define __OPENGALAXY_SERVER_SIABLOCK_HPP__

#include "atomic.h"
#include <string>
#include <cstring>

namespace openGalaxy {

// this class describes a single SIA (data) block
class SiaBlock {
public:
  constexpr static const int datablock_max = 63; // Max nr of bytes in a SIA data block
  constexpr static const int block_overhead = 3; // Nr of overhead bytes in a SIA block
  constexpr static const int block_max = (datablock_max + block_overhead); // Max nr of bytes in a SIA block
  constexpr static const unsigned char blockheader_length_mask = 63;// Bitmask to get the SIA block length from the SIA block header.
  constexpr static const unsigned char blockheader_flag_ack_request = 0x40;
  constexpr static const unsigned char blockheader_flag_reverse_chn = 0x80;
  constexpr static const int block_retries = 4; // the number of times to keep trying to send data

  // Data Acknoledgements
  // - After a block with an acknoledgement request has been send, the TX should wait no more
  //   then 2.5 seconds. Failure to respond should be handled as a communications error.
  constexpr static const int block_ack_timeout_ms = 2000; // (use a little less, specs above are for telephone lines)

  enum class FunctionCode : unsigned char {
    // System blocks
    end_of_data        = 0x30,
    wait               = 0x31,
    abort              = 0x32,
    res_3              = 0x33,
    res_4              = 0x34,
    res_5              = 0x35,
    ack_and_standby    = 0x36,
    ack_and_disconnect = 0x37,
    acknoledge         = 0x38,
    alt_acknoledge     = 0x08,
    reject             = 0x39,
    alt_reject         = 0x09,
    // Info blocks
    control            = 0x43,
    environmental      = 0x45,
    new_event          = 0x4E,
    old_event          = 0x4F,
    program            = 0x50,
    // Special blocks
    configuration      = 0x40,
    remote_login       = 0x3F,
    account_id         = 0x23,
    origin_id          = 0x26,
    ascii              = 0x41,
    extended           = 0x58,
    listen_in          = 0x4C,
    vchn_request       = 0x56,
    vchn_frame         = 0x76,
    video              = 0x49
  };

  union HeaderByte {
    unsigned char data;
    struct {
      unsigned char block_length :6;
      unsigned char acknoledge_request :1;
      unsigned char reverse_channel_enable :1;
    };
  };

  union BlockData {
    unsigned char data[block_max];
    struct {
      HeaderByte header;
      FunctionCode function_code;
      unsigned char message[datablock_max];
      unsigned char parity;
    };
  };

  // the block data
  BlockData block;

  void Erase(){
    block.header.data = 0;
    block.function_code = (FunctionCode)0;
    memset(block.message, 0, datablock_max);
    block.parity = 255;
  }

  // constructor
  SiaBlock(){ Erase(); }

  // (re)generate the parity field
  void GenerateParity(){
    block.parity = 0xFF;
    block.parity ^= block.header.data;
    block.parity ^= (unsigned char)block.function_code;
    for(size_t i=0; i<block.header.block_length; i++){
      block.parity ^= block.message[i];
    }
  }

  // test if function_code contains a valid function code
  bool IsFunctionCode();

  // convert a function code into a human readable string
  const char* FunctionCodeToString(std::string& str);
};

} // ends namespace openGalaxy

#endif

