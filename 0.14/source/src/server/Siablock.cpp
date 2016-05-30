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

/*******************************************************************************

          Sia.cpp - Decode SIA DC-03-1990.01 (R2000.11) messages

********************************************************************************

 The routines in this file work together to decode SIA (level 2...4)
 messages. Although these function are geared towards implementing a complete
 SIA decoder, currently only enough functionality to listen to 'Galaxy'
 security control panels is implemented. No other devices have been tested.

*******************************************************************************/

#include "atomic.h"

#include "Siablock.hpp"

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>

namespace openGalaxy {

// returns true if 'function_code' is a valid SIA function code
bool SiaBlock::IsFunctionCode()
{
  if(block.function_code==FunctionCode::alt_acknoledge) return true;
  if(block.function_code==FunctionCode::alt_reject) return true;
  if(block.function_code==FunctionCode::acknoledge) return true;
  if(block.function_code==FunctionCode::reject) return true;
  if(block.function_code==FunctionCode::account_id) return true;
  if(block.function_code==FunctionCode::new_event) return true;
  if(block.function_code==FunctionCode::old_event ) return true;
  if(block.function_code==FunctionCode::ascii ) return true;
  if(block.function_code==FunctionCode::extended ) return true;
  if(block.function_code==FunctionCode::ack_and_standby ) return true;
  if(block.function_code==FunctionCode::ack_and_disconnect) return true;
  if(block.function_code==FunctionCode::end_of_data) return true;
  if(block.function_code==FunctionCode::wait) return true;
  if(block.function_code==FunctionCode::abort) return true;
  if(block.function_code==FunctionCode::control) return true;
  if(block.function_code==FunctionCode::environmental) return true;
  if(block.function_code==FunctionCode::program) return true;
  if(block.function_code==FunctionCode::configuration) return true;
  if(block.function_code==FunctionCode::remote_login) return true;
  if(block.function_code==FunctionCode::origin_id) return true;
  if(block.function_code==FunctionCode::listen_in) return true;
  if(block.function_code==FunctionCode::vchn_request) return true;
  if(block.function_code==FunctionCode::vchn_frame) return true;
  if(block.function_code==FunctionCode::video) return true;
  if(block.function_code==FunctionCode::res_3) return true;
  if(block.function_code==FunctionCode::res_4) return true;
  if(block.function_code==FunctionCode::res_5) return true;
  return false;
}

// Converts a SIA function code to a human readable string
const char*  SiaBlock::FunctionCodeToString(std::string& str)
{
  if(IsFunctionCode()){
    switch(block.function_code){
      case SiaBlock::FunctionCode::end_of_data:
        str.assign("End of data");
        break;
      case SiaBlock::FunctionCode::wait:
        str.assign("Wait");
        break;
      case SiaBlock::FunctionCode::abort:
        str.assign("Abort");
        break;
      case SiaBlock::FunctionCode::res_3:
      case SiaBlock::FunctionCode::res_4:
      case SiaBlock::FunctionCode::res_5:
        str.assign("Reserved");
        break;
      case SiaBlock::FunctionCode::ack_and_standby:
        str.assign("Acknoledge and stand-by");
        break;
      case SiaBlock::FunctionCode::ack_and_disconnect:
        str.assign("Acknoledge and disconnect");
        break;
      case SiaBlock::FunctionCode::acknoledge:
      case SiaBlock::FunctionCode::alt_acknoledge:
        str.assign("Acknoledge");
        break;
      case SiaBlock::FunctionCode::reject:
      case SiaBlock::FunctionCode::alt_reject:
        str.assign("Reject");
        break;

      /// Info Data Blocks
      case SiaBlock::FunctionCode::control:
        str.assign("Control");
        break;
      case SiaBlock::FunctionCode::environmental:
        str.assign("Environmental");
        break;
      case SiaBlock::FunctionCode::new_event:
        str.assign("New event");
        break;
      case SiaBlock::FunctionCode::old_event:
        str.assign("Old event");
        break;
      case SiaBlock::FunctionCode::program:
        str.assign("Program");
        break;

      /// Special Data Blocks
      case SiaBlock::FunctionCode::configuration:
        str.assign("Configuration");
        break;
      case SiaBlock::FunctionCode::remote_login:
        str.assign("Remote login");
        break;
      case SiaBlock::FunctionCode::account_id:
        str.assign("Account ID");
        break;
      case SiaBlock::FunctionCode::origin_id:
        str.assign("Origin ID");
        break;
      case SiaBlock::FunctionCode::ascii:
        str.assign("ASCII");
        break;
      case SiaBlock::FunctionCode::extended:
        str.assign("Extended data");
        break;
      case SiaBlock::FunctionCode::listen_in:
        str.assign("Listen in");
        break;
      case SiaBlock::FunctionCode::vchn_request:
        str.assign("Video channel request");
        break;
      case SiaBlock::FunctionCode::vchn_frame:
        str.assign("Video channel frame data");
        break;
      case SiaBlock::FunctionCode::video:
        str.assign("Video");
        break;
    }
  }
  else {
    return nullptr;
  }
  return str.c_str();
}

} // ends namespace openGalaxy

