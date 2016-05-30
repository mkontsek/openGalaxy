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

#include "Syslog.hpp"
#include "Settings.hpp"
#include "Siablock.hpp"
#include "SiaEvent.hpp"
#include "Sia.hpp"

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>

namespace openGalaxy {

SIA::SIA(openGalaxy& opengalaxy) : m_openGalaxy(opengalaxy) {
  fillSiaEventCodeArray();
  SetLevel(2);
  sia_current_HaveAccountID = false;
  if( m_openGalaxy.settings().sia_use_alt_control_blocks != 0 ){
    m_openGalaxy.syslog().info("Info: Using alternative SIA acknoledge and reject blocks");
  }
}

void SIA::SetLevel(int lvl)
{
  if( lvl != sia_level ){
    opengalaxy().syslog().debug("SIA: Level autodetect: %d", lvl);
    sia_level = lvl;
  }
}

int SIA::GetLevel()
{
  return sia_level;
}

// Send a block to the transmitter
bool SIA::SendBlock(SiaBlock& sia)
{
  size_t n;
  // Fill a buffer with data to send to the serial port
  unsigned char buffer[sia.block.header.block_length + SiaBlock::block_overhead];
  unsigned char *p = buffer;
  *p++ = sia.block.header.data;
  *p++ = (unsigned char)sia.block.function_code;
  for(size_t i=0; i<sia.block.header.block_length; i++){
    *p++ = sia.block.message[i];
  }
  *p = sia.block.parity;
  // Send the buffer to the serial port
  if(
    (n = opengalaxy().serialport().write(
      buffer,
      (size_t)(sia.block.header.block_length + SiaBlock::block_overhead)
    ))
    != (size_t)(sia.block.header.block_length + SiaBlock::block_overhead)
  ){
    // Log any failures
    std::string fc;
    if(!sia.FunctionCodeToString(fc)) fc.assign("unknown");
    opengalaxy().syslog().error(
      "Error: SIA::SendBlock('%s'[0x%02X]) failed after sending %d/%d bytes!",
      fc.c_str(),
      (unsigned char)sia.block.function_code,
      n, sia.block.header.block_length + SiaBlock::block_overhead
    );
    return false;
  }
  return true; 
}

// Send Aknoledge and Standby SIA block (6 block) to transmitter
bool SIA::SendBlock_AcknoledgeAndStandby()
{
  SiaBlock sia;
  sia.block.header.data = 0; // no data, no flags
  sia.block.function_code = SiaBlock::FunctionCode::ack_and_standby;
  sia.GenerateParity();
  return SendBlock(sia);
}

// Send Acknoledge and Disconnect SIA block (7 block) to transmitter
bool SIA::SendBlock_AcknoledgeAndDisconnect()
{
  SiaBlock sia;
  sia.block.header.data = 0; // no data, no flags
  sia.block.function_code = SiaBlock::FunctionCode::ack_and_disconnect;
  sia.GenerateParity();
  return SendBlock(sia);
}

// Send Acknoledge SIA block (8 block) to transmitter
bool SIA::SendBlock_Acknoledge()
{
  opengalaxy().syslog().debug("SIA: Sending Acknoledge");
  SiaBlock sia;
  sia.block.header.data = 0; // no data, no flags
  sia.block.function_code = 
    (opengalaxy().settings().sia_use_alt_control_blocks) ?
      SiaBlock::FunctionCode::alt_acknoledge : SiaBlock::FunctionCode::acknoledge;
  sia.GenerateParity();
  return SendBlock(sia);
}

// Send Reject SIA block (9 block) to transmitter
bool SIA::SendBlock_Reject()
{
  opengalaxy().syslog().debug("SIA: Sending Reject");
  SiaBlock sia;
  sia.block.header.data = 0; // no data, no flags
  sia.block.function_code = 
    (opengalaxy().settings().sia_use_alt_control_blocks) ?
      SiaBlock::FunctionCode::alt_reject : SiaBlock::FunctionCode::reject;
  sia.GenerateParity();
  return SendBlock(sia);
}

// Send Remote Login SIA block to transmitter
bool SIA::SendBlock_RemoteLogin()
{
  SiaBlock sia;
  sia.block.header.block_length = opengalaxy().settings().remote_code.length();
  sia.block.header.acknoledge_request = 1;
  sia.block.function_code = SiaBlock::FunctionCode::remote_login;
  memcpy(
    sia.block.message,
    opengalaxy().settings().remote_code.data(),
    opengalaxy().settings().remote_code.length()
  );
  sia.GenerateParity();
  return SendBlock(sia);
}

// Send Configuration SIA block to transmitter
bool SIA::SendBlock_Configuration()
{
  std::string msg = "AL4B1";
  SiaBlock sia;
  sia.block.header.block_length = msg.length();
  sia.block.header.acknoledge_request = 1;
  sia.block.function_code = SiaBlock::FunctionCode::configuration;
  memcpy(
    sia.block.message,
    msg.data(),
    msg.length()
  );
  sia.GenerateParity();
  return SendBlock(sia);
}

bool SIA::DecodeBlock_EndOfData() 
{ 
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) System Block: End Of Data");
  return true;
}

bool SIA::DecodeBlock_Wait()
{ 
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) System Block: Wait");
  return true;
}

bool SIA::DecodeBlock_Abort()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) System Block: Abort");
  return true;
}

bool SIA::DecodeBlock_Reserved()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) System Block: Reserved");
  return true;
}

bool SIA::DecodeBlock_AcknoledgeAndStandby()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) System Block: Acknoledge And Standby");
  return true;
}

bool SIA::DecodeBlock_AcknoledgeAndDisconnect()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) System Block: Acknoledge And Disconnect");
  return true;
}

bool SIA::DecodeBlock_Acknoledge() 
{
  opengalaxy().syslog().debug("SIA: received Acknoledge");
  // Notify the receiver
  opengalaxy().receiver().TriggerAcknoledge();
  return true;
}

bool SIA::DecodeBlock_Reject()
{
  opengalaxy().syslog().debug("SIA: received Reject");
  // Notify the receiver
  opengalaxy().receiver().TriggerReject();
  return true;
}

bool SIA::DecodeBlock_Control()
{
  // Copy the data block to a C string and delegate further action to the receiver
  char str[sia_current.raw.block.header.block_length + 1];
  memcpy(str, sia_current.raw.block.message, sia_current.raw.block.header.block_length);
  str[sia_current.raw.block.header.block_length] = 0;
  opengalaxy().receiver().TriggerControl(str);
  return true;
}

bool SIA::DecodeBlock_Environmental()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Information Block: Environmental");
  return false;
}

bool SIA::DecodeBlock_NewEvent()
{
	std::string str;
  str.assign((char*)sia_current.raw.block.message, sia_current.raw.block.header.block_length);
  DecodePacket(str);
  return true;
}

bool SIA::DecodeBlock_OldEvent()
{
	std::string str;
  str.assign((char*)sia_current.raw.block.message, sia_current.raw.block.header.block_length);
  DecodePacket(str);
  return true;
}

bool SIA::DecodeBlock_Program()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Information Block: Program");
  return false;
}

bool SIA::DecodeBlock_Configuration()
{
  char *c;
  int t;

  // Copy the data block to a C string
  char str[ sia_current.raw.block.header.block_length + 1];
  memcpy(str, sia_current.raw.block.message, sia_current.raw.block.header.block_length);
  str[sia_current.raw.block.header.block_length ] = '\0';

  // Autodetect the sia_level, scan str for 'ALx'
  for(t=strlen(str), c=str; t>2; t--, c++){
    if(c[0] == 'A' && c[1] == 'L'){
      int i = c[2] - '0';
      if(sia_level < i) SetLevel(i);
    } 
  }

  // Notify the receiver
  opengalaxy().receiver().TriggerConfiguration();
  return true;
}

bool SIA::DecodeBlock_RemoteLogin()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Special Block: Remote Login");
  return false;
}

bool SIA::DecodeBlock_AccountId()
{ 
  if( sia_current_HaveAccountID == true ){
    // if we end up here, there must be a complete message in sia_current that has not been picked up by SIA_Decode(), so finish it up here
    opengalaxy().syslog().debug("SIA: Warning: Reveived an account id (%u), but we allready have one (replaced)", sia_current.accountId);
  }
  std::string str;
  str.assign((char*)sia_current.raw.block.message, sia_current.raw.block.header.block_length);
  sia_current.accountId = std::stoi(str, nullptr, 10);
  sia_current_HaveAccountID = true;
//  opengalaxy().syslog().debug("SIA: Account ID: %u", sia_current.accountId);
  return true; 
}

bool SIA::DecodeBlock_OriginId()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Special Block: Origin ID");
  return false;
}

bool SIA::DecodeBlock_ASCII()
{
  sia_current.ascii.assign((char*)sia_current.raw.block.message, sia_current.raw.block.header.block_length);
  sia_current.haveAscii = true;
//  opengalaxy().syslog().debug("SIA: ASCII: %s", sia_current.ascii.c_str());
  return true;
}

bool SIA::DecodeBlock_Extended()
{
  // Copy the data block to a C string
  char str[sia_current.raw.block.header.block_length + 1];
  memcpy(str, sia_current.raw.block.message, sia_current.raw.block.header.block_length);
  str[sia_current.raw.block.header.block_length] = 0;

  // Pass it back to the receiver
  opengalaxy().receiver().TriggerExtended(str, sia_current.raw.block.header.block_length);
  return true;
}

bool SIA::DecodeBlock_ListenIn()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Special Block: Listen-In" );
  return false;
}

bool SIA::DecodeBlock_VideoChannelRequest()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Special Block: Video Channel Request" );
  return false;
}

bool SIA::DecodeBlock_VideoChannelFrame()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Special Block: Video Channel Frame" );
  return false;
}

bool SIA::DecodeBlock_Video()
{
  opengalaxy().syslog().error("SIA: Cooked: TODO: Decode (incoming) Special Block: Video" );
  return false;
}

/// bool SIA::DecodePacket(std::string& packet)
///
/// Data Code Packets (aka. Event code)
/// -----------------------------------
///
/// TTAAAA*UUUUUUuu
///
/// TT     = Data Type Code (aka. Event code) (Always 2 characters A-Z)
/// AAAA   = Address Number (optional, ASCII representation of base 16 value, at least 1 character and a maximum of 4)
/// UUUUUU = Units Number (optional, presence indicated by *, ASCII representation of base 10 value, at least 1 character and a maximum of 6)
/// uu     = Unit Type (optional, Units Number must be present, 1 or 2 characters)
///
/// Note: Galaxy panels send the Address Number in base10 and in the Galaxy numbering format!!
///
/// Modifier Code Packets
/// ---------------------
///
/// Modifier code packets act as adjectives to describe the Data Code Packets to follow. Modifiers only act upon packets that follow the modifier itself and
/// occur whitin the same SIA block.
///
/// Modifier codes apply to all information block types (ie. Control, Environmental, Program, New Event and Old Event).
///
/// Date - the date on which an event took place.
/// daMM-DD-YY
/// MM is the month (01 -12), DD is the day (01 - 31), and YY is the year (least significant two dig­its).
/// Alternately, the day of week (1 - 7, Sun­day = 1) may be passed in the DD posi­tion if MM is set to zero.
/// All numbers are ASCII repre­sented, decimal numbers.
///
/// Time - the time at which an event took place.
/// tiHH:MM:SS
/// HH is hours (00 - 23), MM is minutes (00 - 59), and SS is sec­onds (00 - 59).  Seconds and the preceding ':' are optional.
///
/// Subscriber ID - the identity of the user causing the actions or events in­cluded in the current block.
/// idSSSS
/// SSSS is the subscriber number (0000 - 9999).  All numbers are ASCII repre­sented, decimal numbers.
/// Leading zeros may be in­cluded, but are not required.  
///
/// Area ID - the identity of a logical area causing the actions or events in­cluded in the current block.
/// riSSSS
/// SSSS is the area number (0000 - 9999).  All numbers are ASCII repre­sented, decimal numbers.
/// Leading zeros may be in­cluded, but are not required.
///
/// Peripheral ID - the identity of a physical device causing the actions or events included in the current block.
/// piSSSS
/// SSSS is the peripheral number (0000 - 9999).  All numbers are ASCII repre­sented, decimal numbers.
/// Leading zeros may be in­cluded, but are not required.  
///
/// Automated ID - the identity of a logical function or timer causing the actions or events in­cluded in the current block.
/// aiSSSS
/// SSSS is the automated number (0000 - 9999).  All numbers are ASCII repre­sented, decimal numbers.
/// Leading zeros may be in­cluded, but are not required.  
///
/// Telephone ID - the index of the telephone service number used when the follow­ing events occurred.
/// phXXXX
/// XXX is the index (0000 - 9999).  All numbers are ASCII repre­sented, decimal numbers.
/// Leading zeros may be in­cluded, but are not required.  
///
/// Level - used to indicate a state that has multiple, meaningful levels which can be quantitative or qualitative.
/// lvLLLL
/// LLLL is the level number (0000 - 9999).  All numbers are ASCII represented, decimal numbers.
/// Leading zeros may be included, but are not required.
///
/// Value - used to transmit a numerical value associated with the event code reported.
/// vaVVVV
/// VVVV is the value number (0000 - 9999).  All numbers are ASCII represented, decimal numbers.
/// Leading zeros may be included, but are not required.
///
/// Path - used to transmit which of multiple communications paths the event code relates to.
/// ptPPP
/// PPP is the path number (000 - 999).  All numbers are ASCII represented, decimal numbers.
/// Leading zeros may be included, but are not required.
///
/// Route Group - used to identify which of several communications path groupings (primary and secondary) has failed to communicate. 
/// rgGG
/// GG is the path number (00 -99).  All numbers are ASCII represented, decimal numbers.
/// Leading zeros may be included, but are not required.
///
/// Sub-Subscriber - user category number.
/// ssSSSS
/// SSSS is the number (0000 - 9999).  All numbers are ASCII represented, decimal numbers.
/// Leading zeros may be included, but are not required.
///
bool SIA::DecodePacket(std::string& packet)
{
//  opengalaxy().syslog().debug("SIA: Decoding packet: %s", packet.c_str());
	
  char code[3] = {0, 0, 0};
  int len = packet.length();
  const char *p = packet.data();

  // Sanity check: there should be at least 2 characters in the packet
  if(len < 2) return false;
	
  while(len >= 2){
    code[0] = *p++; // get the two digit data or modifier code:
    code[1] = *p++;
    len -= 2;
    //
    // ** decode event modifiers **
    //	  
    // Date modifier: daMM-DD-YY
    //
    if( code[0] == 'd' && code[1] == 'a' ){
      if( len >= 8 ){ // 8 chars must follow
        char MM[3]={0,0,0}, DD[3]={0,0,0}, YY[3]={0,0,0};
        MM[0] = *p++;
        MM[1] = *p++;
        p++;
        DD[0] = *p++;
        DD[1] = *p++;
        p++;
        YY[0] = *p++;
        YY[1] = *p++;
        len -= 8;
        sia_current.date.assign(atoi(MM), atoi(DD), atoi(YY));
        sia_current.haveDate = true;
//        opengalaxy().syslog().debug("SIA:  Date: %s", sia_current.date.get().c_str());
      }
      else { // not 8 chars, log and skip over separator
        opengalaxy().syslog().error("SIA:  Error, failed to decode date modifier");
        while(len != 0){
          char pp = *p++; len--;
          if(pp == SIA::packet_separator) break;
        }
      }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
    }
    // Time modifier: tiHH:MM:SS
    //
    else if (code[0]=='t' && code[1]=='i') {
      char HH[3]={0,0,0}, MM[3]={0,0,0}, SS[3]={0,0,0};
      HH[0] = *p++; // get HH
      HH[1] = *p++;
      if(*p == ':'){ p++; len--; } 
      MM[0] = *p++; // get MM
      MM[1] = *p++;
      len -= 4;
      if(len > 0 && *p != SIA::packet_separator){
        if(*p == ':'){ p++; len--; } 
        SS[0] = *p++; // get SS
        SS[1] = *p++;
        len -= 2;
      }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.time.assign(atoi(HH), atoi(MM), atoi(SS));
      sia_current.haveTime = true;
//      opengalaxy().syslog().debug("SIA:  Time: %s", sia_current.time.get().c_str());
    }
    // Subscriber ID (gebruiker ID): idSSSS
    //
    else if(code[0] == 'i' && code[1] == 'd'){
      char id[5] = {0,0,0,0,0};
      if(len > 0 ){ id[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ id[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ id[2] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ id[3] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.subscriberId = atoi(id);
      sia_current.haveSubscriberId = true;
//      opengalaxy().syslog().debug("SIA:  Subscriber ID: %u", sia_current.subscriberId );
    }
    // Area ID: riSSSS
    //
    else if(code[0] == 'r' && code[1] == 'i'){
      char ri[5] = {0,0,0,0,0};
      if(len >0){ ri[0] = *p++; len--; }
      if(len >0 && *p != SIA::packet_separator){ ri[1] = *p++; len--; }
      if(len >0 && *p != SIA::packet_separator){ ri[2] = *p++; len--; }
      if(len >0 && *p != SIA::packet_separator){ ri[3] = *p++; len--; }
      if(len >0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.areaId = atoi(ri);
      sia_current.haveAreaId = true;
//      opengalaxy().syslog().debug("SIA:  Area ID: %u", sia_current.areaId );
    }
    // Peripheral ID: piSSSS
    //
    else if(code[0] == 'p' && code[1] == 'i'){
      char pi[5] = { 0, 0, 0, 0, 0 };
      if(len > 0 ){ pi[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ pi[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ pi[2] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ pi[3] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.peripheralId = atoi(pi);
      sia_current.havePeripheralId = true;
//      opengalaxy().syslog().debug("SIA:  Peripheral ID: %u", sia_current.peripheralId);
    }
    // Automated ID: aiSSSS
    //
    else if(code[0] == 'a' && code[1] == 'i'){
      char ai[5] = { 0, 0, 0, 0, 0 };
      if(len > 0){ ai[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ai[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ai[2] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ai[3] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.automatedId = atoi(ai);
      sia_current.haveAutomatedId = true;
//      opengalaxy().syslog().debug("SIA:  Automated ID: %u", sia_current.automatedId);
    }
    // Telephone ID: phXXXX
    //
    else if(code[0] == 'p' && code[1] == 'h'){
      char ph[5] = {0,0,0,0,0};
      if(len > 0){ ph[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ph[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ph[2] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ph[3] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.telephoneId = atoi(ph);
      sia_current.haveTelephoneId = true;
//      opengalaxy().syslog().debug("SIA:  Telephone ID: %u", sia_current.telephoneId);
    }
    // Level: lvLLLL
    //
    else if(code[0] == 'l' && code[1] == 'v'){
      char lv[5] = {0,0,0,0,0};
      if(len > 0){ lv[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ lv[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ lv[2] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ lv[3] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.level = atoi(lv);
      sia_current.haveLevel = true;
//      opengalaxy().syslog().debug("SIA:  Level: %u", sia_current.level);
    }
    // Value: vaVVVV
    //
    else if(code[0] == 'v' && code[1] == 'a'){
      char va[5] = {0,0,0,0,0};
      if(len > 0){ va[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ va[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ va[2] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ va[3] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.value = atoi(va);
      sia_current.haveValue = true;
//      opengalaxy().syslog().debug("SIA:  Value: %u", sia_current.value);
    }
    // Path: ptPPP
    //
    else if(code[0] == 'p' && code[1] == 't'){
      char pt[4] = {0,0,0,0};
      if(len > 0){ pt[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ pt[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ pt[2] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.path = atoi(pt);
      sia_current.havePath = true;
//      opengalaxy().syslog().debug("SIA:  Path: %u", sia_current.path);
    }
    // Route Group: rgGG
    //
    else if(code[0] == 'r' && code[1] == 'g'){
      char rg[3] = {0,0,0};
      if(len > 0){ rg[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ rg[1] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.routeGroup = atoi(rg);
      sia_current.haveRouteGroup = true;
//      opengalaxy().syslog().debug("SIA:  Route Group: %u", sia_current.routeGroup);
    }
    // Sub-Subscriber: ssSSSS
    //
    else if(code[0] == 's' && code[1] == 's'){
      char ss[5] = {0,0,0,0,0};
      if(len > 0){ ss[0] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ss[1] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ss[2] = *p++; len--; }
      if(len > 0 && *p != SIA::packet_separator){ ss[3] = *p++; len--; }
      if(len > 0 && *p == SIA::packet_separator){ p++; len--; }
      sia_current.subSubscriber = atoi(ss);
      sia_current.haveSubSubscriber = true;
//      opengalaxy().syslog().debug("SIA:  Sub-Subscriber: %u", sia_current.subSubscriber);
    }
    //
    // ** Decode the event **
    //
    else {
      SiaEventCode* ev;
      bool match = false;
      for(int t=0; t<m_SiaEvents.size(); t++){
        ev = m_SiaEvents[t];
        if(ev->letter_code.compare(code)==0){
          match = true;
          break;
        }
      }
      if(match == true){
        sia_current.event = ev;
        sia_current.haveEvent = true;

        char an[5] = {0,0,0,0,0};
        char un[7] = {0,0,0,0,0,0,0};
        char ut[3] = {0,0,0};
        /// AAAA*UUUUUUuu
        ///
        /// AAAA   = (an) Address Number (optional, ASCII representation of base 16 value, at least 1 character and a maximum of 4)
        /// UUUUUU = (un) Units Number (optional, presence indicated by *, ASCII representation of base 10 value, at least 1 character and a maximum of 6)
        /// uu     = (ut) Unit Type (optional, Units Number must be present, 1 or 2 characters)
        if(len > 0 && *p != SIA::packet_separator){
          if(len > 0){ an[0] = *p++; len--; }
          if(len > 0 && *p != SIA::packet_separator && *p != '*'){ an[1] = *p++; len--; }
          if(len > 0 && *p != SIA::packet_separator && *p != '*'){ an[2] = *p++; len--; }
          if(len > 0 && *p != SIA::packet_separator && *p != '*'){ an[3] = *p++; len--; }
          if(len > 0 && *p == '*'){
            sia_current.haveUnits = true;
            p++; len--;
            if(len > 0){ un[0] = *p++; len--; }
            if(len > 0 && *p != SIA::packet_separator && *p >= '0' && *p <= '9'){ un[1] = *p++; len--; }
            if(len > 0 && *p != SIA::packet_separator && *p >= '0' && *p <= '9'){ un[2] = *p++; len--; }
            if(len > 0 && *p != SIA::packet_separator && *p >= '0' && *p <= '9'){ un[3] = *p++; len--; }
            if(len > 0 && *p != SIA::packet_separator && *p >= '0' && *p <= '9'){ un[4] = *p++; len--; }
            if(len > 0 && *p != SIA::packet_separator && *p >= '0' && *p <= '9'){ un[5] = *p++; len--; }
            if(len > 0 && *p != SIA::packet_separator){ ut[0] = *p++; len--; }
            if(len > 0 && *p != SIA::packet_separator){ ut[1] = *p++; len--; }
          }
        }
        if(len > 0 && *p == SIA::packet_separator){ p++; len--; }

//        opengalaxy().syslog().debug("SIA:  Event: '%s' -> '%s' -> '%s'", ev->letter_code.c_str(), ev->name.c_str(), ev->desc.c_str());

        if(1 /* value indicating that the connected panel is a Galaxy */){
          sia_current.addressNumber = strtol(an, nullptr, 10);
        }
        else {
          // not a Galaxy panel; decode as base16
          sia_current.addressNumber = strtol(an, nullptr, 16);
        }

        if(sia_current.addressNumber == 0) sia_current.addressNumber = -1;

        if(sia_current.haveUnits){
          sia_current.units = strtol(un, nullptr, 10);
          sia_current.unitsType.assign(ut);
//          opengalaxy().syslog().debug("SIA:  Units: %d of Type: '%s'", sia_current.units, sia_current.unitsType.c_str());
        }

        switch(ev->address_field){
          case SiaEventCode::AddressField::unused:
            sia_current.addressType = "Unused";
            break;
          case SiaEventCode::AddressField::zone:
            sia_current.addressType = "Zone";
            break;
          case SiaEventCode::AddressField::area:
            sia_current.addressType = "Area";
            break;
          case SiaEventCode::AddressField::user:
            sia_current.addressType = "User";
            break;
          case SiaEventCode::AddressField::door:
            sia_current.addressType = "Door";
            break;
          case SiaEventCode::AddressField::dealer_id:
            sia_current.addressType = "Dealer ID";
            break;
          case SiaEventCode::AddressField::expander:
            sia_current.addressType = "Expander";
            break;
          case SiaEventCode::AddressField::line:
            sia_current.addressType = "Line";
            break;
          case SiaEventCode::AddressField::relay:
            sia_current.addressType = "Relay";
            break;
          case SiaEventCode::AddressField::point:
            sia_current.addressType = "Point";
            break;
          case SiaEventCode::AddressField::printer:
            sia_current.addressType = "Printer";
            break;
          case SiaEventCode::AddressField::mfr_defined:
            sia_current.addressType = "Manufacturer defined";
            break;
        }
//        opengalaxy().syslog().debug("SIA:  AddressType: '%s' addressNumber: %d", sia_current.addressType.c_str(), sia_current.addressNumber);
      }
      else {
        // ** Nothing found -> Unknown event or modifier. log and skip over separator **
        opengalaxy().syslog().error("SIA: Error, failed to decode packet: %s", code);
        while(len != 0){
          char pp = *p++; len--;
          if(pp == SIA::packet_separator) break;
        }
      }
    }
  }

  return true;
}

SiaEvent* SIA::Decode(unsigned char* data, size_t size)
{
  unsigned char parity;
  int t;
  int block_size;
  SiaEvent *out = nullptr;
  bool retv = false;

  //	
  // Sanity check on remaining buffer size
  //
  if(size > (sizeof(sia_buffer)-sia_buffer_counter)){
    throw new std::runtime_error("sia-buffer-overrun");
  }

  //
  // Append the new bytes to the bytes allready in the buffer
  //
  if(data != nullptr){
    memcpy(&sia_buffer[sia_buffer_counter], data, size);
    sia_buffer_counter += size;
  }

  //
  // Try to parse the bytes in the buffer
  //
  while(sia_buffer_counter){

    //
    // Try to find a SIA block in the buffer
    //
    if(sia_buffer_counter >= SiaBlock::block_overhead) { // Must have at least SiaBlock::block_overhead bytes
      SiaBlock raw;
      raw.block.function_code = (SiaBlock::FunctionCode)sia_buffer[1];
/*
      if(raw.IsFunctionCode() == false){ // Must have a valid SIA function code
        //
        // Oeps, the data does not start with a valid SIA function code
        //  - left shift remaining bytes in the buffer
        //  - Try again or wait for the buffer to be filled
        //
        opengalaxy().syslog().error("SIA: unknown function code, resyncing data (%c == 0x%02X)", raw.block.function_code, raw.block.function_code);
//        pbuffer();

        opengalaxy().receiver().TriggerReject(); // reject any pending command, just to be safe

// do not do that        SendBlock_Reject();

        // Scan sia_buffer for a valid function code
        while((raw.IsFunctionCode() == false) && (sia_buffer_counter >= SiaBlock::block_overhead)){
opengalaxy().syslog().debug("SIA: left shifting data 1 place");
          for(t=1; t<sia_buffer_counter; t++) sia_buffer[t-1] = sia_buffer[t]; // Shift all bytes to the left
          sia_buffer_counter--; // one less bottle of beer on the wall
          raw.block.function_code = (SiaBlock::FunctionCode)sia_buffer[1];
        }

        if(sia_buffer_counter >= SiaBlock::block_overhead) continue; // Try again

        return nullptr; // not enough bytes in the buffer, wait for them
      }
*/
      if(raw.IsFunctionCode() == false){
        // Not a valid function code, left shift the entire buffer and try again
        // or wait for more data.
        opengalaxy().syslog().error("SIA: unknown function code (0x%02X)", raw.block.function_code);
        if(sia_buffer_counter > 0){
          for(t=1; t<sia_buffer_counter; t++) sia_buffer[t-1] = sia_buffer[t]; // Shift all bytes to the left
          sia_buffer_counter--;
          return Decode(nullptr, 0);
        }
        return nullptr;
      }

    }
    else return nullptr; // not enough bytes in the buffer, wait for them

    //
    // At this point we have at least SiaBlock::block_overhead bytes with a valid function code, now:
    //
    //  - Calculate block size
    //  - Do parity check
    //
  
    block_size = (sia_buffer[0] & SiaBlock::blockheader_length_mask) + SiaBlock::block_overhead;
  
    if(sia_buffer_counter < block_size) return nullptr; // Not enough bytes, wait for more data

    // We have enough bytes in the buffer to decode something
    // Now check the parity of the received block
    for(t=0, parity=0xFF; t<block_size-1; parity^=sia_buffer[t++]); // column parity check
    if(parity != sia_buffer[block_size-1]){
      
      //
      // Column Parity test failed
      //
      //  - Left shift remaining bytes
      //  - Try again or wait for the buffer to be filled
      //

      opengalaxy().syslog().error("SIA: discarding block, invalid column parity.");
      for(t=1; t<sia_buffer_counter; t++) sia_buffer[t-1] = sia_buffer[t]; // shift buffer to the left
      sia_buffer_counter--;
      opengalaxy().receiver().TriggerReject();
      SendBlock_Reject();
      if(sia_buffer_counter >= SiaBlock::block_overhead) continue; // Try again
      return nullptr; // not enough bytes in the buffer, wait for them

    }

    //
    // At this point we have a valid SIA block in the buffer, now:
    //
    //  - Copy the block into the buffer for the 'current' SIA block (sia_current)
    //  - If it is an event block (ie. not an account or ascii block) then also store it in a safe place (remember_me)
    //    (and later use it as the raw member of the final sia_event)
    //  - Remove the block from the (input) buffer
    //
     
    sia_current.raw.block.header.data = sia_buffer[0];
    sia_current.raw.block.function_code = (SiaBlock::FunctionCode)sia_buffer[1];
    sia_current.raw.block.parity = sia_buffer[block_size-1];
    for(t=0; t<sia_current.raw.block.header.block_length; t++) sia_current.raw.block.message[t] = sia_buffer[t+2];

    if(
      (SiaBlock::FunctionCode)sia_buffer[1] != SiaBlock::FunctionCode::account_id &&
      (SiaBlock::FunctionCode)sia_buffer[1] != SiaBlock::FunctionCode::ascii
    ){
      remember_me.Erase();
      remember_me.block.header.data = sia_buffer[0];
      remember_me.block.function_code = (SiaBlock::FunctionCode)sia_buffer[1];
      remember_me.block.parity = 0; // set to zero to implicitly make raw.data a valid C string if raw.data is the maximum blocklength
      for(t=0; t<remember_me.block.header.block_length; t++) remember_me.block.message[t] = sia_buffer[t+2];
    }

    // Left shift the remaining bytes in the buffer
    sia_buffer_counter -= block_size;
    if(sia_buffer_counter > 0){
      for(t=0; t<sia_buffer_counter; t++) sia_buffer[t] = sia_buffer[block_size + t];
    }
      
    // Sanity check, input buffer cannot be lesser them empty
    if(sia_buffer_counter < 0){
       opengalaxy().syslog().error("SIA: SIA::Decode(): Guru Meditation!");
       sia_buffer_counter = 0;
    }

    //
    // Now decode the 'current' SIA block
    //  (by calling the SIA::DecodeBlock_xxx() function for this SIA functioncode)
    //
    std::string fcstr;
    sia_current.raw.FunctionCodeToString(fcstr);
//    opengalaxy().syslog().debug("SIA: datablock has function code 0x%02X (%s)", sia_current.raw.block.function_code, fcstr.data());

    switch(sia_current.raw.block.function_code){

      case SiaBlock::FunctionCode::end_of_data:
        retv=DecodeBlock_EndOfData();
        break;

      case SiaBlock::FunctionCode::wait:
        retv=DecodeBlock_Wait();
        break;

      case SiaBlock::FunctionCode::abort:
        retv=DecodeBlock_Abort();
        break;

      case SiaBlock::FunctionCode::res_3:
      case SiaBlock::FunctionCode::res_4:
      case SiaBlock::FunctionCode::res_5:
        retv=DecodeBlock_Reserved();
        break;

      case SiaBlock::FunctionCode::ack_and_standby:
        retv=DecodeBlock_AcknoledgeAndStandby();
        break;

      case SiaBlock::FunctionCode::ack_and_disconnect:
        retv=DecodeBlock_AcknoledgeAndDisconnect();
        break;

      case SiaBlock::FunctionCode::acknoledge:
      case SiaBlock::FunctionCode::alt_acknoledge:
        retv=DecodeBlock_Acknoledge();
        break;

      case SiaBlock::FunctionCode::reject:
      case SiaBlock::FunctionCode::alt_reject:
        retv=DecodeBlock_Reject();
        break;

      case SiaBlock::FunctionCode::control:
        retv=DecodeBlock_Control();
        break;

      case SiaBlock::FunctionCode::environmental:
        retv=DecodeBlock_Environmental();
        break;

      case SiaBlock::FunctionCode::new_event:
        retv=DecodeBlock_NewEvent();
        break;

      case SiaBlock::FunctionCode::old_event:
        retv=DecodeBlock_OldEvent();
        break;

      case SiaBlock::FunctionCode::program:
        retv=DecodeBlock_Program();
        break;

      case SiaBlock::FunctionCode::configuration:
        retv=DecodeBlock_Configuration();
        break;

      case SiaBlock::FunctionCode::remote_login:
        retv=DecodeBlock_RemoteLogin();
        break;

      case SiaBlock::FunctionCode::account_id:
        retv=DecodeBlock_AccountId();
        break;

      case SiaBlock::FunctionCode::origin_id:
        retv=DecodeBlock_OriginId();
        break;

      case SiaBlock::FunctionCode::ascii:
        retv=DecodeBlock_ASCII();
        break;

      case SiaBlock::FunctionCode::extended:
        retv=DecodeBlock_Extended();
        break;

      case SiaBlock::FunctionCode::listen_in:
        retv=DecodeBlock_ListenIn();
        break;

      case SiaBlock::FunctionCode::vchn_request:
        retv=DecodeBlock_VideoChannelRequest();
        break;

      case SiaBlock::FunctionCode::vchn_frame:
        retv=DecodeBlock_VideoChannelFrame();
        break;

      case SiaBlock::FunctionCode::video:
        retv=DecodeBlock_Video();
        break;
  
      // This point should never be reached
      default:
        retv=false;
        break;
    }

    // After decoding the block:
    //
    //  - Check if we need to send an acknoledge or reject SIA block in reply to the received block
    //
    if(retv == false){
      opengalaxy().syslog().error("SIA: failed to decode data block, function code 0x%02X", sia_current.raw.block.function_code);
      if(sia_current.raw.block.header.acknoledge_request == 1){
        switch(sia_current.raw.block.function_code){
           case SiaBlock::FunctionCode::alt_reject:
           case SiaBlock::FunctionCode::reject:
           case SiaBlock::FunctionCode::alt_acknoledge:
           case SiaBlock::FunctionCode::acknoledge:
           case SiaBlock::FunctionCode::configuration:
           case SiaBlock::FunctionCode::control:
           case SiaBlock::FunctionCode::extended:
             break; // These do not require an acknoledge
           default:
             SendBlock_Reject();
             break;
        }
      }
    }
    else {
      if(sia_current.raw.block.header.acknoledge_request == 1){
        switch(sia_current.raw.block.function_code){
           case SiaBlock::FunctionCode::alt_reject:
           case SiaBlock::FunctionCode::reject:
           case SiaBlock::FunctionCode::alt_acknoledge:
           case SiaBlock::FunctionCode::acknoledge:
           case SiaBlock::FunctionCode::configuration:
           case SiaBlock::FunctionCode::control:
           case SiaBlock::FunctionCode::extended:
             break; // These do not require an acknoledge
           default:
             SendBlock_Acknoledge();
             break;
        }
      }
    }

    //
    // Now check if we have a complete SIA message
    //

    // Every message must have an account ID
    if(sia_current_HaveAccountID == true){
      // Every message must have an event
      if(sia_current.haveEvent == true){
        if(sia_level < 3){
          //
          // We have a complete SIA (level < 3) message
          //

          // Copy sia_current to a new SiaEvent
          out = new SiaEvent(sia_current);

          // Restore the raw event data block
          memcpy(out->raw.block.data, remember_me.block.data, SiaBlock::block_max);

          // Reset sia_current, remember_me and sia_current_HaveAccountID
          sia_current.Erase();
          remember_me.Erase();
          sia_current_HaveAccountID = false;

          // Return the complete sia message
          return out;
        }
        else if(sia_current.haveAscii == true){
          //
          // We have a complete SIA (level >= 3) message
          //

          // Copy sia_current to a new SiaEvent
          out = new SiaEvent(sia_current);

          // Restore the raw event data block
          memcpy(out->raw.block.data, remember_me.block.data, SiaBlock::block_max);

          // Reset sia_current, remember_me and sia_current_HaveAccountID
          sia_current.Erase();
          remember_me.Erase();
          sia_current_HaveAccountID = false;

          // Return the complete sia message
          return out;
        }
      }
    }
    else if(sia_current.haveEvent==true || sia_current.haveAscii==true){
      // Do we have an event but no account ID? Yes? Then reset the affected values.
      // This is needed when autodetecting the sia level:
      //  When an ASCII block arrives without having received an event first,
      //  the sia_level gets updated here but it's to late to add the block to the previous sia message
      opengalaxy().syslog().debug("SIA: Discarding ASCII block for previous level %d message.", GetLevel());
      sia_current.haveEvent = false;
      sia_current.haveAscii = false;
      if(sia_level < 3) SetLevel(3);
    }

    // Any remaining bytes?
    if(sia_buffer_counter){
      opengalaxy().syslog().debug("SIA: %u bytes remaining in sia_buffer.", sia_buffer_counter);
    }

  } // ends while( sia_buffer_counter )

  return nullptr; // Wait for more data
}

// max DESC
//                                           1         2         3         4         5         6
//                                  12345678901234567890123456789012345678901234567890123456789012345678

// max NAME
//                                           1         2         3
//                                  123456789012345678901234567890

void SIA::fillSiaEventCodeArray(void)
{
  static std::string SIA_AR      = "AR";
  static std::string SIA_AR_NAME = "AR restoral";
  static std::string SIA_AR_DESC = "AC power has been restored";

  static std::string SIA_AT      = "AT"; 
  static std::string SIA_AT_NAME = "AC trouble";
  static std::string SIA_AT_DESC = "AC power has failed";

  static std::string SIA_BA      = "BA";
  static std::string SIA_BA_NAME = "Burglary alarm";
  static std::string SIA_BA_DESC = "Burglary zone has been violated while armed";

  static std::string SIA_BB      = "BB";
  static std::string SIA_BB_NAME = "Burglary bypass";
  static std::string SIA_BB_DESC = "Burglary zone has been bypassed";

  static std::string SIA_BC      = "BC";
  static std::string SIA_BC_NAME = "Burglary cancel";
  static std::string SIA_BC_DESC = "Alarm has been canceled";

  static std::string SIA_BH      = "BH";
  static std::string SIA_BH_NAME = "Burglary alarm restoral";
  static std::string SIA_BH_DESC = "Alarm condition eliminated";

  static std::string SIA_BJ      = "BJ";
  static std::string SIA_BJ_NAME = "Burglary trouble restoral";
  static std::string SIA_BJ_DESC = "Trouble condition eliminated";

  static std::string SIA_BR      = "BR";
  static std::string SIA_BR_NAME = "Burglary restoral";
  static std::string SIA_BR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_BS      = "BS";
  static std::string SIA_BS_NAME = "Burglary supervisory";
  static std::string SIA_BS_DESC = "Unsafe intrusion detection system condition";

  static std::string SIA_BT      = "BT";
  static std::string SIA_BT_NAME = "Burglary trouble";
  static std::string SIA_BT_DESC = "Burglary trouble condition was activated";

  static std::string SIA_BU      = "BU";
  static std::string SIA_BU_NAME = "Burglary unbypass";
  static std::string SIA_BU_DESC = "Zone bypass has been removed";

  static std::string SIA_BV      = "BV";
  static std::string SIA_BV_NAME = "Burglary verified";
  static std::string SIA_BV_DESC = "More than 3 Burglary zones has been triggered";

  static std::string SIA_BX      = "BX";
  static std::string SIA_BX_NAME = "Burglary test";
  static std::string SIA_BX_DESC = "Burglary zone activated during testing";

  static std::string SIA_CA      = "CA";
  static std::string SIA_CA_NAME = "Automatic closing";
  static std::string SIA_CA_DESC = "System armed automatically";

  static std::string SIA_CE      = "CE";
  static std::string SIA_CE_NAME = "Closing extend";
  static std::string SIA_CE_DESC = "Extended closing time";

  static std::string SIA_CF      = "CF";
  static std::string SIA_CF_NAME = "Forced closing";
  static std::string SIA_CF_DESC = "System armed, zones not ready";

  static std::string SIA_CG      = "CG";
  static std::string SIA_CG_NAME = "Close area";
  static std::string SIA_CG_DESC = "System has been partially armed";

  static std::string SIA_CI      = "CI";
  static std::string SIA_CI_NAME = "Fail to close";
  static std::string SIA_CI_DESC = "An area has not been armed at the end of the closing window";

  static std::string SIA_CJ      = "CJ";
  static std::string SIA_CJ_NAME = "Late close";
  static std::string SIA_CJ_DESC = "An area was armed after the closing window";

  static std::string SIA_CK      = "CK";
  static std::string SIA_CK_NAME = "Early close";
  static std::string SIA_CK_DESC = "An area was armed before the closing window";

  static std::string SIA_CL      = "CL";
  static std::string SIA_CL_NAME = "Closing report";
  static std::string SIA_CL_DESC = "System armed";

  static std::string SIA_CP      = "CP";
  static std::string SIA_CP_NAME = "Automatic closing";
  static std::string SIA_CP_DESC = "System armed automatically";

  static std::string SIA_CR      = "CR";
  static std::string SIA_CR_NAME = "Recent closing";
  static std::string SIA_CR_DESC = "An alarm occurred within 5 minutes after the system was armed";

  static std::string SIA_CS      = "CS";
  static std::string SIA_CS_NAME = "Closing switch";
  static std::string SIA_CS_DESC = "System was armed by keyswitch";

  static std::string SIA_CT      = "CT";
  static std::string SIA_CT_NAME = "Late to open";
  static std::string SIA_CT_DESC = "System was not disarmed on time";

  static std::string SIA_CW      = "CW";
  static std::string SIA_CW_NAME = "Force armed";
  static std::string SIA_CW_DESC = "Header for force armed sesssion, force point msg. may follow";

  static std::string SIA_CZ      = "CZ";
  static std::string SIA_CZ_NAME = "Point closing";
  static std::string SIA_CZ_DESC = "A point (a opposed to a whole area or account) has closed/armed";

  static std::string SIA_DC      = "DC";
  static std::string SIA_DC_NAME = "Access closed";
  static std::string SIA_DC_DESC = "Access to all users prohibited";

  static std::string SIA_DD      = "DD";
  static std::string SIA_DD_NAME = "Access denied";
  static std::string SIA_DD_DESC = "Access denied, unknown code";

  static std::string SIA_DF      = "DF";
  static std::string SIA_DF_NAME = "Door forced";
  static std::string SIA_DF_DESC = "Door opened without access request";

  static std::string SIA_DG      = "DG";
  static std::string SIA_DG_NAME = "Access granted";
  static std::string SIA_DG_DESC = "Door access granted";

  static std::string SIA_DK      = "DK";
  static std::string SIA_DK_NAME = "Access lockout";
  static std::string SIA_DK_DESC = "Door access denied, known code";

  static std::string SIA_DO      = "DO";
  static std::string SIA_DO_NAME = "Access open";
  static std::string SIA_DO_DESC = "Door access to authorised users allowed";

  static std::string SIA_DR      = "DR";
  static std::string SIA_DR_NAME = "Door restoral";
  static std::string SIA_DR_DESC = "Door access alarm/trouble condition eliminated";

  static std::string SIA_DS      = "DS";
  static std::string SIA_DS_NAME = "Door station";
  static std::string SIA_DS_DESC = "Identifies door for next report";

  static std::string SIA_DT      = "DT";
  static std::string SIA_DT_NAME = "Access trouble";
  static std::string SIA_DT_DESC = "Access system trouble";

  static std::string SIA_DU      = "DU";
  static std::string SIA_DU_NAME = "Dealer ID";
  static std::string SIA_DU_DESC = "Zone description gives dealer ID #";

  static std::string SIA_EA      = "EA";
  static std::string SIA_EA_NAME = "Exit alarm";
  static std::string SIA_EA_DESC = "An exit zone remained violated at the end of the exit delay period";

  static std::string SIA_EE      = "EE";
  static std::string SIA_EE_NAME = "Exit error";
  static std::string SIA_EE_DESC = "An exit zone remained violated at the end of the exit delay period";

  static std::string SIA_ER      = "ER";
  static std::string SIA_ER_NAME = "Expansion restoral";
  static std::string SIA_ER_DESC = "Expansion device trouble eliminated";

  static std::string SIA_ET      = "ET";
  static std::string SIA_ET_NAME = "Expansion trouble";
  static std::string SIA_ET_DESC = "Expansion device trouble";

  static std::string SIA_FA      = "FA";
  static std::string SIA_FA_NAME = "Fire alarm";
  static std::string SIA_FA_DESC = "Fire condition detected";

  static std::string SIA_FB      = "FB";
  static std::string SIA_FB_NAME = "Fire bypass";
  static std::string SIA_FB_DESC = "Zone has been bypassed";

  static std::string SIA_FH      = "FH";
  static std::string SIA_FH_NAME = "Fire alarm restore";
  static std::string SIA_FH_DESC = "Alarm condition eliminated";

  static std::string SIA_FI      = "FI";
  static std::string SIA_FI_NAME = "Fire test begin";
  static std::string SIA_FI_DESC = "The transmitter area\'s fire test has begun";

  static std::string SIA_FJ      = "FJ";
  static std::string SIA_FJ_NAME = "Fire trouble restore";
  static std::string SIA_FJ_DESC = "Trouble condition eliminated";

  static std::string SIA_FK      = "FK";
  static std::string SIA_FK_NAME = "Fire test end";
  static std::string SIA_FK_DESC = "The transmitter area\'s fire test has ended";

  static std::string SIA_FR      = "FR";
  static std::string SIA_FR_NAME = "Fire restoral";
  static std::string SIA_FR_DESC = "Alarm/trouble condition has been eliminated";

  static std::string SIA_FS      = "FS";
  static std::string SIA_FS_NAME = "Fire supervisory";
  static std::string SIA_FS_DESC = "Unsafe fire detection system condition";

  static std::string SIA_FT      = "FT";
  static std::string SIA_FT_NAME = "Fire trouble";
  static std::string SIA_FT_DESC = "Zone disabled by fault";

  static std::string SIA_FU      = "FU";
  static std::string SIA_FU_NAME = "Fire unbypass";
  static std::string SIA_FU_DESC = "Bypass has been removed";

  static std::string SIA_FX      = "FX";
  static std::string SIA_FX_NAME = "Fire test";
  static std::string SIA_FX_DESC = "Fire zone activated during test";

  static std::string SIA_FY      = "FY";
  static std::string SIA_FY_NAME = "Missing fire trouble";
  static std::string SIA_FY_DESC = "A fire point is now logically missing";

  static std::string SIA_GA      = "GA";
  static std::string SIA_GA_NAME = "Gas alarm";
  static std::string SIA_GA_DESC = "Gas alarm condition detected";

  static std::string SIA_GB      = "GB";
  static std::string SIA_GB_NAME = "Gas bypass";
  static std::string SIA_GB_DESC = "Zone has been bypassed";

  static std::string SIA_GH      = "GH";
  static std::string SIA_GH_NAME = "Gas alarm restore";
  static std::string SIA_GH_DESC = "Alarm condition eliminated";

  static std::string SIA_GJ      = "GJ";
  static std::string SIA_GJ_NAME = "Gas trouble restore";
  static std::string SIA_GJ_DESC = "Trouble condition eliminated";

  static std::string SIA_GR      = "GR";
  static std::string SIA_GR_NAME = "Gas alarm/trouble restore";
  static std::string SIA_GR_DESC = "Alarm/trouble condition has been eliminated";

  static std::string SIA_GS      = "GS";
  static std::string SIA_GS_NAME = "Gas supervisory";
  static std::string SIA_GS_DESC = "Unsafe gas detection system condition";

  static std::string SIA_GT      = "GT";
  static std::string SIA_GT_NAME = "Gas trouble";
  static std::string SIA_GT_DESC = "Zone disabled by fault";

  static std::string SIA_GU      = "GU";
  static std::string SIA_GU_NAME = "Gas unbypass";
  static std::string SIA_GU_DESC = "Bypass has been removed";

  static std::string SIA_GX      = "GX";
  static std::string SIA_GX_NAME = "Gas test gas";
  static std::string SIA_GX_DESC = "Zone activated during test";

  static std::string SIA_HA      = "HA";
  static std::string SIA_HA_NAME = "Hold-up alarm";
  static std::string SIA_HA_DESC = "Silent alarm, user under duress";

  static std::string SIA_HB      = "HB";
  static std::string SIA_HB_NAME = "Hold-up bypass";
  static std::string SIA_HB_DESC = "Zone has been bypassed";

  static std::string SIA_HH      = "HH";
  static std::string SIA_HH_NAME = "Hold-up alarm restoral";
  static std::string SIA_HH_DESC = "Alarm condition eliminated";

  static std::string SIA_HJ      = "HJ";
  static std::string SIA_HJ_NAME = "Hold-up trouble restoral";
  static std::string SIA_HJ_DESC = "Trouble condition eliminated";

  static std::string SIA_HR      = "HR";
  static std::string SIA_HR_NAME = "Hold-up restoral";
  static std::string SIA_HR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_HS      = "HS";
  static std::string SIA_HS_NAME = "Hold-up supervisory";
  static std::string SIA_HS_DESC = "Unsafe hold-up system condition";

  static std::string SIA_HT      = "HT";
  static std::string SIA_HT_NAME = "Hold-up trouble";
  static std::string SIA_HT_DESC = "Zone disable by fault";

  static std::string SIA_HU      = "HU";
  static std::string SIA_HU_NAME = "Hold-up unbypass";
  static std::string SIA_HU_DESC = "Bypass has been removed";

  static std::string SIA_JA      = "JA";
  static std::string SIA_JA_NAME = "User code tamper";
  static std::string SIA_JA_DESC = "Too many unsuccessfull attempts made to enter a user ID";

  static std::string SIA_JD      = "JD";
  static std::string SIA_JD_NAME = "Date changed";
  static std::string SIA_JD_DESC = "The date was changed in the transmitter/receiver";

  static std::string SIA_JH      = "JH";
  static std::string SIA_JH_NAME = "Holiday changed";
  static std::string SIA_JH_DESC = "The transmitters holiday schedule has been changed";

  static std::string SIA_JL      = "JL";
  static std::string SIA_JL_NAME = "Log threshold";
  static std::string SIA_JL_DESC = "The transmitters log memory has reached its threshold level";

  static std::string SIA_JO      = "JO";
  static std::string SIA_JO_NAME = "Log overflow";
  static std::string SIA_JO_DESC = "The transmitters log memory has overflowed";

  static std::string SIA_JR      = "JR";
  static std::string SIA_JR_NAME = "Schedule execute";
  static std::string SIA_JR_DESC = "An automatic scheduled event was executed";

  static std::string SIA_JS      = "JS";
  static std::string SIA_JS_NAME = "Schedule change";
  static std::string SIA_JS_DESC = "An automatic schedule was changed";

  static std::string SIA_JT      = "JT";
  static std::string SIA_JT_NAME = "Time changed";
  static std::string SIA_JT_DESC = "The time was changed in the tranmitter/receiver";

  static std::string SIA_JV      = "JV";
  static std::string SIA_JV_NAME = "User code change";
  static std::string SIA_JV_DESC = "A user\'s code has been changed";

  static std::string SIA_JX      = "JX";
  static std::string SIA_JX_NAME = "User code delete";
  static std::string SIA_JX_DESC = "A user\'s code has been removed";

  static std::string SIA_KA      = "KA";
  static std::string SIA_KA_NAME = "Heat alarm";
  static std::string SIA_KA_DESC = "High temperature detected on premise";

  static std::string SIA_KB      = "KB";
  static std::string SIA_KB_NAME = "Heat bypass";
  static std::string SIA_KB_DESC = "Zone has been bypassed";

  static std::string SIA_KH      = "KH";
  static std::string SIA_KH_NAME = "Heat alarm restore";
  static std::string SIA_KH_DESC = "Alarm condition eliminated";

  static std::string SIA_KJ      = "KJ";
  static std::string SIA_KJ_NAME = "Heat trouble restore";
  static std::string SIA_KJ_DESC = "Trouble condition eliminated";

  static std::string SIA_KR      = "KR";
  static std::string SIA_KR_NAME = "Heat restoral";
  static std::string SIA_KR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_KS      = "KS";
  static std::string SIA_KS_NAME = "Heat supervisory";
  static std::string SIA_KS_DESC = "Unsafe heat detection system condition";

  static std::string SIA_KT      = "KT";
  static std::string SIA_KT_NAME = "Heat trouble";
  static std::string SIA_KT_DESC = "Zone disabled by fault";

  static std::string SIA_KU      = "KU";
  static std::string SIA_KU_NAME = "Heat unbypass";
  static std::string SIA_KU_DESC = "Bypass has been removed";

  static std::string SIA_LB      = "LB";
  static std::string SIA_LB_NAME = "Local program";
  static std::string SIA_LB_DESC = "Begin local programming";

  static std::string SIA_LD      = "LD";
  static std::string SIA_LD_NAME = "Local program denied";
  static std::string SIA_LD_DESC = "Access code incorrect";

  static std::string SIA_LE      = "LE";
  static std::string SIA_LE_NAME = "Listen-in ended";
  static std::string SIA_LE_DESC = "The listen-in session has been terminated";

  static std::string SIA_LF      = "LF";
  static std::string SIA_LF_NAME = "Listen-in begin";
  static std::string SIA_LF_DESC = "The listen-in session with the receiver has begun";

  static std::string SIA_LR      = "LR";
  static std::string SIA_LR_NAME = "Phone line resoral";
  static std::string SIA_LR_DESC = "Phone line restored to service";

  static std::string SIA_LS      = "LS";
  static std::string SIA_LS_NAME = "Local program";
  static std::string SIA_LS_DESC = "Local programming successfull";

  static std::string SIA_LT      = "LT";
  static std::string SIA_LT_NAME = "Phone line trouble";
  static std::string SIA_LT_DESC = "Phone line report";

  static std::string SIA_LU      = "LU";
  static std::string SIA_LU_NAME = "Local program fail";
  static std::string SIA_LU_DESC = "Local programming unsuccessfull";

  static std::string SIA_LX      = "LX";
  static std::string SIA_LX_NAME = "Local program ended";
  static std::string SIA_LX_DESC = "A local programming session has been terminated";

  static std::string SIA_MA      = "MA";
  static std::string SIA_MA_NAME = "Medical alarm";
  static std::string SIA_MA_DESC = "Emergency assistance request";

  static std::string SIA_MB      = "MB";
  static std::string SIA_MB_NAME = "Medical bypass";
  static std::string SIA_MB_DESC = "Zone has been bypassed";

  static std::string SIA_MH      = "MH";
  static std::string SIA_MH_NAME = "Medical alarm restore";
  static std::string SIA_MH_DESC = "Alarm condition eliminated";

  static std::string SIA_MJ      = "MJ";
  static std::string SIA_MJ_NAME = "Medical trouble restore";
  static std::string SIA_MJ_DESC = "Trouble condition eliminated";

  static std::string SIA_MR      = "MR";
  static std::string SIA_MR_NAME = "Medical restoral";
  static std::string SIA_MR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_MS      = "MS";
  static std::string SIA_MS_NAME = "Medical supervisory";
  static std::string SIA_MS_DESC = "Unsafe system condition exists";

  static std::string SIA_MT      = "MT";
  static std::string SIA_MT_NAME = "Medical trouble";
  static std::string SIA_MT_DESC = "Zone disabled by fault";

  static std::string SIA_MU      = "MU";
  static std::string SIA_MU_NAME = "Medical unbypass";
  static std::string SIA_MU_DESC = "Bypass has been removed";

  static std::string SIA_NA      = "NA";
  static std::string SIA_NA_NAME = "No activity";
  static std::string SIA_NA_DESC = "There has been no activity for a programmed amount of time";

  static std::string SIA_NF      = "NF";
  static std::string SIA_NF_NAME = "Force perimeter arm";
  static std::string SIA_NF_DESC = "Some zones/points not ready";

  static std::string SIA_NL      = "NL";
  static std::string SIA_NL_NAME = "Perimeter armed";
  static std::string SIA_NL_DESC = "An area has been perimeter armed";

  static std::string SIA_OA      = "OA";
  static std::string SIA_OA_NAME = "Automatic opening";
  static std::string SIA_OA_DESC = "System has disarmed automatically";

  static std::string SIA_OC      = "OC";
  static std::string SIA_OC_NAME = "Cancel report";
  static std::string SIA_OC_DESC = "Untyped zone cancel";

  static std::string SIA_OG      = "OG";
  static std::string SIA_OG_NAME = "Open area";
  static std::string SIA_OG_DESC = "System has been partially disarmed";

  static std::string SIA_OI      = "OI";
  static std::string SIA_OI_NAME = "Fail to open";
  static std::string SIA_OI_DESC = "An area has not been armed at the end of the opening window";

  static std::string SIA_OJ      = "OJ";
  static std::string SIA_OJ_NAME = "Late open";
  static std::string SIA_OJ_DESC = "An area was disarmed after the opening window";

  static std::string SIA_OK      = "OK";
  static std::string SIA_OK_NAME = "Early open";
  static std::string SIA_OK_DESC = "An area was disarmed before the opening window";

  static std::string SIA_OP      = "OP";
  static std::string SIA_OP_NAME = "Opening report";
  static std::string SIA_OP_DESC = "Account was disarmed";

  static std::string SIA_OR      = "OR";
  static std::string SIA_OR_NAME = "Disarm from alarm";
  static std::string SIA_OR_DESC = "Account in alarm was reset/disarmed";

  static std::string SIA_OS      = "OS";
  static std::string SIA_OS_NAME = "Opening keyswitch";
  static std::string SIA_OS_DESC = "Account has been disarmed by keyswitch zone";

  static std::string SIA_OT      = "OT";
  static std::string SIA_OT_NAME = "Late to close";
  static std::string SIA_OT_DESC = "System was not armed on time";

  static std::string SIA_OZ      = "OZ";
  static std::string SIA_OZ_NAME = "Point opening";
  static std::string SIA_OZ_DESC = "A point, rather then a full area or account was disarmed";

  static std::string SIA_PA      = "PA";
  static std::string SIA_PA_NAME = "Panic alarm";
  static std::string SIA_PA_DESC = "Emergency assistance request, manually activated";

  static std::string SIA_PB      = "PB";
  static std::string SIA_PB_NAME = "Panic bypass";
  static std::string SIA_PB_DESC = "Panic zone has been bypassed";

  static std::string SIA_PH      = "PH";
  static std::string SIA_PH_NAME = "Panic alarm restore";
  static std::string SIA_PH_DESC = "Alarm condition eliminated";

  static std::string SIA_PJ      = "PJ";
  static std::string SIA_PJ_NAME = "Panic trouble restore";
  static std::string SIA_PJ_DESC = "Trouble condition eliminated";

  static std::string SIA_PR      = "PR";
  static std::string SIA_PR_NAME = "Panic restoral";
  static std::string SIA_PR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_PS      = "PS";
  static std::string SIA_PS_NAME = "Panic Supervisory";
  static std::string SIA_PS_DESC = "Unsafe system condition exists";

  static std::string SIA_PT      = "PT";
  static std::string SIA_PT_NAME = "Panic trouble";
  static std::string SIA_PT_DESC = "Zone disabled by fault";

  static std::string SIA_PU      = "PU";
  static std::string SIA_PU_NAME = "Panic unbypass";
  static std::string SIA_PU_DESC = "Panic zone bypass has been removed";

  static std::string SIA_QA      = "QA";
  static std::string SIA_QA_NAME = "Emergency alarm";
  static std::string SIA_QA_DESC = "Emergency assistance request, manually activated";

  static std::string SIA_QB      = "QB";
  static std::string SIA_QB_NAME = "Emergency bypass";
  static std::string SIA_QB_DESC = "Zone has been bypassed";

  static std::string SIA_QH      = "QH";
  static std::string SIA_QH_NAME = "Emergency alarm restore";
  static std::string SIA_QH_DESC = "Alarm condition eliminated";

  static std::string SIA_QJ      = "QJ";
  static std::string SIA_QJ_NAME = "Emergency trouble restore";
  static std::string SIA_QJ_DESC = "Trouble condition eliminated";

  static std::string SIA_QR      = "QR";
  static std::string SIA_QR_NAME = "Emergency restoral";
  static std::string SIA_QR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_QS      = "QS";
  static std::string SIA_QS_NAME = "Emergency Supervisory";
  static std::string SIA_QS_DESC = "Unsafe system condition exists";

  static std::string SIA_QT      = "QT";
  static std::string SIA_QT_NAME = "Emergency trouble";
  static std::string SIA_QT_DESC = "Zone disabled by fault";

  static std::string SIA_QU      = "QU";
  static std::string SIA_QU_NAME = "Emergency unbypass";
  static std::string SIA_QU_DESC = "Zone bypass has been removed";

  static std::string SIA_RA      = "RA";
  static std::string SIA_RA_NAME = "Remote programmer call failed";
  static std::string SIA_RA_DESC = "Transmitter failed to communicate with the remote programmer";

  static std::string SIA_RB      = "RB";
  static std::string SIA_RB_NAME = "Remote program begin";
  static std::string SIA_RB_DESC = "Remote programming session initiated";

  static std::string SIA_RC      = "RC";
  static std::string SIA_RC_NAME = "Relay close";
  static std::string SIA_RC_DESC = "The relay specified in the address field (optional) has energised";

  static std::string SIA_RD      = "RD";
  static std::string SIA_RD_NAME = "Remote program denied";
  static std::string SIA_RD_DESC = "Access passcode incorrect";

  static std::string SIA_RN      = "RN";
  static std::string SIA_RN_NAME = "Remote reset";
  static std::string SIA_RN_DESC = "Transmitter was reset via a remote programmer";

  static std::string SIA_RO      = "RO";
  static std::string SIA_RO_NAME = "Relay open";
  static std::string SIA_RO_DESC = "The relay specified in the address field (optional) has de-energised";

  static std::string SIA_RP      = "RP";
  static std::string SIA_RP_NAME = "Automatic test";
  static std::string SIA_RP_DESC = "Automatic communication test report";

  static std::string SIA_RR      = "RR";
  static std::string SIA_RR_NAME = "Power up";
  static std::string SIA_RR_DESC = "System lost power, is now restored";

  static std::string SIA_RS      = "RS";
  static std::string SIA_RS_NAME = "Remote program success";
  static std::string SIA_RS_DESC = "Remote programming successful";

  static std::string SIA_RT      = "RT";
  static std::string SIA_RT_NAME = "Data lost";
  static std::string SIA_RT_DESC = "Dailer data lost, transmission error";

  static std::string SIA_RU      = "RU";
  static std::string SIA_RU_NAME = "Remote program fail";
  static std::string SIA_RU_DESC = "Remote programming unsuccessful";

  static std::string SIA_RX      = "RX";
  static std::string SIA_RX_NAME = "Manual test";
  static std::string SIA_RX_DESC = "Manual communication test report";

  static std::string SIA_SA      = "SA";
  static std::string SIA_SA_NAME = "Sprinkler alarm";
  static std::string SIA_SA_DESC = "Sprinkler flow condition exists";

  static std::string SIA_SB      = "SB";
  static std::string SIA_SB_NAME = "Sprinkler bypass";
  static std::string SIA_SB_DESC = "Sprinkler zone has been bypassed";

  static std::string SIA_SH      = "SH";
  static std::string SIA_SH_NAME = "Sprinkler alarm restore";
  static std::string SIA_SH_DESC = "Alarm condition eliminated";

  static std::string SIA_SJ      = "SJ";
  static std::string SIA_SJ_NAME = "Sprinkler trouble restore";
  static std::string SIA_SJ_DESC = "Trouble condition eliminated";

  static std::string SIA_SR      = "SR";
  static std::string SIA_SR_NAME = "Sprinkler restoral";
  static std::string SIA_SR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_SS      = "SS";
  static std::string SIA_SS_NAME = "Sprinkler Supervisory";
  static std::string SIA_SS_DESC = "Unsafe sprinkler system condition exists";

  static std::string SIA_ST      = "ST";
  static std::string SIA_ST_NAME = "Sprinkler trouble";
  static std::string SIA_ST_DESC = "Zone disabled by fault";

  static std::string SIA_SU      = "SU";
  static std::string SIA_SU_NAME = "Sprinkler unbypass";
  static std::string SIA_SU_DESC = "Sprinkler zone bypass has been removed";

  static std::string SIA_TA      = "TA";
  static std::string SIA_TA_NAME = "Tamper Alarm";
  static std::string SIA_TA_DESC = "Alarm equipment enclosure opened";

  static std::string SIA_TB      = "TB";
  static std::string SIA_TB_NAME = "Tamper bypass";
  static std::string SIA_TB_DESC = "Tamper detection has been bypassed";

  static std::string SIA_TE      = "TE";
  static std::string SIA_TE_NAME = "Test end";
  static std::string SIA_TE_DESC = "Communicator restored to normal operation";

  static std::string SIA_TR      = "TR";
  static std::string SIA_TR_NAME = "Tamper restoral";
  static std::string SIA_TR_DESC = "Alarm equipment enclosure has been closed";

  static std::string SIA_TS      = "TS";
  static std::string SIA_TS_NAME = "Test start";
  static std::string SIA_TS_DESC = "Communicator taken out of operation";

  static std::string SIA_TU      = "TU";
  static std::string SIA_TU_NAME = "Tamper unbypass";
  static std::string SIA_TU_DESC = "Tamper detection bypass has been removed";

  static std::string SIA_TX      = "TX";
  static std::string SIA_TX_NAME = "Test report";
  static std::string SIA_TX_DESC = "An unspecified (manual or automatic) communicator test";

  static std::string SIA_UA      = "UA";
  static std::string SIA_UA_NAME = "Untyped zone alarm";
  static std::string SIA_UA_DESC = "Alarm condition from zone of unknown type ";

  static std::string SIA_UB      = "UB";
  static std::string SIA_UB_NAME = "Untyped zone bypass";
  static std::string SIA_UB_DESC = "Zone of unknown type has been bypassed";

  static std::string SIA_UH      = "UH";
  static std::string SIA_UH_NAME = "Untyped alarm restoral";
  static std::string SIA_UH_DESC = "Alarm condition eliminated";

  static std::string SIA_UJ      = "UJ";
  static std::string SIA_UJ_NAME = "Untyped trouble restoral";
  static std::string SIA_UJ_DESC = "Trouble condition eliminated";

  static std::string SIA_UR      = "UR";
  static std::string SIA_UR_NAME = "Untyped alarm/trouble restoral";
  static std::string SIA_UR_DESC = "Alarm/trouble condition eliminated";

  static std::string SIA_US      = "US";
  static std::string SIA_US_NAME = "Untyped zone supervisory";
  static std::string SIA_US_DESC = "Unsafe condition from zone of unknown type";

  static std::string SIA_UT      = "UT";
  static std::string SIA_UT_NAME = "Untyped zone trouble";
  static std::string SIA_UT_DESC = "Trouble condition from zone of unknown type";

  static std::string SIA_UU      = "UU";
  static std::string SIA_UU_NAME = "Untyped zone unbypass";
  static std::string SIA_UU_DESC = "Bypass of unknown zone has been removed";

  static std::string SIA_UX      = "UX";
  static std::string SIA_UX_NAME = "Undefined alarm";
  static std::string SIA_UX_DESC = "An undefined alarm condition has occured";

  static std::string SIA_UY      = "UY";
  static std::string SIA_UY_NAME = "Untyped missing trouble";
  static std::string SIA_UY_DESC = "A point which was not armed is now logically missing";

  static std::string SIA_UZ      = "UZ";
  static std::string SIA_UZ_NAME = "Untyped missing alarm";
  static std::string SIA_UZ_DESC = "A point which was armed is now logically missing";

  static std::string SIA_VI      = "VI";
  static std::string SIA_VI_NAME = "Printer paper in";
  static std::string SIA_VI_DESC = "Transmitter or receiver paper in, printer X";

  static std::string SIA_VO      = "VO";
  static std::string SIA_VO_NAME = "Printer paper out";
  static std::string SIA_VO_DESC = "Transmitter or receiver paper out, printer X";

  static std::string SIA_VR      = "VR";
  static std::string SIA_VR_NAME = "Printer restore";
  static std::string SIA_VR_DESC = "Transmitter or receiver trouble restored, printer X";

  static std::string SIA_VT      = "VT";
  static std::string SIA_VT_NAME = "Printer trouble";
  static std::string SIA_VT_DESC = "Transmitter or receiver trouble, printer X";

  static std::string SIA_VX      = "VX";
  static std::string SIA_VX_NAME = "Printer test";
  static std::string SIA_VX_DESC = "Transmitter or receiver test, printer X";

  static std::string SIA_VY      = "VY";
  static std::string SIA_VY_NAME = "Printer on line";
  static std::string SIA_VY_DESC = "The receiver\'s printer is now on line";

  static std::string SIA_VZ      = "VZ";
  static std::string SIA_VZ_NAME = "Printer off line";
  static std::string SIA_VZ_DESC = "The receiver\'s printer is now off line";

  static std::string SIA_WA      = "WA";
  static std::string SIA_WA_NAME = "Water alarm";
  static std::string SIA_WA_DESC = "Water detected at premise";

  static std::string SIA_WB      = "WB";
  static std::string SIA_WB_NAME = "Water bypass";
  static std::string SIA_WB_DESC = "Water detection zone has been bypassed";

  static std::string SIA_WH      = "WH";
  static std::string SIA_WH_NAME = "Water alarm restoral";
  static std::string SIA_WH_DESC = "Alarm condition eliminated";

  static std::string SIA_WJ      = "WJ";
  static std::string SIA_WJ_NAME = "Water trouble restoral";
  static std::string SIA_WJ_DESC = "Trouble condition eliminated";

  static std::string SIA_WR      = "WR";
  static std::string SIA_WR_NAME = "Water restoral";
  static std::string SIA_WR_DESC = "Alarm/trouble condition has been eliminated";

  static std::string SIA_WS      = "WS";
  static std::string SIA_WS_NAME = "Water supervisory";
  static std::string SIA_WS_DESC = "Unsafe water detection system detected";

  static std::string SIA_WT      = "WT";
  static std::string SIA_WT_NAME = "Water trouble";
  static std::string SIA_WT_DESC = "Zone disabled by fault";

  static std::string SIA_WU      = "WU";
  static std::string SIA_WU_NAME = "Water unbypass";
  static std::string SIA_WU_DESC = "Water detection bypass has been removed";

  static std::string SIA_XE      = "XE";
  static std::string SIA_XE_NAME = "Extra point";
  static std::string SIA_XE_DESC = "The panel has sensed an extra point not specified for this site";

  static std::string SIA_XF      = "XF";
  static std::string SIA_XF_NAME = "Extra RF point";
  static std::string SIA_XF_DESC = "The panel has sensed an extra RF point not specified for this site";

  static std::string SIA_XI      = "XI";
  static std::string SIA_XI_NAME = "Sensor reset";
  static std::string SIA_XI_DESC = "A user has reset a sensor";

  static std::string SIA_XR      = "XR";
  static std::string SIA_XR_NAME = "TX battery restoral";
  static std::string SIA_XR_DESC = "Low battery in wireless transmitter has been corrected";

  static std::string SIA_XT      = "XT";
  static std::string SIA_XT_NAME = "TX battery trouble";
  static std::string SIA_XT_DESC = "Low battery in wireless transmitter";

  static std::string SIA_XW      = "XW";
  static std::string SIA_XW_NAME = "Forced point";
  static std::string SIA_XW_DESC = "A point was forced out of the system at arm time";

  static std::string SIA_YB      = "YB";
  static std::string SIA_YB_NAME = "Busy seconds";
  static std::string SIA_YB_DESC = "Percent of time receiver\'s line card is on line";

  static std::string SIA_YC      = "YC";
  static std::string SIA_YC_NAME = "Communication fail";
  static std::string SIA_YC_DESC = "Receiver and transmitter";

  static std::string SIA_YD      = "YD";
  static std::string SIA_YD_NAME = "RX line card trouble";
  static std::string SIA_YD_DESC = "A line card identified by the passed address is in trouble";

  static std::string SIA_YE      = "YE";
  static std::string SIA_YE_NAME = "RX line card restoral";
  static std::string SIA_YE_DESC = "A line card identified by the passed address has restored";

  static std::string SIA_YF      = "YF";
  static std::string SIA_YF_NAME = "Parameter checksum fail";
  static std::string SIA_YF_DESC = "System data corrupted";

  static std::string SIA_YG      = "YG";
  static std::string SIA_YG_NAME = "Parameter changed";
  static std::string SIA_YG_DESC = "A tranmitter\'s parameters have been changed";

  static std::string SIA_YK      = "YK";
  static std::string SIA_YK_NAME = "Communication restoral";
  static std::string SIA_YK_DESC = "The transmitter has resumed communication with a receiver";

  static std::string SIA_YM      = "YM";
  static std::string SIA_YM_NAME = "System battery missing";
  static std::string SIA_YM_DESC = "The tranmitter/receiver battery is missing";

  static std::string SIA_YN      = "YN";
  static std::string SIA_YN_NAME = "Invalid report";
  static std::string SIA_YN_DESC = "The transmitter has send a packet with invalid data";

  static std::string SIA_YO      = "YO";
  static std::string SIA_YO_NAME = "Unknown message";
  static std::string SIA_YO_DESC = "An unknown message was received from automation or the printer";

  static std::string SIA_YP      = "YP";
  static std::string SIA_YP_NAME = "Power supply trouble";
  static std::string SIA_YP_DESC = "The transmitter/receiver has a problem with the power supply";

  static std::string SIA_YQ      = "YQ";
  static std::string SIA_YQ_NAME = "Power supply restored";
  static std::string SIA_YQ_DESC = "The transmitter/receiver power supply has restored";

  static std::string SIA_YR      = "YR";
  static std::string SIA_YR_NAME = "System battery restoral";
  static std::string SIA_YR_DESC = "Low battery has been corrected";

  static std::string SIA_YS      = "YS";
  static std::string SIA_YS_NAME = "Communication trouble";
  static std::string SIA_YS_DESC = "Receiver and transmitter";

  static std::string SIA_YT      = "YT";
  static std::string SIA_YT_NAME = "System battery trouble";
  static std::string SIA_YT_DESC = "Low battery in control panel/communicator";

  static std::string SIA_YW      = "YW";
  static std::string SIA_YW_NAME = "Watchdog reset";
  static std::string SIA_YW_DESC = "The transmitter created an internal reset";

  static std::string SIA_YX      = "YX";
  static std::string SIA_YX_NAME = "Service required";
  static std::string SIA_YX_DESC = "A transmitter/receiver needs service";

  static std::string SIA_YY      = "YY";
  static std::string SIA_YY_NAME = "Status report";
  static std::string SIA_YY_DESC = "This is a header for an account status report transmission";

  static std::string SIA_YZ      = "YZ";
  static std::string SIA_YZ_NAME = "Service completed";
  static std::string SIA_YZ_DESC = "Required transmitter/receiver service completed";

  static std::string SIA_ZA      = "ZA";
  static std::string SIA_ZA_NAME = "Freeze alarm";
  static std::string SIA_ZA_DESC = "Low temperature detected at premise";

  static std::string SIA_ZB      = "ZB";
  static std::string SIA_ZB_NAME = "Freeze bypass";
  static std::string SIA_ZB_DESC = "Low temperature detection has been bypassed";

  static std::string SIA_ZH      = "ZH";
  static std::string SIA_ZH_NAME = "Freeze alarm restoral";
  static std::string SIA_ZH_DESC = "Alarm condition eliminated";

  static std::string SIA_ZJ      = "ZJ";
  static std::string SIA_ZJ_NAME = "Freeze trouble restoral";
  static std::string SIA_ZJ_DESC = "Trouble condition eliminated";

  static std::string SIA_ZR      = "ZR";
  static std::string SIA_ZR_NAME = "Freeze restoral";
  static std::string SIA_ZR_DESC = "Alarm/trouble condition has been eliminated";

  static std::string SIA_ZS      = "ZS";
  static std::string SIA_ZS_NAME = "Freeze supervisory";
  static std::string SIA_ZS_DESC = "Unsafe freeze detection system condition detected";

  static std::string SIA_ZT      = "ZT";
  static std::string SIA_ZT_NAME = "Freeze trouble";
  static std::string SIA_ZT_DESC = "Zone disabled by fault";

  static std::string SIA_ZU      = "ZU";
  static std::string SIA_ZU_NAME = "Freeze unbypass";
  static std::string SIA_ZU_DESC = "Low temperature detection bypass removed";

  static SiaEventCode SiaEventCode_0( SIA_AR, SIA_AR_NAME, SIA_AR_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_1( SIA_AT, SIA_AT_NAME, SIA_AT_DESC, SiaEventCode::AddressField::unused);
      
  static SiaEventCode SiaEventCode_2( SIA_BA, SIA_BA_NAME, SIA_BA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_3( SIA_BB, SIA_BB_NAME, SIA_BB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_4( SIA_BC, SIA_BC_NAME, SIA_BC_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_5( SIA_BH, SIA_BH_NAME, SIA_BH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_6( SIA_BJ, SIA_BJ_NAME, SIA_BJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_7( SIA_BR, SIA_BR_NAME, SIA_BR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_8( SIA_BS, SIA_BS_NAME, SIA_BS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_9( SIA_BT, SIA_BT_NAME, SIA_BT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_10( SIA_BU, SIA_BU_NAME, SIA_BU_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_11( SIA_BV, SIA_BV_NAME, SIA_BV_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_12( SIA_BX, SIA_BX_NAME, SIA_BX_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_13( SIA_CA, SIA_CA_NAME, SIA_CA_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_14( SIA_CE, SIA_CE_NAME, SIA_CE_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_15( SIA_CF, SIA_CF_NAME, SIA_CF_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_16( SIA_CG, SIA_CG_NAME, SIA_CG_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_17( SIA_CI, SIA_CI_NAME, SIA_CI_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_18( SIA_CJ, SIA_CJ_NAME, SIA_CJ_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_19( SIA_CK, SIA_CK_NAME, SIA_CK_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_20( SIA_CL, SIA_CL_NAME, SIA_CL_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_21( SIA_CP, SIA_CP_NAME, SIA_CP_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_22( SIA_CR, SIA_CR_NAME, SIA_CR_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_23( SIA_CS, SIA_CS_NAME, SIA_CS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_24( SIA_CT, SIA_CT_NAME, SIA_CT_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_25( SIA_CW, SIA_CW_NAME, SIA_CW_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_26( SIA_CZ, SIA_CZ_NAME, SIA_CZ_DESC, SiaEventCode::AddressField::zone);

  static SiaEventCode SiaEventCode_27( SIA_DC, SIA_DC_NAME, SIA_DC_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_28( SIA_DD, SIA_DD_NAME, SIA_DD_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_29( SIA_DF, SIA_DF_NAME, SIA_DF_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_30( SIA_DG, SIA_DG_NAME, SIA_DG_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_31( SIA_DK, SIA_DK_NAME, SIA_DK_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_32( SIA_DO, SIA_DO_NAME, SIA_DO_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_33( SIA_DR, SIA_DR_NAME, SIA_DR_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_34( SIA_DS, SIA_DS_NAME, SIA_DS_DESC, SiaEventCode::AddressField::door);
  static SiaEventCode SiaEventCode_35( SIA_DT, SIA_DT_NAME, SIA_DT_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_36( SIA_DU, SIA_DU_NAME, SIA_DU_DESC, SiaEventCode::AddressField::dealer_id);

  static SiaEventCode SiaEventCode_37( SIA_EA, SIA_EA_NAME, SIA_EA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_38( SIA_EE, SIA_EE_NAME, SIA_EE_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_39( SIA_ER, SIA_ER_NAME, SIA_ER_DESC, SiaEventCode::AddressField::expander);
  static SiaEventCode SiaEventCode_40( SIA_ET, SIA_ET_NAME, SIA_ET_DESC, SiaEventCode::AddressField::expander);

  static SiaEventCode SiaEventCode_41( SIA_FA, SIA_FA_NAME, SIA_FA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_42( SIA_FB, SIA_FB_NAME, SIA_FB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_43( SIA_FH, SIA_FH_NAME, SIA_FH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_44( SIA_FI, SIA_FI_NAME, SIA_FI_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_45( SIA_FJ, SIA_FJ_NAME, SIA_FJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_46( SIA_FK, SIA_FK_NAME, SIA_FK_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_47( SIA_FR, SIA_FR_NAME, SIA_FR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_48( SIA_FS, SIA_FS_NAME, SIA_FS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_49( SIA_FT, SIA_FT_NAME, SIA_FT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_50( SIA_FU, SIA_FU_NAME, SIA_FU_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_51( SIA_FX, SIA_FX_NAME, SIA_FX_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_52( SIA_FY, SIA_FY_NAME, SIA_FY_DESC, SiaEventCode::AddressField::zone);

  static SiaEventCode SiaEventCode_53( SIA_GA, SIA_GA_NAME, SIA_GA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_54( SIA_GB, SIA_GB_NAME, SIA_GB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_55( SIA_GH, SIA_GH_NAME, SIA_GH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_56( SIA_GJ, SIA_GJ_NAME, SIA_GJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_57( SIA_GR, SIA_GR_NAME, SIA_GR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_58( SIA_GS, SIA_GS_NAME, SIA_GS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_59( SIA_GT, SIA_GT_NAME, SIA_GT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_60( SIA_GU, SIA_GU_NAME, SIA_GU_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_61( SIA_GX, SIA_GX_NAME, SIA_GX_DESC, SiaEventCode::AddressField::zone);

  static SiaEventCode SiaEventCode_62( SIA_HA, SIA_HA_NAME, SIA_HA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_63( SIA_HB, SIA_HB_NAME, SIA_HB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_64( SIA_HH, SIA_HH_NAME, SIA_HH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_65( SIA_HJ, SIA_HJ_NAME, SIA_HJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_66( SIA_HR, SIA_HR_NAME, SIA_HR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_67( SIA_HS, SIA_HS_NAME, SIA_HS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_68( SIA_HT, SIA_HT_NAME, SIA_HT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_69( SIA_HU, SIA_HU_NAME, SIA_HU_DESC, SiaEventCode::AddressField::zone);

  static SiaEventCode SiaEventCode_70( SIA_JA, SIA_JA_NAME, SIA_JA_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_71( SIA_JD, SIA_JD_NAME, SIA_JD_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_72( SIA_JH, SIA_JH_NAME, SIA_JH_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_73( SIA_JL, SIA_JL_NAME, SIA_JL_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_74( SIA_JO, SIA_JO_NAME, SIA_JO_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_75( SIA_JR, SIA_JR_NAME, SIA_JR_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_76( SIA_JS, SIA_JS_NAME, SIA_JS_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_77( SIA_JT, SIA_JT_NAME, SIA_JT_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_78( SIA_JV, SIA_JV_NAME, SIA_JV_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_79( SIA_JX, SIA_JX_NAME, SIA_JX_DESC, SiaEventCode::AddressField::user);

  static SiaEventCode SiaEventCode_80( SIA_KA, SIA_KA_NAME, SIA_KA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_81( SIA_KB, SIA_KB_NAME, SIA_KB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_82( SIA_KH, SIA_KH_NAME, SIA_KH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_83( SIA_KJ, SIA_KJ_NAME, SIA_KJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_84( SIA_KR, SIA_KR_NAME, SIA_KR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_85( SIA_KS, SIA_KS_NAME, SIA_KS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_86( SIA_KT, SIA_KT_NAME, SIA_KT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_87( SIA_KU, SIA_KU_NAME, SIA_KU_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_88( SIA_LB, SIA_LB_NAME, SIA_LB_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_89( SIA_LD, SIA_LD_NAME, SIA_LD_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_90( SIA_LE, SIA_LE_NAME, SIA_LE_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_91( SIA_LF, SIA_LF_NAME, SIA_LF_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_92( SIA_LR, SIA_LR_NAME, SIA_LR_DESC, SiaEventCode::AddressField::line);
  static SiaEventCode SiaEventCode_93( SIA_LS, SIA_LS_NAME, SIA_LS_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_94( SIA_LT, SIA_LT_NAME, SIA_LT_DESC, SiaEventCode::AddressField::line);
  static SiaEventCode SiaEventCode_95( SIA_LU, SIA_LU_NAME, SIA_LU_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_96( SIA_LX, SIA_LX_NAME, SIA_LX_DESC, SiaEventCode::AddressField::unused);

  static SiaEventCode SiaEventCode_97( SIA_MA, SIA_MA_NAME, SIA_MA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_98( SIA_MB, SIA_MB_NAME, SIA_MB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_99( SIA_MH, SIA_MH_NAME, SIA_MH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_100( SIA_MJ, SIA_MJ_NAME, SIA_MJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_101( SIA_MR, SIA_MR_NAME, SIA_MR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_102( SIA_MS, SIA_MS_NAME, SIA_MS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_103( SIA_MT, SIA_MT_NAME, SIA_MT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_104( SIA_MU, SIA_MU_NAME, SIA_MU_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_105( SIA_NA, SIA_NA_NAME, SIA_NA_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_106( SIA_NF, SIA_NF_NAME, SIA_NF_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_107( SIA_NL, SIA_NL_NAME, SIA_NL_DESC, SiaEventCode::AddressField::area);

  static SiaEventCode SiaEventCode_108( SIA_OA, SIA_OA_NAME, SIA_OA_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_109( SIA_OC, SIA_OC_NAME, SIA_OC_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_110( SIA_OG, SIA_OG_NAME, SIA_OG_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_111( SIA_OI, SIA_OI_NAME, SIA_OI_DESC, SiaEventCode::AddressField::area);
  static SiaEventCode SiaEventCode_112( SIA_OJ, SIA_OJ_NAME, SIA_OJ_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_113( SIA_OK, SIA_OK_NAME, SIA_OK_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_114( SIA_OP, SIA_OP_NAME, SIA_OP_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_115( SIA_OR, SIA_OR_NAME, SIA_OR_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_116( SIA_OS, SIA_OS_NAME, SIA_OS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_117( SIA_OT, SIA_OT_NAME, SIA_OT_DESC, SiaEventCode::AddressField::user);
  static SiaEventCode SiaEventCode_118( SIA_OZ, SIA_OZ_NAME, SIA_OZ_DESC, SiaEventCode::AddressField::zone);

  static SiaEventCode SiaEventCode_119( SIA_PA, SIA_PA_NAME, SIA_PA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_120( SIA_PB, SIA_PB_NAME, SIA_PB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_121( SIA_PH, SIA_PH_NAME, SIA_PH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_122( SIA_PJ, SIA_PJ_NAME, SIA_PJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_123( SIA_PR, SIA_PR_NAME, SIA_PR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_124( SIA_PS, SIA_PS_NAME, SIA_PS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_125( SIA_PT, SIA_PT_NAME, SIA_PT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_126( SIA_PU, SIA_PU_NAME, SIA_PU_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_127( SIA_QA, SIA_QA_NAME, SIA_QA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_128( SIA_QB, SIA_QB_NAME, SIA_QB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_129( SIA_QH, SIA_QH_NAME, SIA_QH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_130( SIA_QJ, SIA_QJ_NAME, SIA_QJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_131( SIA_QR, SIA_QR_NAME, SIA_QR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_132( SIA_QS, SIA_QS_NAME, SIA_QS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_133( SIA_QT, SIA_QT_NAME, SIA_QT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_134( SIA_QU, SIA_QU_NAME, SIA_QU_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_135( SIA_RA, SIA_RA_NAME, SIA_RA_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_136( SIA_RB, SIA_RB_NAME, SIA_RB_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_137( SIA_RC, SIA_RC_NAME, SIA_RC_DESC, SiaEventCode::AddressField::relay);
  static SiaEventCode SiaEventCode_138( SIA_RD, SIA_RD_NAME, SIA_RD_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_139( SIA_RN, SIA_RN_NAME, SIA_RN_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_140( SIA_RO, SIA_RO_NAME, SIA_RO_DESC, SiaEventCode::AddressField::relay);
  static SiaEventCode SiaEventCode_141( SIA_RP, SIA_RP_NAME, SIA_RP_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_142( SIA_RR, SIA_RR_NAME, SIA_RR_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_143( SIA_RS, SIA_RS_NAME, SIA_RS_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_144( SIA_RT, SIA_RT_NAME, SIA_RT_DESC, SiaEventCode::AddressField::line);
  static SiaEventCode SiaEventCode_145( SIA_RU, SIA_RU_NAME, SIA_RU_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_146( SIA_RX, SIA_RX_NAME, SIA_RX_DESC, SiaEventCode::AddressField::user);
      
  static SiaEventCode SiaEventCode_147( SIA_SA, SIA_SA_NAME, SIA_SA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_148( SIA_SB, SIA_SB_NAME, SIA_SB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_149( SIA_SH, SIA_SH_NAME, SIA_SH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_150( SIA_SJ, SIA_SJ_NAME, SIA_SJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_151( SIA_SR, SIA_SR_NAME, SIA_SR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_152( SIA_SS, SIA_SS_NAME, SIA_SS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_153( SIA_ST, SIA_ST_NAME, SIA_ST_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_154( SIA_SU, SIA_SU_NAME, SIA_SU_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_155( SIA_TA, SIA_TA_NAME, SIA_TA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_156( SIA_TB, SIA_TB_NAME, SIA_TB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_157( SIA_TE, SIA_TE_NAME, SIA_TE_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_158( SIA_TR, SIA_TR_NAME, SIA_TR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_159( SIA_TS, SIA_TS_NAME, SIA_TS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_160( SIA_TU, SIA_TU_NAME, SIA_TU_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_161( SIA_TX, SIA_TX_NAME, SIA_TX_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_162( SIA_UA, SIA_UA_NAME, SIA_UA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_163( SIA_UB, SIA_UB_NAME, SIA_UB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_164( SIA_UH, SIA_UH_NAME, SIA_UH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_165( SIA_UJ, SIA_UJ_NAME, SIA_UJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_166( SIA_UR, SIA_UR_NAME, SIA_UR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_167( SIA_US, SIA_US_NAME, SIA_US_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_168( SIA_UT, SIA_UT_NAME, SIA_UT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_169( SIA_UU, SIA_UU_NAME, SIA_UU_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_170( SIA_UX, SIA_UX_NAME, SIA_UX_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_171( SIA_UY, SIA_UY_NAME, SIA_UY_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_172( SIA_UZ, SIA_UZ_NAME, SIA_UZ_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_173( SIA_VI, SIA_VI_NAME, SIA_VI_DESC, SiaEventCode::AddressField::printer);
  static SiaEventCode SiaEventCode_174( SIA_VO, SIA_VO_NAME, SIA_VO_DESC, SiaEventCode::AddressField::printer);
  static SiaEventCode SiaEventCode_175( SIA_VR, SIA_VR_NAME, SIA_VR_DESC, SiaEventCode::AddressField::printer);
  static SiaEventCode SiaEventCode_176( SIA_VT, SIA_VT_NAME, SIA_VT_DESC, SiaEventCode::AddressField::printer);
  static SiaEventCode SiaEventCode_177( SIA_VX, SIA_VX_NAME, SIA_VX_DESC, SiaEventCode::AddressField::printer);
  static SiaEventCode SiaEventCode_178( SIA_VY, SIA_VY_NAME, SIA_VY_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_179( SIA_VZ, SIA_VZ_NAME, SIA_VZ_DESC, SiaEventCode::AddressField::unused);
      
  static SiaEventCode SiaEventCode_180( SIA_WA, SIA_WA_NAME, SIA_WA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_181( SIA_WB, SIA_WB_NAME, SIA_WB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_182( SIA_WH, SIA_WH_NAME, SIA_WH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_183( SIA_WJ, SIA_WJ_NAME, SIA_WJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_184( SIA_WR, SIA_WR_NAME, SIA_WR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_185( SIA_WS, SIA_WS_NAME, SIA_WS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_186( SIA_WT, SIA_WT_NAME, SIA_WT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_187( SIA_WU, SIA_WU_NAME, SIA_WU_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_188( SIA_XE, SIA_XE_NAME, SIA_XE_DESC, SiaEventCode::AddressField::point);
  static SiaEventCode SiaEventCode_189( SIA_XF, SIA_XF_NAME, SIA_XF_DESC, SiaEventCode::AddressField::point);
  static SiaEventCode SiaEventCode_190( SIA_XI, SIA_XI_NAME, SIA_XI_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_191( SIA_XR, SIA_XR_NAME, SIA_XR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_192( SIA_XT, SIA_XT_NAME, SIA_XT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_193( SIA_XW, SIA_XW_NAME, SIA_XW_DESC, SiaEventCode::AddressField::zone);
      
  static SiaEventCode SiaEventCode_194( SIA_YB, SIA_YB_NAME, SIA_YB_DESC, SiaEventCode::AddressField::line);
  static SiaEventCode SiaEventCode_195( SIA_YC, SIA_YC_NAME, SIA_YC_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_196( SIA_YD, SIA_YD_NAME, SIA_YD_DESC, SiaEventCode::AddressField::line);
  static SiaEventCode SiaEventCode_197( SIA_YE, SIA_YE_NAME, SIA_YE_DESC, SiaEventCode::AddressField::line);
  static SiaEventCode SiaEventCode_198( SIA_YF, SIA_YF_NAME, SIA_YF_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_199( SIA_YG, SIA_YG_NAME, SIA_YG_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_200( SIA_YK, SIA_YK_NAME, SIA_YK_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_201( SIA_YM, SIA_YM_NAME, SIA_YM_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_202( SIA_YN, SIA_YN_NAME, SIA_YN_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_203( SIA_YO, SIA_YO_NAME, SIA_YO_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_204( SIA_YP, SIA_YP_NAME, SIA_YP_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_205( SIA_YQ, SIA_YQ_NAME, SIA_YQ_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_206( SIA_YR, SIA_YR_NAME, SIA_YR_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_207( SIA_YS, SIA_YS_NAME, SIA_YS_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_208( SIA_YT, SIA_YT_NAME, SIA_YT_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_209( SIA_YW, SIA_YW_NAME, SIA_YW_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_210( SIA_YX, SIA_YX_NAME, SIA_YX_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_211( SIA_YY, SIA_YY_NAME, SIA_YY_DESC, SiaEventCode::AddressField::unused);
  static SiaEventCode SiaEventCode_212( SIA_YZ, SIA_YZ_NAME, SIA_YZ_DESC, SiaEventCode::AddressField::mfr_defined);
      
  static SiaEventCode SiaEventCode_213( SIA_ZA, SIA_ZA_NAME, SIA_ZA_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_214( SIA_ZB, SIA_ZB_NAME, SIA_ZB_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_215( SIA_ZH, SIA_ZH_NAME, SIA_ZH_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_216( SIA_ZJ, SIA_ZJ_NAME, SIA_ZJ_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_217( SIA_ZR, SIA_ZR_NAME, SIA_ZR_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_218( SIA_ZS, SIA_ZS_NAME, SIA_ZS_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_219( SIA_ZT, SIA_ZT_NAME, SIA_ZT_DESC, SiaEventCode::AddressField::zone);
  static SiaEventCode SiaEventCode_220( SIA_ZU, SIA_ZU_NAME, SIA_ZU_DESC, SiaEventCode::AddressField::zone);

  m_SiaEvents.append(&SiaEventCode_0);
  m_SiaEvents.append(&SiaEventCode_1);
  m_SiaEvents.append(&SiaEventCode_2);
  m_SiaEvents.append(&SiaEventCode_3);
  m_SiaEvents.append(&SiaEventCode_4);
  m_SiaEvents.append(&SiaEventCode_5);
  m_SiaEvents.append(&SiaEventCode_6);
  m_SiaEvents.append(&SiaEventCode_7);
  m_SiaEvents.append(&SiaEventCode_8);
  m_SiaEvents.append(&SiaEventCode_9);
  m_SiaEvents.append(&SiaEventCode_10);
  m_SiaEvents.append(&SiaEventCode_11);
  m_SiaEvents.append(&SiaEventCode_12);
  m_SiaEvents.append(&SiaEventCode_13);
  m_SiaEvents.append(&SiaEventCode_14);
  m_SiaEvents.append(&SiaEventCode_15);
  m_SiaEvents.append(&SiaEventCode_16);
  m_SiaEvents.append(&SiaEventCode_17);
  m_SiaEvents.append(&SiaEventCode_18);
  m_SiaEvents.append(&SiaEventCode_19);
  m_SiaEvents.append(&SiaEventCode_20);
  m_SiaEvents.append(&SiaEventCode_21);
  m_SiaEvents.append(&SiaEventCode_22);
  m_SiaEvents.append(&SiaEventCode_23);
  m_SiaEvents.append(&SiaEventCode_24);
  m_SiaEvents.append(&SiaEventCode_25);
  m_SiaEvents.append(&SiaEventCode_26);
  m_SiaEvents.append(&SiaEventCode_27);
  m_SiaEvents.append(&SiaEventCode_28);
  m_SiaEvents.append(&SiaEventCode_29);
  m_SiaEvents.append(&SiaEventCode_30);
  m_SiaEvents.append(&SiaEventCode_31);
  m_SiaEvents.append(&SiaEventCode_32);
  m_SiaEvents.append(&SiaEventCode_33);
  m_SiaEvents.append(&SiaEventCode_34);
  m_SiaEvents.append(&SiaEventCode_35);
  m_SiaEvents.append(&SiaEventCode_36);
  m_SiaEvents.append(&SiaEventCode_37);
  m_SiaEvents.append(&SiaEventCode_38);
  m_SiaEvents.append(&SiaEventCode_39);
  m_SiaEvents.append(&SiaEventCode_40);
  m_SiaEvents.append(&SiaEventCode_41);
  m_SiaEvents.append(&SiaEventCode_42);
  m_SiaEvents.append(&SiaEventCode_43);
  m_SiaEvents.append(&SiaEventCode_44);
  m_SiaEvents.append(&SiaEventCode_45);
  m_SiaEvents.append(&SiaEventCode_46);
  m_SiaEvents.append(&SiaEventCode_47);
  m_SiaEvents.append(&SiaEventCode_48);
  m_SiaEvents.append(&SiaEventCode_49);
  m_SiaEvents.append(&SiaEventCode_50);
  m_SiaEvents.append(&SiaEventCode_51);
  m_SiaEvents.append(&SiaEventCode_52);
  m_SiaEvents.append(&SiaEventCode_53);
  m_SiaEvents.append(&SiaEventCode_54);
  m_SiaEvents.append(&SiaEventCode_55);
  m_SiaEvents.append(&SiaEventCode_56);
  m_SiaEvents.append(&SiaEventCode_57);
  m_SiaEvents.append(&SiaEventCode_58);
  m_SiaEvents.append(&SiaEventCode_59);
  m_SiaEvents.append(&SiaEventCode_60);
  m_SiaEvents.append(&SiaEventCode_61);
  m_SiaEvents.append(&SiaEventCode_62);
  m_SiaEvents.append(&SiaEventCode_63);
  m_SiaEvents.append(&SiaEventCode_64);
  m_SiaEvents.append(&SiaEventCode_65);
  m_SiaEvents.append(&SiaEventCode_66);
  m_SiaEvents.append(&SiaEventCode_67);
  m_SiaEvents.append(&SiaEventCode_68);
  m_SiaEvents.append(&SiaEventCode_69);
  m_SiaEvents.append(&SiaEventCode_70);
  m_SiaEvents.append(&SiaEventCode_71);
  m_SiaEvents.append(&SiaEventCode_72);
  m_SiaEvents.append(&SiaEventCode_73);
  m_SiaEvents.append(&SiaEventCode_74);
  m_SiaEvents.append(&SiaEventCode_75);
  m_SiaEvents.append(&SiaEventCode_76);
  m_SiaEvents.append(&SiaEventCode_77);
  m_SiaEvents.append(&SiaEventCode_78);
  m_SiaEvents.append(&SiaEventCode_79);
  m_SiaEvents.append(&SiaEventCode_80);
  m_SiaEvents.append(&SiaEventCode_81);
  m_SiaEvents.append(&SiaEventCode_82);
  m_SiaEvents.append(&SiaEventCode_83);
  m_SiaEvents.append(&SiaEventCode_84);
  m_SiaEvents.append(&SiaEventCode_85);
  m_SiaEvents.append(&SiaEventCode_86);
  m_SiaEvents.append(&SiaEventCode_87);
  m_SiaEvents.append(&SiaEventCode_88);
  m_SiaEvents.append(&SiaEventCode_89);
  m_SiaEvents.append(&SiaEventCode_90);
  m_SiaEvents.append(&SiaEventCode_91);
  m_SiaEvents.append(&SiaEventCode_92);
  m_SiaEvents.append(&SiaEventCode_93);
  m_SiaEvents.append(&SiaEventCode_94);
  m_SiaEvents.append(&SiaEventCode_95);
  m_SiaEvents.append(&SiaEventCode_96);
  m_SiaEvents.append(&SiaEventCode_97);
  m_SiaEvents.append(&SiaEventCode_98);
  m_SiaEvents.append(&SiaEventCode_99);
  m_SiaEvents.append(&SiaEventCode_100);
  m_SiaEvents.append(&SiaEventCode_101);
  m_SiaEvents.append(&SiaEventCode_102);
  m_SiaEvents.append(&SiaEventCode_103);
  m_SiaEvents.append(&SiaEventCode_104);
  m_SiaEvents.append(&SiaEventCode_105);
  m_SiaEvents.append(&SiaEventCode_106);
  m_SiaEvents.append(&SiaEventCode_107);
  m_SiaEvents.append(&SiaEventCode_108);
  m_SiaEvents.append(&SiaEventCode_109);
  m_SiaEvents.append(&SiaEventCode_110);
  m_SiaEvents.append(&SiaEventCode_111);
  m_SiaEvents.append(&SiaEventCode_112);
  m_SiaEvents.append(&SiaEventCode_113);
  m_SiaEvents.append(&SiaEventCode_114);
  m_SiaEvents.append(&SiaEventCode_115);
  m_SiaEvents.append(&SiaEventCode_116);
  m_SiaEvents.append(&SiaEventCode_117);
  m_SiaEvents.append(&SiaEventCode_118);
  m_SiaEvents.append(&SiaEventCode_119);
  m_SiaEvents.append(&SiaEventCode_120);
  m_SiaEvents.append(&SiaEventCode_121);
  m_SiaEvents.append(&SiaEventCode_122);
  m_SiaEvents.append(&SiaEventCode_123);
  m_SiaEvents.append(&SiaEventCode_124);
  m_SiaEvents.append(&SiaEventCode_125);
  m_SiaEvents.append(&SiaEventCode_126);
  m_SiaEvents.append(&SiaEventCode_127);
  m_SiaEvents.append(&SiaEventCode_128);
  m_SiaEvents.append(&SiaEventCode_129);
  m_SiaEvents.append(&SiaEventCode_130);
  m_SiaEvents.append(&SiaEventCode_131);
  m_SiaEvents.append(&SiaEventCode_132);
  m_SiaEvents.append(&SiaEventCode_133);
  m_SiaEvents.append(&SiaEventCode_134);
  m_SiaEvents.append(&SiaEventCode_135);
  m_SiaEvents.append(&SiaEventCode_136);
  m_SiaEvents.append(&SiaEventCode_137);
  m_SiaEvents.append(&SiaEventCode_138);
  m_SiaEvents.append(&SiaEventCode_139);
  m_SiaEvents.append(&SiaEventCode_140);
  m_SiaEvents.append(&SiaEventCode_141);
  m_SiaEvents.append(&SiaEventCode_142);
  m_SiaEvents.append(&SiaEventCode_143);
  m_SiaEvents.append(&SiaEventCode_144);
  m_SiaEvents.append(&SiaEventCode_145);
  m_SiaEvents.append(&SiaEventCode_146);
  m_SiaEvents.append(&SiaEventCode_147);
  m_SiaEvents.append(&SiaEventCode_148);
  m_SiaEvents.append(&SiaEventCode_149);
  m_SiaEvents.append(&SiaEventCode_150);
  m_SiaEvents.append(&SiaEventCode_151);
  m_SiaEvents.append(&SiaEventCode_152);
  m_SiaEvents.append(&SiaEventCode_153);
  m_SiaEvents.append(&SiaEventCode_154);
  m_SiaEvents.append(&SiaEventCode_155);
  m_SiaEvents.append(&SiaEventCode_156);
  m_SiaEvents.append(&SiaEventCode_157);
  m_SiaEvents.append(&SiaEventCode_158);
  m_SiaEvents.append(&SiaEventCode_159);
  m_SiaEvents.append(&SiaEventCode_160);
  m_SiaEvents.append(&SiaEventCode_161);
  m_SiaEvents.append(&SiaEventCode_162);
  m_SiaEvents.append(&SiaEventCode_163);
  m_SiaEvents.append(&SiaEventCode_164);
  m_SiaEvents.append(&SiaEventCode_165);
  m_SiaEvents.append(&SiaEventCode_166);
  m_SiaEvents.append(&SiaEventCode_167);
  m_SiaEvents.append(&SiaEventCode_168);
  m_SiaEvents.append(&SiaEventCode_169);
  m_SiaEvents.append(&SiaEventCode_170);
  m_SiaEvents.append(&SiaEventCode_171);
  m_SiaEvents.append(&SiaEventCode_172);
  m_SiaEvents.append(&SiaEventCode_173);
  m_SiaEvents.append(&SiaEventCode_174);
  m_SiaEvents.append(&SiaEventCode_175);
  m_SiaEvents.append(&SiaEventCode_176);
  m_SiaEvents.append(&SiaEventCode_177);
  m_SiaEvents.append(&SiaEventCode_178);
  m_SiaEvents.append(&SiaEventCode_179);
  m_SiaEvents.append(&SiaEventCode_180);
  m_SiaEvents.append(&SiaEventCode_181);
  m_SiaEvents.append(&SiaEventCode_182);
  m_SiaEvents.append(&SiaEventCode_183);
  m_SiaEvents.append(&SiaEventCode_184);
  m_SiaEvents.append(&SiaEventCode_185);
  m_SiaEvents.append(&SiaEventCode_186);
  m_SiaEvents.append(&SiaEventCode_187);
  m_SiaEvents.append(&SiaEventCode_188);
  m_SiaEvents.append(&SiaEventCode_189);
  m_SiaEvents.append(&SiaEventCode_190);
  m_SiaEvents.append(&SiaEventCode_191);
  m_SiaEvents.append(&SiaEventCode_192);
  m_SiaEvents.append(&SiaEventCode_193);
  m_SiaEvents.append(&SiaEventCode_194);
  m_SiaEvents.append(&SiaEventCode_195);
  m_SiaEvents.append(&SiaEventCode_196);
  m_SiaEvents.append(&SiaEventCode_197);
  m_SiaEvents.append(&SiaEventCode_198);
  m_SiaEvents.append(&SiaEventCode_199);
  m_SiaEvents.append(&SiaEventCode_200);
  m_SiaEvents.append(&SiaEventCode_201);
  m_SiaEvents.append(&SiaEventCode_202);
  m_SiaEvents.append(&SiaEventCode_203);
  m_SiaEvents.append(&SiaEventCode_204);
  m_SiaEvents.append(&SiaEventCode_205);
  m_SiaEvents.append(&SiaEventCode_206);
  m_SiaEvents.append(&SiaEventCode_207);
  m_SiaEvents.append(&SiaEventCode_208);
  m_SiaEvents.append(&SiaEventCode_209);
  m_SiaEvents.append(&SiaEventCode_210);
  m_SiaEvents.append(&SiaEventCode_211);
  m_SiaEvents.append(&SiaEventCode_212);
  m_SiaEvents.append(&SiaEventCode_213);
  m_SiaEvents.append(&SiaEventCode_214);
  m_SiaEvents.append(&SiaEventCode_215);
  m_SiaEvents.append(&SiaEventCode_216);
  m_SiaEvents.append(&SiaEventCode_217);
  m_SiaEvents.append(&SiaEventCode_218);
  m_SiaEvents.append(&SiaEventCode_219);
  m_SiaEvents.append(&SiaEventCode_220);
}

} // ends namespace openGalaxy

