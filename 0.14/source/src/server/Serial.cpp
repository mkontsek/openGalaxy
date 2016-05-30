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

 /* Compile with DEBUG_SERIAL defined to dump bytes to the screen... */

#include "atomic.h"

#include "Syslog.hpp"
#include "Settings.hpp"
#include "Serial.hpp"

#include "opengalaxy.hpp"

#include <thread>
#include <mutex>
#include <condition_variable>
#include <fcntl.h>

#if __linux__
#include <termios.h>
#endif 

namespace openGalaxy {

#ifdef DEBUG_SERIAL
// prints the content of a buffer
static void pbuffer(const char *str, const unsigned char *buf, int l)
{
  int t, c=0;
  unsigned char b16[16];
  for( int t=0; t<l; t++) {
    if(!c) printf("%s",str);
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
#endif

#if __linux__
///
/// Opens the serial port
///
bool SerialPort::open(void)
{
  if(m_bIsOpen==false){
    // open the tty for reading and writing, and it is not a console
    m_nTTY = ::open(opengalaxy().settings().receiver_tty.c_str(),O_RDWR|O_NOCTTY);
    if(m_nTTY<0){
      opengalaxy().syslog().error("Serial: Error, could not open tty: %s. Are you a member of group 'dialout'?",opengalaxy().settings().receiver_tty.c_str());
      return false;
    }

    // save the current tty settings
    tcgetattr(m_nTTY,&m_oldtio);

    // setup and apply our tty settings
    memset(&m_tio,0,sizeof(struct termios));

    //
    // Baudrate = 300, 600, 1200, 2400, 4800, 9600, 19200, 38400 or 57600 baud.
    // CRTSCTS -> Use hardware flow control.
    // CS8 -> 8 data bits, no parity, 1 stop bit.
    // CLOCAL -> direct connection, not a modem.
    // CREAD -> Open port for reading.
    //
    m_tio.c_cflag=opengalaxy().settings().receiver_baudrate_termios|IXON|CS8|CLOCAL|CREAD;

    m_tio.c_iflag=IGNPAR;              // raw input, do not look at parity
    m_tio.c_oflag=IGNPAR;              // raw output, no parity
    m_tio.c_lflag=0;                   // input mode: non-canonical, no echo

    m_tio.c_cc[VMIN]=0;                // Blocking read function until at least 0 (VMIN) characters
    m_tio.c_cc[VTIME]=10;              // have been read OR until 10*0.1seconds (VTIME) have passed.
                                       // Note: If VMIN>0 the timer starts when the 1st byte was received

    tcflush(m_nTTY,TCIFLUSH);          // flush buffers
    tcsetattr(m_nTTY,TCSANOW,&m_tio ); // start using new settings

    m_bIsOpen=true;
  }

  return true;
}

///
/// Closes the serial port
///
void SerialPort::close(void)
{
  if(m_bIsOpen==true){
    tcsetattr(m_nTTY,TCSANOW,&m_oldtio);
    ::close(m_nTTY);
    m_bIsOpen=false;
  }
}

///
/// Reads from open serial port
///
/// This function blocks for a maximum of VTIME * 0.1 = 10 * 0.1 = 1 second(s)
///  while receiving a maximum of 'count' bytes.
///
/// Returns the number of bytes read
///
size_t SerialPort::read(void* buf,size_t count)
{
  if(m_bIsOpen==true){
    size_t retv = ::read(m_nTTY,buf,count);
    if(retv) opengalaxy().syslog().debug("Serial: Read %d byte(s) from %s", retv, opengalaxy().settings().receiver_tty.c_str());
#ifdef DEBUG_SERIAL
    if(retv && opengalaxy().syslog().get_level()>=Syslog::Level::Debug) pbuffer("read: ",(const unsigned char*)buf, retv);
#endif
    return retv;
  }
  return 0;
}

///
/// Writes to open serial port
///
/// Returns the number of bytes written
///
size_t SerialPort::write(void* buf,size_t count)
{
  if(m_bIsOpen==true){
    opengalaxy().syslog().debug("Serial: Write %d byte(s) to %s", count, opengalaxy().settings().receiver_tty.c_str());
#ifdef DEBUG_SERIAL
    if(count && opengalaxy().syslog().get_level()>=Syslog::Level::Debug) pbuffer("write: ",(const unsigned char*)buf, count);
#endif
    size_t retv = ::write(m_nTTY,buf,count);
    fsync(m_nTTY); // flush cache (ie write immediately)
    return retv;
  }
  return 0;
}

#endif // ends IF __linux__

#ifdef _WIN32
///
/// Class openGalaxy::Serial implementation for Windows
///

/*
  communication port configuartion:
  https://msdn.microsoft.com/en-us/library/windows/desktop/aa363201(v=vs.85).aspx

  More on communication port configuartion:
  https://technet.microsoft.com/en-us/library/bb490932.aspx

  baud   = b                      : Specifies the transmission rate in bits per
                                    second. The following table lists valid
                                    abbreviations for b and its related rate.
  parity = p                      : Specifies how the system uses the parity
                                    bit to check for transmission errors.
                                    The following table lists valid p values.
                                    The default value is e. Not all computers
                                    support the values m and s.
  data   = d                      : Specifies the number of data bits in a
                                    character. Valid values for d are in the
                                    range 5 through 8. The default value is 7.
                                    Not all computers support the values
                                    5 and 6.
  stop   = s                      : Specifies the number of stop bits that
                                    define the end of a character: 1, 1.5, or
                                    2. If the baud rate is 110, the default
                                    value is 2. Otherwise, the default value is
                                    1. Not all computers support the value 1.5.
  to     = { on | off }           : Specifies whether infinite time-out
                                    processing is on or off.
                                    The default is off.
  xon    = { on | off }           : Specifies whether the xon or xoff protocol
                                    for data-flow control is on or off.
  odsr   = { on | off }           : Specifies whether output handshaking that
                                    uses the Data Set Ready (DSR) circuit is on
                                    or off.
  octs   = { on | off }           : Specifies whether output handshaking that
                                    uses the Clear To Send (CTS) circuit is on
                                    or off.
  dtr    = { on | off | hs }      : Specifies whether the Data Terminal Ready
                                    (DTR) circuit is on or off, or set to
                                    handshake.
  rts    = { on | off | hs | tg } : Specifies whether the Request To Send (RTS)
                                    circuit is set to on, off, handshake,
                                    or toggle.
  idsr   = { on | off }           : Specifies whether the DSR circuit
                                    sensitivity is on or off.
*/

///
/// Opens the serial port
///
bool SerialPort::open(void)
{
  static const char *baudfmt =
    "baud=%d "  // opengalaxy().settings().receiver_baudrate
    "parity=N " // no parity
    "data=8 "   // 8 data bits
    "stop=1 "   // 1 stop bit
    "to=off "   // no infinite time-out processing
    "xon=off "  // do not use the xon or xoff protocol for data-flow control
    "odsr=off " // no output DSR handshaking
    "octs=on "  // do output CTS handshaking
    "dtr=off "  // no DTR (handshaking)
    "rts=on "   // do RTS (handshaking)
    "idsr=off"; // no input DSR handshaking

  static const char *portfmt = "\\\\.\\COM%d";

  if( m_bIsOpen==false ){

    char baudrate[strlen(baudfmt)+8];
    char portname[strlen(portfmt)+32];

    int portnumber = strtol( (opengalaxy().settings().receiver_tty.size()>3) ? &opengalaxy().settings().receiver_tty.c_str()[3] : "", NULL, 10);

    if(portnumber <= 0) {
      opengalaxy().syslog().error("Serial: Invalid serial port name: %s", opengalaxy().settings().receiver_tty.c_str() );
      return false;
    }

    sprintf(baudrate, baudfmt, opengalaxy().settings().receiver_baudrate);
    sprintf(portname, portfmt, portnumber);

    // (This blocks for a significant amount of time if the port does not exist)
    m_nTTY = CreateFileA(
      portname,
      GENERIC_READ | GENERIC_WRITE,
      0,                            // must be opened with exclusive-access
      nullptr,                      // default security attributes
      OPEN_EXISTING,                // must use OPEN_EXISTING
      0,                            // not overlapped I/O
      nullptr                       // hTemplate must be NULL for comm devices
    );

    if( m_nTTY == INVALID_HANDLE_VALUE ) {
      opengalaxy().syslog().error("Serial: Could not open serial port %s", opengalaxy().settings().receiver_tty.c_str() );
      return false;
    }

    DCB portsettings;
    memset(&portsettings, 0, sizeof(portsettings));
    portsettings.DCBlength = sizeof(portsettings);

    if( ! BuildCommDCBA( baudrate, &portsettings ) ) {
      opengalaxy().syslog().error("Serial: Could not configure the COM port." );
      CloseHandle( m_nTTY );
      return false;
    }

    if( ! SetCommState( m_nTTY, &portsettings ) ) {
      opengalaxy().syslog().error("Serial: Could not configure the COM port." );
      CloseHandle( m_nTTY );
      return false;
    }

    COMMTIMEOUTS timeouts;
    /*
     * If an application sets ReadIntervalTimeout and ReadTotalTimeoutMultiplier
     * to MAXDWORD and sets ReadTotalTimeoutConstant to a value greater than
     * zero and less than MAXDWORD, one of the following occurs when the
     * ReadFile function is called:
     * 
     *  - If there are any bytes in the input buffer,
     *    ReadFile returns immediately with the bytes in the buffer.
     * 
     *  - If there are no bytes in the input buffer,
     *    ReadFile waits until a byte arrives and then returns immediately.
     * 
     *  - If no bytes arrive within the time specified by
     *    ReadTotalTimeoutConstant, ReadFile times out.
     */
    timeouts.ReadIntervalTimeout         = MAXDWORD;
    timeouts.ReadTotalTimeoutMultiplier  = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant    = 1000UL;
    timeouts.WriteTotalTimeoutMultiplier = MAXDWORD;
    timeouts.WriteTotalTimeoutConstant   = 1000UL;

    if( ! SetCommTimeouts( m_nTTY, &timeouts ) ) {
      opengalaxy().syslog().error("Serial: Could not configure the COM port timeout" );
      CloseHandle( m_nTTY );
      return false;
    }

    m_bIsOpen = true;
  }

  return true;
}

///
/// Closes the serial port
///
void SerialPort::close(void)
{
  if( m_bIsOpen == true ){
    CloseHandle( m_nTTY );
    m_bIsOpen = false;
  }
}

///
/// Reads from open serial port
///
/// This function blocks for a maximum of 1 second(s)
///  while receiving a maximum of 'count' bytes.
///
/// Returns the number of bytes read
///
size_t SerialPort::read(void* buf,size_t count)
{
  if( m_bIsOpen == true ){
    size_t retv = 0;
    ReadFile( m_nTTY, buf, count, (LPDWORD)((void *)&retv), nullptr);
    if(retv) opengalaxy().syslog().debug("Serial: Read %d byte(s) from %s", retv, opengalaxy().settings().receiver_tty.c_str());
#ifdef DEBUG_SERIAL
    if(retv && opengalaxy().syslog().get_level()>=Syslog::Level::Debug) pbuffer("read: ",(const unsigned char*)buf, retv);
#endif
    return retv;
  }
  return 0;
}

///
/// Writes to open serial port
///
/// Returns the number of bytes written
///
size_t SerialPort::write(void* buf,size_t count)
{
  if( m_bIsOpen == true ){
    size_t retv = 0;
    opengalaxy().syslog().debug("Serial: Write %d byte(s) to %s", count, opengalaxy().settings().receiver_tty.c_str());
#ifdef DEBUG_SERIAL
    if(count && opengalaxy().syslog().get_level()>=Syslog::Level::Debug) pbuffer("write: ",(const unsigned char*)buf, count);
#endif
    WriteFile( m_nTTY, buf, count, (LPDWORD)((void *)&retv), NULL);
    return retv;
  }
  return 0;
}

#endif // ends IF _WIN32

} // ends namespace openGalaxy

