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
#include "opengalaxy.hpp"
#include "Signal.hpp"

#include <locale>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <stdexcept>

//
// This will be set to true when signal SIGHUP is received.
// See: SignalsCallback()
//
static volatile bool isHup = false;

//
// This function will be called when a signal was received
// by the Signal class created in main().
//
// Under Windows, SIGINT is the only signal...
//
void SignalsCallback(void *userdata, int signum)
{
  using namespace openGalaxy;

  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_EVP_strings();

  class openGalaxy *opengalaxy = (class openGalaxy*)userdata;
  if(opengalaxy == nullptr) return;

  switch( signum ){

    case SIGINT: // Interrupt (Ctrl-C), quit program
      opengalaxy->syslog().debug( "Caught signal: %s","SIGINT" );
      opengalaxy->exit(); // Signal all threads to exit.
      break;

#ifdef __linux__
    case SIGABRT: // Abort (quit program)
      opengalaxy->syslog().debug( "Caught signal: %s","SIGABRT" );
      opengalaxy->exit(); // Signal all threads to exit.
      break;

    case SIGHUP: // Reload settings from file, restart program
      opengalaxy->syslog().print( "" );
      opengalaxy->syslog().debug( "Caught signal: %s","SIGHUP" );
      opengalaxy->syslog().print( "Reloading settings and certificates..." );
      opengalaxy->syslog().print( "" );
      // Let the main() function know we wish to restart
      isHup = true;
      // and signal the openGalaxy object to exit.
      opengalaxy->exit();
      break;

    case SIGTERM: // Request to terminate program
      opengalaxy->syslog().debug( "Caught signal: %s","SIGTERM" );
      opengalaxy->exit(); // Signal all threads to exit.
      break;

    case SIGQUIT: // Terminate program and dump core
      opengalaxy->syslog().debug( "Caught signal: %s","SIGQUIT" );
      opengalaxy->exit(); // Signal all threads to exit.
      break;

    case SIGUSR1: // Not used
      opengalaxy->syslog().debug( "Caught signal: %s","SIGUSR1" );
      break;

    case SIGUSR2: // Not used
      opengalaxy->syslog().debug( "Caught signal: %s","SIGUSR2" );
      break;
#endif

    default: // This point should not be reached
      opengalaxy->syslog().debug( "Caught signal: %s","(default signal handler)" );
      break;
  }
}


namespace openGalaxy {
  // The (static) function called by lws_emit_log():
  //
  // Now that class Websocket is no longer 'static'
  // we cannot implement this function in class Websocket anymore because
  // we do not have access to libwebsockets context userdata from within it
  // (and therefore do not have access to the class Websocket instance we
  // store there).
  //
  // For now we implement it here and refer to our openGalaxy instance thru a
  // global variable so we can access its Syslog facility...

  static class openGalaxy **opengalaxy_ctx_ptr;

  void Websocket::emit_log(int level, const char *msg)
  {
    std::string s = msg; // copy, do not modify the original
    s.pop_back();        // remove trailing newline
    (*opengalaxy_ctx_ptr)->syslog().print("Websocket: %s", s.c_str());
  }
}


int main(int argc,char *argv[])
{
  using namespace openGalaxy;

#if HAVE_GPERFTOOLS
  // Defaults to $(localstatedir)/log/galaxy/profile.txt
  ProfilerStart( _LOG_DIR_ "/profile.txt" );
#endif

  class context_options ctx_options;          // options from the commandline
  class Signals *signals = nullptr;           // signal handler
  class openGalaxy *opengalaxy_ctx = nullptr; // openGalaxy server

  opengalaxy_ctx_ptr = &opengalaxy_ctx;       // for Websocket::emit_log()

  // Program exit status
  int retv = EXIT_SUCCESS;

  try {

    // Parse the command line parameters on first startup
    if(isHup == false){
      if(ctx_options.parse_command_line(argc, argv) == true) return EXIT_FAILURE;
    }

    // The Signals object must be created first
    // as it needs to setup blocking/catching signals before the first
    // std::thread is created. This is so that all threads created later
    // will inherit our signal handler,
    // we will set the signal handler to call later.
    signals = new class Signals();

    while(1){

      // Create a new openGalaxy context
      //
      opengalaxy_ctx = new class openGalaxy(ctx_options);

      // Check for any fatal errors
      if(opengalaxy_ctx->isQuit()){
        delete opengalaxy_ctx;
        break;
      }

      // Reset any previous SIGHUP condition
      isHup = false;

      // Now that we have an openGalaxy instance we can use
      // it as the userdata passed to our signal handler.
      signals->set_callback(SignalsCallback, (void*)opengalaxy_ctx);

      // Calling this function is mandatory!
      // It blocks until openGalaxy::exit() is called, then
      // re-throws any exceptions from the worker threads.
      //
      // To check if opengalaxy has exited before calling
      // openGalaxy::wait(), the following function is available:
      // openGalaxy::isQuit() - Returns true if openGalaxy has exited
      //
      // (To manually exit openGalaxy call the openGalaxy::exit() method,
      // then call openGalaxy::wait().)
      opengalaxy_ctx->wait();

      // Check the exit status to check ig we need to restart or quit
      if(opengalaxy_ctx->exit_status == openGalaxy::openGalaxy::EXIT_STATUS_CERTS_UPDATED){
        isHup = true;
        // When restarting after uploading certificates, override any commandline
        // option to disable SSL
        ctx_options.no_ssl = 0;
        ctx_options.no_client_certs = 0;
        ctx_options.auto_logoff = 1;
      }

      // Delete the openGalaxy instance
      signals->set_callback(nullptr, nullptr); // just in case of an incomming signal
      delete opengalaxy_ctx;


      // Did we receive a SIGHUP signal and want to reload settings and certificates/crl?
      if(isHup == true){
        continue; // restart
      }

      // no SIGHUP signal was received, break out of the ifinite loop instead
      std::cout << "Have a nice day!" << std::endl;
      break;
    }

    // delete our signals handler
    delete signals;
  }
  //
  // Catch exceptions thrown by class openGalaxy
  //
  catch(...){
    delete opengalaxy_ctx;
    delete signals;
    std::exception_ptr eptr = std::current_exception();
    retv = EXIT_FAILURE;
    try {
      std::rethrow_exception(eptr);
    }
    catch(std::runtime_error* ex) {
      std::cerr << "Guru meditation: " << ex->what() << std::endl;
    }
    catch(...) {
      std::cerr << std::endl << "I'm Spartacus!" << std::endl;
      throw;
    }
  }

#if HAVE_GPERFTOOLS
  ProfilerFlush();
  ProfilerStop();
  std::cerr
   << std::endl
   << "Profiling enabled, to view the profiling log execute:"
   << std::endl
   << " google-pprof --text "
   << argv[0]
   << " " _LOG_DIR_ "/profile.txt"
   << std::endl
   << std::endl;
#endif

  return retv;
}

