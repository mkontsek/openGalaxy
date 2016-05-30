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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#if __linux__
#include <unistd.h>
#include <grp.h>
#include <sys/wait.h>
#endif
#include <sys/stat.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "support.h"

// Glade XML data converted to C variables
#include "error_dialog.h"
#include "popen_window.h"

// The maximum length of a command on the commandline (kb830473)
#define CMD_MAX_LEN 8191

int __gtk_display_error_dialog( const gchar *msg, const gchar *title, GtkWidget* parent, GCallback cb )
{
  GtkBuilder *builder;
  GtkWidget *dialog;
  GtkWidget *label;
  GtkWidget *close_button;

  // Create a gtk_builder object
  builder = gtk_builder_new();
  // And feed it our popen-window XML data
  if( 0 == gtk_builder_add_from_string( builder, (const gchar *)error_dialog_glade, error_dialog_glade_len, NULL ) ){
    return( -1 );
  }

  // Get the widgets from the gtk_builder object
  dialog = GTK_WIDGET( gtk_builder_get_object( builder, "error-dialog" ) );
  label = GTK_WIDGET( gtk_builder_get_object( builder, "error-dialog-label" ) );
  close_button = GTK_WIDGET( gtk_builder_get_object( builder, "error-dialog-button" ) );

  // Throw the gtk_builder object away
  g_object_unref( G_OBJECT( builder ) );

  // Make the dialog a child of our main-window
  gtk_window_set_transient_for( GTK_WINDOW( dialog ), GTK_WINDOW( parent ) );

  // Set the title for the dialog
  gtk_window_set_title( GTK_WINDOW( dialog ), title );

  // Display the error
  gtk_label_set_text( ( GtkLabel* )label, msg );

  // Set a callback for close-button clicked signal to close the dialog
  g_signal_connect_swapped( close_button, "clicked", cb, dialog );

  // Show the dialog
  gtk_widget_show( dialog );
  return( 0 );
}


//
// Displays a dialog with an error message
//
/*
int _gtk_display_error_dialog( GtkWidget* parent, const gchar *title, const gchar *msg)
{
  return( __gtk_display_error_dialog( msg, title, parent, G_CALLBACK( gtk_window_close ) ) );
}
*/
int _gtk_display_error_dialog( GtkWidget* parent, const gchar *title, const gchar *fmt, ...)
{
  char buf[CMD_MAX_LEN];
  va_list args;
  va_start( args, fmt );
  vsnprintf( buf, CMD_MAX_LEN, fmt, args );
  va_end( args );
  return( __gtk_display_error_dialog( buf, title, parent, G_CALLBACK( gtk_window_close ) ) );
}


//
// Exec cmd and pipe its standard output to a GtkTextBuffer
// Use 2>&1 at the end of cmd to also redirect stderr to the dialog
//
// Return value:
//  -2 if the command could not be executed
//  -1 if the command was executed but no return state could be retrieved
//  otherwise the exit status of the child process is returned
//
int _gtk_popen( char *cmd, GtkTextBuffer *out )
{
  int retv = -2;
  FILE *fp;
  char in[80];

  // Exit if no cmd
  if( ! cmd ) return( retv );

  // Create a one way pipe and execute cmd with call to popen()
  if( ( fp = popen( cmd, "r") ) == NULL ){
    return( retv );
  }

  // Processing loop: Read from cmd's standard output and append to the GtkTextBuffer
  while( fgets( in, 80, fp ) ){
    if( out ){
      gtk_text_buffer_insert_at_cursor( out, in, strlen( in ) );
    }
  }

  // Get the exit status of the child process
#if __linux__
  int state_loc;
  if( wait( &state_loc ) != -1 ){
    if( WIFEXITED( state_loc ) ) retv = WEXITSTATUS( state_loc );
    else retv = -1;
  }
  else retv = -1;
#else
  retv = 0; // TODO: Find out how to get the return status on windows
#endif

  // Close the pipe
  pclose( fp );
  return( retv );
}

//
// Callback for when the contents of the exec_textview from _gtk_dialog_exec() changed
//
void G_MODULE_EXPORT _gtk_dialog_exec_cb_changed( GtkWidget *widget, gpointer data )
{
  // Storage for a cursor position
  GtkTextIter iter;

  // Get the textbuffer object
  GtkTextBuffer *textbuffer = gtk_text_view_get_buffer( ( GtkTextView* )widget );

  // Get the 'insert' mark from the textbuffer (ie. the end of the text)
  GtkTextMark *insert_mark = gtk_text_buffer_get_mark( textbuffer, "insert" );

  // Load the cursor postion from the 'insert' mark of the textview into iter
  gtk_text_buffer_get_iter_at_mark( textbuffer, &iter, insert_mark );

  // Scroll the text to the current cursor position (iter)
  gtk_text_view_scroll_to_iter( ( GtkTextView* )widget, &iter, 0.0, FALSE, 0.0, 0.0 );
}


//
// Execute a comand and sends its output to
//  the GtkTextView in a new dialog window.
//
// Return value:
//  -3 if a new dialog window could not be created (the command was not executed)
//  -2 if the command could not be executed
//  -1 if the command was executed but no return state could be retrieved
//  otherwise the exit status of the child process is returned
//
int _gtk_dialog_exec( char *cmd, const gchar *title, GtkWindow *parent )
{
  GtkBuilder *builder;
  GtkWindow *dialog;
  GtkWidget *close_button;
  GtkTextView *command;
  GtkTextView *output;

  // Sanity check
  if( cmd == NULL ) return( -3 ); // no command to execute

  // Create a gtk_builder object
  builder = gtk_builder_new();

  // And feed it our popen-window XML data
  if( 0 == gtk_builder_add_from_string( builder, (const gchar *)popen_window_glade, popen_window_glade_len, NULL ) ){
    return( -3 );
  }

  // Get the widgets from the gtk_builder object
  dialog = GTK_WINDOW( gtk_builder_get_object( builder, "popen-window" ) );
  command = (GtkTextView *)gtk_builder_get_object( builder, "popen-cmd-textview" );
  output = (GtkTextView *)gtk_builder_get_object( builder, "popen-exec-textview" );
  close_button = GTK_WIDGET( gtk_builder_get_object( builder, "popen-window-close-button" ) );

  // Throw the gtk_builder object away
  g_object_unref( G_OBJECT( builder ) );

  // Make the dialog a child of its parent
  gtk_window_set_transient_for( dialog, parent );

  // Set the title for the dialog
  if( title ) gtk_window_set_title( dialog, title );

  // Display the cmd as the content of the d->cmd textview
  gtk_text_buffer_insert_at_cursor( gtk_text_view_get_buffer( command ), cmd, strlen( cmd ) );

  // Set a callback for close-button clicked signal to close the dialog
  g_signal_connect_swapped( close_button, "clicked", G_CALLBACK(gtk_window_close), dialog );

  // Set a callback for when the content of these textbuffers changes that
  // scrolls to the end of the textviewbuffer
  // (the size-allocate signal is inherited from GtkWidget...)
  g_signal_connect( command, "size-allocate", G_CALLBACK( _gtk_dialog_exec_cb_changed ), NULL );
  g_signal_connect( output, "size-allocate", G_CALLBACK( _gtk_dialog_exec_cb_changed ), NULL );

  // Show the dialog
  gtk_widget_show( GTK_WIDGET( dialog ) );

  // Execute the command sending its output to the d->output textview
  return( _gtk_popen( cmd, gtk_text_view_get_buffer( output ) ) );
}


//
// Execute a list of commands one after the other
// and send its stdout to the same new dialog window
//
// GtkWindow *parent : Parent window
// gchar *title      : Title for the new dialog window
// char **cmdlist    : NULL terminated list of commands
// int do_check      : !0 = check return value of the commands
//
int _gtk_dialog_exec_list( GtkWindow *parent, const gchar *title, char **cmdlist, int do_check )
{
  GtkBuilder *builder;
  GtkWindow *dialog;
  GtkWidget *close_button;
  GtkTextView *command;
  GtkTextView *output;
  int retv = 0;

  // Sanity check
  if( cmdlist == NULL ) return( -3 );  // no cmdlist
  if( *cmdlist == NULL ) return( -3 ); // no commands in cmdlist

  // Create a gtk_builder object
  builder = gtk_builder_new();
  // And feed it our popen-window XML data
  if( 0 == gtk_builder_add_from_string( builder, (const gchar *)popen_window_glade, popen_window_glade_len, NULL ) ){
    return( -3 );
  }

  // Get the widgets from the gtk_builder object
  dialog = GTK_WINDOW( gtk_builder_get_object( builder, "popen-window" ) );
  command = (GtkTextView *)gtk_builder_get_object( builder, "popen-cmd-textview" );
  output = (GtkTextView *)gtk_builder_get_object( builder, "popen-exec-textview" );
  close_button = GTK_WIDGET( gtk_builder_get_object( builder, "popen-window-close-button" ) );

  // Throw the gtk_builder object away
  g_object_unref( G_OBJECT( builder ) );

  // Make the dialog a child of its parent
  gtk_window_set_transient_for( dialog, parent );

  // Set the title for the dialog
  if( title ) gtk_window_set_title( dialog, title );

  // Set a callback for close-button clicked signal to close the dialog
  g_signal_connect_swapped( close_button, "clicked", G_CALLBACK(gtk_window_close), dialog );

  // Set a callback for when the content of exex_textview's textbuffer changes
  // (the size-allocate signal is inherited from GtkWidget...)
  g_signal_connect( command, "size-allocate", G_CALLBACK( _gtk_dialog_exec_cb_changed ), NULL );
  g_signal_connect( output, "size-allocate", G_CALLBACK( _gtk_dialog_exec_cb_changed ), NULL );

  // Show the dialog
  gtk_widget_show( GTK_WIDGET( dialog ) );

  while( *cmdlist ){
    char *cmd = *cmdlist;

    // Display the cmd as the content of the cmd_textview
    gtk_text_buffer_insert_at_cursor( gtk_text_view_get_buffer( command ), cmd, strlen( cmd ) );

    // Execute the command
    retv = _gtk_popen( cmd, gtk_text_view_get_buffer( output ) );

    // Print a newline for the next cmd
    char buf[24];
    snprintf( buf, sizeof( buf ), "\n" );
    gtk_text_buffer_insert_at_cursor( gtk_text_view_get_buffer( command ), buf, strlen( buf ) );

    // check the return value
    if( do_check && retv ) break;

    // next command
    cmdlist++;
  }

  // Return the output value from the last cmd
  return( retv );
}


//
// Printf a command, execute it and send its stdout to
//  a GtkTextView in a new dialog window.
//
// GtkWindow *parent : Parent window
// gchar *title      : Title for the new dialog window
// const char *fmt   : Format for the command string
// ...               : Parameters for the format string
//
// Return value:
//  -3 if a new dialog window could not be created (the command was not executed)
//  -2 if the command could not be executed
//  -1 if the command was executed but no return state could be retrieved
//  otherwise the exit status of the child process is returned
//
int _gtk_dialog_exec_printf( GtkWindow *parent, const gchar *title, const char *fmt, ... )
{
  char buf[CMD_MAX_LEN];
  va_list args;
  va_start( args, fmt );
  vsnprintf( buf, CMD_MAX_LEN, fmt, args );
  va_end( args );
  return( _gtk_dialog_exec( buf, title, parent ) );
}

//
// Returns a pointer to a new list of commands that we can execute once the list is filled
//
char **_gtk_dialog_exec_new_list( void )
{
  char ** retv = g_malloc( sizeof( char* ) );
  if( retv ) *retv = NULL;
  return( retv );
}

//
// Printf a command and add it to a command list
//
int _gtk_dialog_exec_list_printf( char ***cmdlist, const char *fmt, ... )
{
  char buf[CMD_MAX_LEN];
  char *dup;
  char **in, **out, **new;
  va_list args;

  // determine the number of items in the new cmdlist
  in = *cmdlist;
  int count = 2; // Add 2 to the count of items in the cmdlist (1 for the new item and 1 for the trailing NULL)
  while( *(in++) ) count++; // nr of iterations is number of items in 'in' minus one (the closing NULL pointer is not counted)

  // malloc the new cmdlist
  new = malloc( sizeof( char* ) * count );
  if( new == NULL ) return( -1 );

  // printf the new item to a buffer and duplicate that buffer
  va_start( args, fmt );
  vsnprintf( buf, CMD_MAX_LEN, fmt, args );
  va_end( args );
  dup = strdup( buf );
  if( dup == NULL ){
    free( new );
    return( -1 );
  }

  // copy the old items to the new cmdlist
  in = *cmdlist;
  out = new;
  while( *in ) *(out++) = *(in++);

  // append the new item and close the cmdlist
  *(out++) = dup;
  *out = NULL;

  // free the old cmdlist and replace it with the new one
  free( *cmdlist );
  *cmdlist = new;

  return 0;
}


//
// Free's a command list after usage
//
void _gtk_dialog_exec_free_list( char **cmdlist )
{
  if( cmdlist ){
    char **l = cmdlist;
    while( *l ) g_free( *(l++) );
    g_free( cmdlist );
  }
}


//
// Returns 0 when fn is an existing regular file that is atleast 1 byte large
// Returns !0 when file does not exist, is not a regular file or has 0 length
//
int is_regular_file( char *fn )
{
  struct stat st;

  if( stat( fn, &st ) != 0 ){
    // Could not stat the file
    return -1;
  }
  else if( !S_ISREG( st.st_mode ) ){
    // Not a regular file
    return -1;
  }

  int retv = 0;
  FILE *fp = fopen( fn, "r" );
  fseek( fp, 0L, SEEK_END );
  if( ftell(fp) == 0 ){
    // file is empty
    retv = -2;
  }
  fclose( fp );

  return retv;
}


//
// Returns 0 when ip is an IP address in dotted decimal format.
// Returns !0 when it is not.
//
int is_ip_address( const char *ip )
{
  int numDigits;
  char *next;
  unsigned long one, two, three, four;
  if( ip ){

    // first byte
    numDigits = 0;
    while( *ip >= '0' && *ip <= '9' ){
      numDigits++;
      ip++;
    }
    if( numDigits == 0 || numDigits > 3 ) return -1;
    if( *ip != '.' ) return -1;
    ip++;

    // second byte
    numDigits = 0;
    while( *ip >= '0' && *ip <= '9' ){
      numDigits++;
      ip++;
    }
    if( numDigits == 0 || numDigits > 3 ) return -2;
    if( *ip != '.' ) return -2;
    ip++;

    // third byte
    numDigits = 0;
    while( *ip >= '0' && *ip <= '9' ){
      numDigits++;
      ip++;
    }
    if( numDigits == 0 || numDigits > 3 ) return -3;
    if( *ip != '.' ) return -3;
    ip++;

    // fourth byte
    numDigits = 0;
    while( *ip >= '0' && *ip <= '9' ){
      numDigits++;
      ip++;
    }
    if( numDigits == 0 || numDigits > 3 ) return -4;
    if( *ip != '.' ) return -4;

    // We havedetermined that the format of the string is valid
    // Now try to convert the dotted decimal into an actual IP address
    one = strtoul( ip, &next, 10 );
    next++; // skip over the dot
    two = strtoul( next, &next, 10 );
    next++; // skip over the dot
    three = strtoul( next, &next, 10 );
    next++; // skip over the dot
    four = strtoul( next, NULL, 10 );
    if( one > 255 ) return -1;
    if( two > 255 ) return -2;
    if( three > 255 ) return -3;
    if( four > 255 ) return -4;

    return 0;
  }
  return -1;
}


//
// On Linux this set a file's group ID to that of group 'staff'
//
// Returns: !0 on errror
//
int set_opengalaxy_gid( const char *path )
{
#if __linux__
  struct group *grp = getgrnam( "staff" );
  if( grp == NULL ){
    return -1;
  }
  else {
    if( 0 != chown( path, getuid(), grp->gr_gid ) ){
      return -1;
    }
  }
#endif
  return 0;
}


//
// Check if a directory exists,
//  if it does not exist create it.
//
// Returns: !0 on errror
//
int _mkdir( const char *path, mode_t mode )
{
  struct stat st;
  int retv = 0;
  // Get directory stats
  if( stat( path, &st ) != 0 ){
    // Could not get stats, create the directory
    if(
#if __linux__
      mkdir( path, mode ) != 0 && errno != EEXIST
#else
      mkdir( path ) != 0 && errno != EEXIST
#endif
    ){
      // Could not create the directory
      retv = -1;
    }
    // Set the correct group id
    if( set_opengalaxy_gid( path ) != 0 ){
      retv = -1;
    }
    if( chmod( path, mode ) != 0 ){
      retv = -1;
    }
  }
  // Verify that it is a directory
  else if( !S_ISDIR( st.st_mode ) ){
    errno = ENOTDIR;
    retv = -1;
  }

  // set the group id to 'staff'
  if( retv == 0 ){
    
  }

  return( retv );
}


//
// 'mkdir -p' like function to create a path
//
// Returns: !0 on errror
//
int mkpath( const char *path, mode_t mode )
{
  int retv = 0;
  char *pp, *sp, *p = strdup( path );
  if( p == NULL ){
    errno = ENOMEM;
    return( -1 );
  }
  pp = p;
  while ( retv == 0 && ( sp = strchr( pp, '/' ) ) != 0 ){
    if( sp != pp ){
      *sp = '\0';
#if ! __linux__
      if( p[strlen(p)-1] != ':' ){ // skip 'creating' the drive letter part of path on windows
#endif
        retv = _mkdir( p, mode );
#if ! __linux__
      }
#endif
      *sp = '/';
    }
    pp = sp + 1;
  }
  if(retv == 0) retv = _mkdir( path, mode );
  free( p );
  return( retv );
}



//
// Convert the date as printed by openssl into a time_t
// Used to calculate the 'days valid' parameter of a given certificate
//
time_t date2epoch( char *date )
{
  time_t retv = -1;

  // Example date string:
  // "Feb 23 23:58:00 2015 GMT"
  //  123456789012345678901234 <- max 24 characters
  if( strlen( date ) > 24 ) return retv;

  // parse the date using sscanf
  char month_str[32];
  int month, day, hours, minutes, seconds, year;

  int r = sscanf( date, "%s %d %d%*c%d%*c%d %d %*s", month_str, &day, &hours, &minutes, &seconds, &year );
  if( r == EOF || r < 6 ) return -1; // fail if not all parameters were filled

  if( strcmp( month_str, "Jan" ) == 0 ){ // try to convert the month to an integer value
    month = 0;
  }
  else if( strcmp( month_str, "Feb" ) == 0 ){
    month = 1;
  }
  else if( strcmp( month_str, "Mar" ) == 0 ){
    month = 2;
  }
  else if( strcmp( month_str, "Apr" ) == 0 ){
    month = 3;
  }
  else if( strcmp( month_str, "May" ) == 0 ){
    month = 4;
  }
  else if( strcmp( month_str, "Jun" ) == 0 ){
    month = 5;
  }
  else if( strcmp( month_str, "Jul" ) == 0 ){
    month = 6;
  }
  else if( strcmp( month_str, "Aug" ) == 0 ){
    month = 7;
  }
  else if( strcmp( month_str, "Sep" ) == 0 ){
    month = 8;
  }
  else if( strcmp( month_str, "Oct" ) == 0 ){
    month = 9;
  }
  else if( strcmp( month_str, "Nov" ) == 0 ){
    month = 10;
  }
  else if( strcmp( month_str, "Dec" ) == 0 ){
    month = 11;
  }
  else {
    month = 0; // Failed to convert, set the integer value to january but do not bail out
  }

  // Copy the integers into a struct tm
  // (months are 0-11 and years start in 1900)
  time( &retv );
  struct tm *t = gmtime( &retv );
  t->tm_year = year - 1900;
  t->tm_mon = month;
  t->tm_mday = day;
  t->tm_hour = hours;
  t->tm_min = minutes;
  t->tm_sec = seconds;

  // Use mktime to get a UTC epoch integer
  retv = mktime( t );

  return retv;
}


//
// Test string for any of the characters in another string
// Returns 0 when none of the characters were found
//
int has_invalid_characters( const char *text, const char *invalid )
{
  int retv = 0;
  if( text && invalid ){
    for( char c = *invalid++; c != '\0'; c = *invalid++ ){
      if( strchr( text, c ) != NULL ){
        retv = 1;
        break;
      }
    }
  }
  else retv = 1;
  return retv;
}


//
// Trims leading and trailing whitespaces from a string
//
int strtrim( char *str )
{
  int retv = 0, len;
  char *p, *s = NULL;

  if( str == NULL ){
    retv = -1;
    goto error;
  }

  s = strdup( str );
  if( s == NULL ){
    retv = -1;
    goto error;
  }
  p = s;

  // strip leading
  while( ( *p == ' ' ) || ( *p == '\t' ) ){
    p++;
  }

  // strip trailing
  len = strlen( p );
  while( ( p[len] == ' ' ) || ( p[len] == '\t' ) ){
    p[len] = '\0';
    len--;
  }

  // copy back
  strcpy( str, p );

error:
  if( s ) free( s );
  return retv;
}

