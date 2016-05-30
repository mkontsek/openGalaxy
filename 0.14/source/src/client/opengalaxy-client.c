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

#if __linux__
#include <X11/Xlib.h>
#else
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <glib.h>
#include <glib/gprintf.h>
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "opengalaxy-client.h"
#include "support.h"
#include "log.h"
#include "websocket.h"
#include "commander.h"
#include "broadcast.h"
#include "connect.h"
#include "areas.h"

#include "client_main_window.h"
#include "client_gtk.h"

GtkWidget *mainWindow;

GtkToolbar    *toolbar;
GtkToolButton *toolbuttonConnect;
GtkToolButton *toolbuttonDisconnect;
GtkToolButton *toolbuttonFullscreen;
GtkToolButton *toolbuttonExit;

GtkOverlay  *serverStatusOverlay;
GtkEventBox *serverStatusOnline,
            *serverStatusOffline,
            *serverStatusConnecting,
            *serverStatusError;

GtkOverlay  *commandStatusOverlay;
GtkEventBox *commandStatusSending,
            *commandStatusReady,
            *commandStatusError,
            *commandStatusIdle;

GtkMenuBar  *menu;
GtkMenuItem *menuConnect;
GtkMenuItem *menuDisconnect;
GtkMenuItem *menuFullscreen;
GtkMenuItem *menuQuit;

GtkBox      *boxWholeWindow; // box with entire mainWindow
GtkBox      *boxAppArea; // box in the paned

GtkTreeView *treeviewSIA;
GtkListStore *liststoreSIA;
GtkTextView *commander_output;
GtkEntry *commander_user_cmd;
GtkTextView *log_output;

gchar *msg = "openGalaxy Client Application.";


int isFullscreen = 0;


//
// Called in stead of gtk_main_quit()
// Takes care of destroying things and then calls gtk_main_quit()
//
static void _gtk_do_main_quit( void )
{
  Websocket_ExitThread();
  Commander_Exit(); // Stop processing incomming command reply messages
  SIA_Exit(); // Stop processing incoming SIA messages
  Log_Exit(); // destroy last
  gtk_main_quit();
}



//
// Called when the mainWindow receives a GDK_CONFIGURE (window resize) event
//
void G_MODULE_EXPORT cbMainWindow_configure( GtkWindow *window,  GdkEvent *event, gpointer data )
{
  //
  // Set a timeout function to call after 10 ms to do the work of re-scaling the gui
  //
  if( TimeoutScaleAreas_Tag ) g_source_remove( TimeoutScaleAreas_Tag ); // Cancel any pending timeout
  TimeoutScaleAreas_UserData.width = event->configure.width;
  TimeoutScaleAreas_UserData.height = event->configure.height;
  TimeoutScaleAreas_Tag = g_timeout_add( 100, cbArea_Grid_TimeoutScaleAreas, &TimeoutScaleAreas_UserData );
}


//
// Called when the mainWindow receives a window change event
//
gboolean G_MODULE_EXPORT cbMainWindow_stateEvent( GtkWidget *widget, GdkEventWindowState *event, gpointer user_data )
{
  /*
  if( event->new_window_state & GDK_WINDOW_STATE_WITHDRAWN ){} // the window is not shown.
  if( event->new_window_state & GDK_WINDOW_STATE_ICONIFIED ){} // the window is minimized.
  if( event->new_window_state & GDK_WINDOW_STATE_MAXIMIZED ){} // the window is maximized.
  if( event->new_window_state & GDK_WINDOW_STATE_STICKY ){}    // the window is sticky.
  if( event->new_window_state & GDK_WINDOW_STATE_ABOVE ){}     // the window is kept above other windows.
  if( event->new_window_state & GDK_WINDOW_STATE_BELOW ){}     // the window is kept below other windows.
  if( event->new_window_state & GDK_WINDOW_STATE_FOCUSED ){}   // the window is presented as focused (with active decorations).
  if( event->new_window_state & GDK_WINDOW_STATE_TILED ){}     // the window is in a tiled state (Since 3.10)
  */ 
  if( event->new_window_state & GDK_WINDOW_STATE_FULLSCREEN ){ // the window is maximized without decorations.
    isFullscreen = 1; // Log fullscreen mode
#pragma GCC diagnostic push // save gcc diagnostic state
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // do not complain about deprecated declarations
    gtk_tool_button_set_stock_id( toolbuttonFullscreen, "gtk-leave-fullscreen" );
#pragma GCC diagnostic pop // restore gcc diagnostic state
    if( _gtk_widget_has_class( GTK_WIDGET( toolbar ), "fullscreen" ) == FALSE ){
      _gtk_widget_add_class( GTK_WIDGET( toolbar ), "fullscreen" );
      _gtk_widget_remove_class( GTK_WIDGET( boxAppArea ), "bg_window" );
      _gtk_widget_add_class( GTK_WIDGET( boxAppArea ), "bg_window_fullscreen" );
      _gtk_widget_add_class( GTK_WIDGET( boxWholeWindow ), "bg_window" );
    }
    gtk_widget_hide( GTK_WIDGET( menu ) );
  }
  return TRUE;
}


//
// Called when the 'Fullscreen' item from the menu/toolbar
//   puts the application in fullscreen mode.
//
void G_MODULE_EXPORT cbMenu_fullscreen( GtkMenuItem *_this, gpointer user_data )
{
  if( isFullscreen == 0 ){
    gtk_window_fullscreen( GTK_WINDOW( mainWindow ) );
  }
  else {
    gtk_window_unfullscreen( GTK_WINDOW( mainWindow ) );
    isFullscreen = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // do not complain about deprecated declarations
    gtk_tool_button_set_stock_id( toolbuttonFullscreen, "gtk-fullscreen" );
#pragma GCC diagnostic pop
    if( _gtk_widget_has_class( GTK_WIDGET( toolbar ), "fullscreen" ) == TRUE ){
      _gtk_widget_remove_class( GTK_WIDGET( toolbar ), "fullscreen" );
      _gtk_widget_remove_class( GTK_WIDGET( boxAppArea ), "bg_window_fullscreen" );
      _gtk_widget_add_class( GTK_WIDGET( boxAppArea ), "bg_window" );
      _gtk_widget_remove_class( GTK_WIDGET( boxWholeWindow ), "bg_window" );
    }
    gtk_widget_show( GTK_WIDGET( menu ) );
  }
}


int main( int argc, char **argv )
{
  //
  // Initialize GTK
  //
  gtk_init( &argc, &argv );

  //
  // Load CSS to use with the ui
  //
  GtkCssProvider *css_provider = gtk_css_provider_new();
  GdkDisplay *display = gdk_display_get_default();
  GdkScreen *screen = gdk_display_get_default_screen( display );
  gtk_style_context_add_provider_for_screen( screen, GTK_STYLE_PROVIDER( css_provider ), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION );
  gtk_css_provider_load_from_data( GTK_CSS_PROVIDER( css_provider ), (const gchar*)client_gtk_css, client_gtk_css_len, NULL );
  g_object_unref( css_provider );

  //
  // Load glade XML data for the main window and get the ui widgets
  //
  GtkBuilder *builder = gtk_builder_new();
  if( 0 == gtk_builder_add_from_string( builder, (const gchar*)client_main_window_glade, client_main_window_glade_len, NULL ) ){
    g_printf( "ERROR: Gtkuilder could not load the main window.\n" );
    return(0);
  }
  mainWindow           = GTK_WIDGET(      gtk_builder_get_object( builder, "mainWindow" ) );

  menu                 = GTK_MENU_BAR(    gtk_builder_get_object( builder, "menubar" ) );
  menuConnect          = GTK_MENU_ITEM(   gtk_builder_get_object( builder, "imagemenuitemConnect" ) );
  menuDisconnect       = GTK_MENU_ITEM(   gtk_builder_get_object( builder, "imagemenuitemDisconnect" ) );
  menuFullscreen       = GTK_MENU_ITEM(   gtk_builder_get_object( builder, "imagemenuitemFullscreen" ) );
  menuQuit             = GTK_MENU_ITEM(   gtk_builder_get_object( builder, "imagemenuitemQuit" ) );

  toolbar              = GTK_TOOLBAR(     gtk_builder_get_object( builder, "toolbar" ) );
  toolbuttonConnect    = GTK_TOOL_BUTTON( gtk_builder_get_object( builder, "toolbuttonConnect" ) );
  toolbuttonDisconnect = GTK_TOOL_BUTTON( gtk_builder_get_object( builder, "toolbuttonDisconnect" ) );
  toolbuttonFullscreen = GTK_TOOL_BUTTON( gtk_builder_get_object( builder, "toolbuttonFullscreen" ) );
  toolbuttonExit       = GTK_TOOL_BUTTON( gtk_builder_get_object( builder, "toolbuttonExit" ) );


  serverStatusOverlay  = GTK_OVERLAY(     gtk_builder_get_object( builder, "overlayToolbarConnectStatus" ) );
  serverStatusOnline   = GTK_EVENT_BOX(   gtk_builder_get_object( builder, "server-status-online" ) );
  serverStatusOffline  = GTK_EVENT_BOX(   gtk_builder_get_object( builder, "server-status-offline" ) );
  serverStatusConnecting = GTK_EVENT_BOX( gtk_builder_get_object( builder, "server-status-connecting" ) );
  serverStatusError    = GTK_EVENT_BOX(   gtk_builder_get_object( builder, "server-status-error" ) );

  commandStatusOverlay = GTK_OVERLAY(     gtk_builder_get_object( builder, "overlayToolbarCommandStatus" ) );
  commandStatusSending = GTK_EVENT_BOX(   gtk_builder_get_object( builder, "command-status-cmd-send" ) );
  commandStatusReady   = GTK_EVENT_BOX(   gtk_builder_get_object( builder, "command-status-cmd-ready" ) );
  commandStatusError   = GTK_EVENT_BOX(   gtk_builder_get_object( builder, "command-status-cmd-error" ) );
  commandStatusIdle    = GTK_EVENT_BOX(   gtk_builder_get_object( builder, "command-status-cmd-idle" ) );

  boxWholeWindow       = GTK_BOX(         gtk_builder_get_object( builder, "whole-window" ) );
  boxAppArea           = GTK_BOX(         gtk_builder_get_object( builder, "whole-app-area" ) );

  treeviewSIA          = GTK_TREE_VIEW(   gtk_builder_get_object( builder, "treeviewSIA" ) );
  liststoreSIA         = GTK_LIST_STORE(  gtk_builder_get_object( builder, "liststoreSIA" ) );
  commander_user_cmd   = GTK_ENTRY(       gtk_builder_get_object( builder, "commander-input" ) );
  commander_output     = GTK_TEXT_VIEW(   gtk_builder_get_object( builder, "commander-output" ) );
  log_output           = GTK_TEXT_VIEW(   gtk_builder_get_object( builder, "debug-console-output" ) );
//  GtkPaned *paned      = GTK_PANED(       gtk_builder_get_object( builder, "paned" ) );

  //
  // Set ui widget properties (that are not in the glade xml)
  //

  // Set titlebar
  gtk_window_set_title( GTK_WINDOW( mainWindow ), "openGalaxy Client" );

  // maximize the window
  gtk_window_maximize( GTK_WINDOW( mainWindow ) );

  // Add overlays to server status overlay
  // - online
  gtk_overlay_add_overlay( serverStatusOverlay, GTK_WIDGET( serverStatusOnline ) );
  gtk_widget_set_halign( GTK_WIDGET( serverStatusOnline ), GTK_ALIGN_CENTER );
  gtk_widget_set_valign( GTK_WIDGET( serverStatusOnline ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOnline ), 0.0 );
  // - offline
  gtk_overlay_add_overlay( serverStatusOverlay, GTK_WIDGET( serverStatusOffline ) );
  gtk_widget_set_halign( GTK_WIDGET( serverStatusOffline ), GTK_ALIGN_CENTER );
  gtk_widget_set_valign( GTK_WIDGET( serverStatusOffline ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusOffline ), 0.0 );
  // - connecting (to server)
  gtk_overlay_add_overlay( serverStatusOverlay, GTK_WIDGET( serverStatusConnecting ) );
  gtk_widget_set_halign( GTK_WIDGET( serverStatusConnecting ), GTK_ALIGN_CENTER );
  gtk_widget_set_valign( GTK_WIDGET( serverStatusConnecting ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusConnecting ), 0.0 );
  // - error (connected but no communication with the Galaxy)
  gtk_overlay_add_overlay( serverStatusOverlay, GTK_WIDGET( serverStatusError ) );
  gtk_widget_set_halign( GTK_WIDGET( serverStatusError ), GTK_ALIGN_CENTER );
  gtk_widget_set_valign( GTK_WIDGET( serverStatusError ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( serverStatusError ), 0.0 );

  // Add overlays to command status overlay
  // - Command send
  gtk_overlay_add_overlay( commandStatusOverlay, GTK_WIDGET( commandStatusSending ) );
  gtk_widget_set_halign( GTK_WIDGET( commandStatusSending ), GTK_ALIGN_END );
  gtk_widget_set_valign( GTK_WIDGET( commandStatusSending ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusSending ), 0.0 );
  // - Command ready
  gtk_overlay_add_overlay( commandStatusOverlay, GTK_WIDGET( commandStatusReady ) );
  gtk_widget_set_halign( GTK_WIDGET( commandStatusReady ), GTK_ALIGN_END );
  gtk_widget_set_valign( GTK_WIDGET( commandStatusReady ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusReady ), 0.0 );
  // - Command error
  gtk_overlay_add_overlay( commandStatusOverlay, GTK_WIDGET( commandStatusError ) );
  gtk_widget_set_halign( GTK_WIDGET( commandStatusError ), GTK_ALIGN_END );
  gtk_widget_set_valign( GTK_WIDGET( commandStatusError ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusError ), 0.0 );
  // - Command idle
  gtk_overlay_add_overlay( commandStatusOverlay, GTK_WIDGET( commandStatusIdle ) );
  gtk_widget_set_halign( GTK_WIDGET( commandStatusIdle ), GTK_ALIGN_END );
  gtk_widget_set_valign( GTK_WIDGET( commandStatusIdle ), GTK_ALIGN_CENTER );
  gtk_widget_set_opacity( GTK_WIDGET( commandStatusIdle ), 0.0 );

  //
  // Set ui signal handlers
  //

  // window
  gtk_widget_add_events( GTK_WIDGET( mainWindow ), GDK_CONFIGURE );
  g_signal_connect( G_OBJECT( mainWindow ), "configure-event", G_CALLBACK( cbMainWindow_configure ), NULL );
  g_signal_connect( G_OBJECT( mainWindow ), "destroy",  G_CALLBACK( _gtk_do_main_quit ), NULL ); // when the window get destroyed
  g_signal_connect( G_OBJECT( mainWindow ), "window-state-event",  G_CALLBACK( cbMainWindow_stateEvent ), NULL ); // when the window size has changed

  // toolbar
  g_signal_connect( G_OBJECT( toolbuttonConnect ), "clicked", G_CALLBACK( cbMenu_websocketConnect ), NULL ); // when the connect button was clicked
  g_signal_connect( G_OBJECT( toolbuttonDisconnect ), "clicked", G_CALLBACK( cbMenu_websocketDisconnect ), NULL ); // when the disconnect button was clicked
  g_signal_connect( G_OBJECT( toolbuttonFullscreen ), "clicked", G_CALLBACK( cbMenu_fullscreen ), NULL ); // when the fullscreen button was clicked
  g_signal_connect_swapped( G_OBJECT( toolbuttonExit ), "clicked", G_CALLBACK( _gtk_do_main_quit ), mainWindow ); // when the exit button was clicked

  // menu
  g_signal_connect( G_OBJECT( menuConnect ), "activate", G_CALLBACK( cbMenu_websocketConnect ), NULL );
  g_signal_connect( G_OBJECT( menuDisconnect ), "activate", G_CALLBACK( cbMenu_websocketDisconnect ), NULL );
  g_signal_connect( G_OBJECT( menuFullscreen ), "activate", G_CALLBACK( cbMenu_fullscreen ), NULL );
  g_signal_connect_swapped( G_OBJECT( menuQuit ), "activate", G_CALLBACK( _gtk_do_main_quit ), mainWindow );

  // Init areas notebook tab
  Area_Init( builder );

  //
  // Initialize non-ui parts
  //

  if(
    Log_Init() != 0 ||
    SIA_Init() != 0 ||
    Commander_Init() != 0 ||
    Websocket_InitThread() == NULL
  ){
    g_printf( "ERROR: main( 'Could not initialize!' );\n" );
    return(0);
  }

  Connect_setStatusOffline(); // set initial connection status


  gtk_widget_show_all( mainWindow );

  //
  // Enter GTK main loop
  //
  gtk_main();

  g_object_unref( G_OBJECT( builder ) );
  return 0;
}

