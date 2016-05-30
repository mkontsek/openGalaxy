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

#ifndef __OPENGALAXY_CLIENT_H__
#define __OPENGALAXY_CLIENT_H__

#include <gtk/gtk.h>

// The widgets for the mainWindow

extern GtkMenuBar    *menu;
extern GtkMenuItem   *menuConnect;
extern GtkMenuItem   *menuDisconnect;
extern GtkMenuItem *menuFullscreen;
extern GtkMenuItem   *menuQuit;

extern GtkToolbar    *toolbar;
extern GtkToolButton *toolbuttonConnect;
extern GtkToolButton *toolbuttonDisconnect;
extern GtkToolButton *toolbuttonFullscreen;
extern GtkToolButton *toolbuttonExit;

extern GtkOverlay    *serverStatusOverlay;
extern GtkEventBox   *serverStatusOnline,
                     *serverStatusOffline,
                     *serverStatusConnecting,
                     *serverStatusError;

extern GtkOverlay    *commandStatusOverlay;
extern GtkEventBox   *commandStatusSending,
                     *commandStatusReady,
                     *commandStatusError,
                     *commandStatusIdle;

extern GtkBox        *boxWholeWindow; // box with entire mainWindow
extern GtkBox        *boxAppArea; // box in the paned

extern GtkWidget     *mainWindow;
extern GtkTreeView   *treeviewSIA;
extern GtkListStore  *liststoreSIA;
extern GtkTextView   *commander_output;
extern GtkEntry      *commander_user_cmd;
extern GtkTextView   *log_output;

extern int isFullscreen;

#endif

