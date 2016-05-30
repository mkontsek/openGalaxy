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

/*
  Assortment of functions used by openGalaxy-ca
*/
#ifndef _SUPPORT_H_
#define _SUPPORT_H_

#include <gtk/gtk.h>
#include <stdarg.h>
#include <time.h>

int    _gtk_popen                    ( char *cmd, GtkTextBuffer *out );
int    _gtk_dialog_exec              ( char *cmd, const gchar *title, GtkWindow *parent );
int    _gtk_dialog_exec_printf       ( GtkWindow *parent, const gchar *title, const char *fmt, ... );
char **_gtk_dialog_exec_new_list     ( void );
int    _gtk_dialog_exec_list_printf  ( char ***cmdlist, const char *fmt, ... );
int    _gtk_dialog_exec_list         ( GtkWindow *parent, const gchar *title, char **cmdlist, int do_check );
void   _gtk_dialog_exec_free_list    ( char **cmdlist );
int    _gtk_display_error_dialog     ( GtkWidget* parent, const gchar *title, const gchar *fmt, ... );
int    __gtk_display_error_dialog    ( const gchar *msg, const gchar *title, GtkWidget* parent, GCallback cb );
int    is_regular_file               ( char *fn );
int    is_ip_address                 ( const char *ip );
int    set_opengalaxy_gid            ( const char *path );
int    _mkdir                        ( const char *path, mode_t mode );
int    mkpath                        ( const char *path, mode_t mode );
time_t date2epoch                    ( char *date );
int    has_invalid_characters        ( const char *text, const char *invalid );
int    strtrim                       ( char *str );

#endif

