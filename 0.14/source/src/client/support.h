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

#ifndef __OPENGALAXY_CLIENT_SUPPORT_H__
#define __OPENGALAXY_CLIENT_SUPPORT_H__

#include <glib.h>
#include <gtk/gtk.h>

extern const char *str_registry_install_dir;
extern const char *str_registry_data_dir;
extern const char *str_registry_config_dir;
extern const char *str_registry_opengalaxyca_dir;
extern const char *str_registry_www_dir;
const char* openGalaxyGetRegistry( const char *key );
#define GET_INSTALL_DIR (openGalaxyGetRegistry(str_registry_install_dir))
#define GET_CERTS_DIR (openGalaxyGetRegistry(str_registry_data_dir))
#define GET_DATA_DIR (openGalaxyGetRegistry(str_registry_data_dir))
#define GET_CONFIG_DIR (openGalaxyGetRegistry(str_registry_config_dir))
#define GET_CA_EXE_DIR (openGalaxyGetRegistry(str_registry_opengalaxyca_dir))
#define GET_WWW_DIR (openGalaxyGetRegistry(str_registry_www_dir))

// Callback for when the contents of a GtkTextBuffer has changed.
void G_MODULE_EXPORT cbTextbufferScrollToStart( GtkTextView *_this, gpointer user_data );

// Callback for when the contents of a GtkTreeView has changed.
void G_MODULE_EXPORT cbTreeViewScrollToStart( GtkTreeView *_this, gpointer user_data );

// Callback for when the contents of a GtkTextBuffer has changed.
void G_MODULE_EXPORT cbTextbufferScrollToEof( GtkTextView *_this, gpointer user_data );


// General purpose informational dialog
void InfoMessageBox( GtkWidget *parent, char *title, char *fmt, ... );


//
// Functions to test/add/remove a CSS class for/to/from a GTK widget 
//

gboolean _gtk_widget_has_class( GtkWidget *widget, const gchar *class_name );
void     _gtk_widget_add_class( GtkWidget *widget, const gchar *class_name );
void     _gtk_widget_remove_class( GtkWidget *widget, const gchar *class_name );

//
// Functions to aid working with a list of (needed filenames of) client certificates
//

// A list of client certificates
typedef struct certs_list_t {
  char *ca_pem;
  char *fn_p12;
  char *fn_pem;
  char *fn_key;
  char *display;
  struct certs_list_t *next;
} certs_list;

// Locates and adds all client certs to a list of certs
int certsList_get( struct certs_list_t **list );

// Free's the list of client certs
void certsList_free( struct certs_list_t **list );

// Copies a list of client certs to the liststore in a combobox
void certsList_fillComboStore( struct certs_list_t **list, GtkComboBox *combo, GtkListStore *store );

#endif

