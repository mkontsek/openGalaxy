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

// TODO verander de manier voor het invoeren van de naam van de client
// (gebruik 1 regel voor de hele voornaam/voornamen + tussenvoegsels etc + achternaam/achternamen)
// 512 byte limiet is toch wel acceptabel???

// TODO voeg privileges toe aan de credentials
//
// (Basic client information)
// name     : base64 encoded real name (string)
// surname  : base64 encoded real surname (string)
// login    : base64 encoded login name (string)
// password : base64 encoded login password (string)
//
// (Areas this client may (dis)arm)
// arm      : 32bit decimal value (each bit representing an area)
// disarm   : 32bit decimal value (each bit representing an area)
// partset  : 32bit decimal value (each bit representing an area)
//
// (Zones this client may omit / set parameter / program)
// omit     : Array of 64 bytes (512 bits each representing a zone)
// param    : Array of 64 bytes (512 bits each representing a zone)
// program  : Array of 64 bytes (512 bits each representing a zone)
//
// (Outputs this client may (re)set)
// outputs  : Array of 32 bytes (256 bits each representing an output)
//
// In function cert_write_FN_CLIENTCNF() the entire formatted string is written
// to a temporary file that is then encrypted 
//
// After reading back the encrypted data from the temporary file this data is
// again base64 encoded before being added to the certificate under
// SubjectAlternativeName->otherName with OID_OTHERNAME as the object identifier
//
// Possibly zip the encrypted data ???
//
/*
static const char *fmt_client_json =
  "{"
  "\"name\":\"%s\","
  "\"surname\":\"%s\","
  "\"login\":\"%s\","
  "\"password\":\"%s\","
  "\"arm\":%u,"
  "\"disarm\":%u,"
  "\"partset\":%u,"
  "\"omit\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],"
  "\"param\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],"
  "\"program\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u],"
  "\"outputs\":[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u]"
  "}";

  sprintf(
    json,
    fmt_client_json,
    b64name,
    b64surname,
    b64login,
    b64password,
    // Privileges
    0xFFFFFFFF, // arm areas
    0xFFFFFFFF, // disarm areas
    0xFFFFFFFF, // partset areas
    // omit zones
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 1
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 2
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 3
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 4
    // set zone parameters
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 1
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 2
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 3
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 4
    // change zones programming
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 1
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 2
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 3
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, // RIOs line 4
    // (re)set outputs
    01,23,45,67,89,1011,1213,1415, // RIOs lines 1 & 2
    01,23,45,67,89,1011,1213,1415  // RIOs lines 3 & 4
  );

*/


#include "atomic.h"

/*
 * Playing arround with the private key algorithm:
 *
 * The type of algorithm to use for generating private keys
 * is a compile time option and is set here.
 *
 * For normal operation GENPKEY_ALGORITHM_RSA should be selected...
 */
#define GENPKEY_ALGORITHM_RSA 1
#define GENPKEY_ALGORITHM_DSA 2
#define GENPKEY_ALGORITHM_EC 3
#define GENPKEY_ALGORITHM_DH 4

#define CA_GENPKEY_ALGORITHM GENPKEY_ALGORITHM_RSA
#define SERVER_GENPKEY_ALGORITHM GENPKEY_ALGORITHM_RSA
#define CLIENT_GENPKEY_ALGORITHM GENPKEY_ALGORITHM_RSA

#if __linux__
#include <X11/Xlib.h>
#else
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "libwebsockets.h"

#if __linux__
#include <sys/wait.h>
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function" // do not create errors from warnings in gtk.h when using -Wall -Werror
#include <gtk/gtk.h>
#pragma GCC diagnostic pop

#include "support.h"
#include "websocket.h"

#include "ssl_evp.h"
#include "credentials.h"


// Include the C header file generated from the glade XML file: ca_main_window.glade
// defines:
// const gchar ca_main_window_glade[]
// const guint ca_main_window_glade_len
#include "ca_main_window.h"

// Include the C header file generated from the glade XML file: ca_password_dialog.glade
// defines:
// const gchar ca_password_dialog_glade[]
// const guint ca_password_dialog_glade_len
#include "ca_password_dialog.h"

// Include the C header files generated from the CSS files used with the glade XML files
// defines:
// const gchar ca_gtk_css[]
// const guint ca_gtk_css_len
#include "ca_gtk.h"

#if ! __linux__
#define EXE_SUFFIX ".exe"
#define CRLF "\n"
#else
#define EXE_SUFFIX ""
#define CRLF "\n"
#endif

// The maximum length of a command on the commandline (kb830473)
#define CMD_MAX_LEN 8191

#if __linux__
#ifndef _CERT_DIR_
#error _CERT_DIR_ has not been set!
#endif
#ifndef _CONFIG_DIR_
#error _CONFIG_DIR_ has not been set!
#endif
#ifndef _SHARE_DIR_
#error _SHARE_DIR_ has not been set!
#endif
static const char     *cert_dir = _CERT_DIR_;
static const char     *share_dir = _SHARE_DIR_;
#else
static char           *cert_dir = _CERT_DIR_;
static char           *config_dir = _CONFIG_DIR_;
static char           *share_dir = _SHARE_DIR_;
#endif

// The OID to use when embedding data in the client certificates.
#define OTHERNAME_OID "1.2.3.4"

GtkWidget      *window;
static GtkEntryBuffer *entrybuffer_caorganization;
static GtkEntryBuffer *entrybuffer_caorganizationalunit;
static GtkEntryBuffer *entrybuffer_cacommonname;
static GtkEntryBuffer *entrybuffer_caemail;
static GtkWidget      *button_cakey;
static GtkWidget      *button_careq;
static GtkWidget      *button_casign;
static GtkWidget      *button_carevoke;
static GtkWidget      *box_cakeysize;
static GtkWidget      *comboboxtext_cakeysize;
static GtkWidget      *box_cadays;
static GtkWidget      *spinbutton_cadays;
static GtkEntryBuffer *entrybuffer_servercommonname;
static GtkEntryBuffer *entrybuffer_serveraltdns;
static GtkEntryBuffer *entrybuffer_serveraltip;
static GtkEntryBuffer *entrybuffer_serveremail;
static GtkWidget      *entry_servercommonname;
static GtkWidget      *entry_serveraltdns;
static GtkWidget      *entry_serveraltip;
static GtkWidget      *entry_serveremail;
static GtkWidget      *button_serverkey;
static GtkWidget      *button_serverreq;
static GtkWidget      *button_serversign;
static GtkWidget      *button_serverrevoke;
static GtkWidget      *box_serverkeysize;
static GtkWidget      *comboboxtext_serverkeysize;
static GtkWidget      *box_serverdays;
static GtkWidget      *spinbutton_serverdays;
static GtkWidget      *frame_servercommonname;
static GtkWidget      *frame_serveraltname;
static GtkWidget      *frame_serveremail;
static GtkWidget      *button_clientkey;
static GtkWidget      *button_clientreq;
static GtkWidget      *button_clientsign;
static GtkWidget      *button_clientrevoke;
static GtkWidget      *button_clientdelete;
static GtkWidget      *box_clientkeysize;
static GtkWidget      *comboboxtext_clientkeysize;
static GtkWidget      *box_clientdays;
static GtkWidget      *spinbutton_clientdays;
static GtkWidget      *label_clientlist;
static GtkWidget      *combobox_clientlist;
static GtkListStore   *liststore_clientlist;
static GtkWidget      *box_clientname;
static GtkWidget      *entry_clientname;
static GtkEntryBuffer *entrybuffer_clientname;
static GtkWidget      *box_clientsurname;
static GtkWidget      *entry_clientsurname;
static GtkEntryBuffer *entrybuffer_clientsurname;
static GtkWidget      *box_clientemail;
static GtkWidget      *entry_clientemail;
static GtkEntryBuffer *entrybuffer_clientemail;
static GtkWidget      *box_clientlogin;
static GtkWidget      *box_clientpassword;
static GtkWidget      *entry_clientlogin;
static GtkWidget      *entry_clientpassword;
static GtkEntryBuffer *entrybuffer_clientlogin;
static GtkEntryBuffer *entrybuffer_clientpassword;
static GtkWidget      *button_clientnew;
static GtkWidget      *textview_about;
static GtkWidget      *textview_gnu;
static GtkWidget      *label_version;

// password confirmation dialog
static GtkWidget      *button_clientpassword_confirm;
static GtkEntryBuffer *entrybuffer_clientpassword_confirm;

// Data for the connect-to-server dialog
GtkWidget      *button_upload;



// used to detect invalid charaters in input values
static const char     *fn_invalid_chars                    = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F`~!,<.>;:\"'/\\|?*";
static const char     *email_invalid_chars                 = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F,;:\"\\";
static const char     *url_invalid_chars                   = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F`^{}|<>";

// Basenames for the files
static const char     *ca_basename                         = "openGalaxyCA";
static const char     *cakey_basename                      = "openGalaxyCAKEY";
static const char     *capubkey_basename                   = "openGalaxyCAPUBKEY";
static const char     *crl_basename                        = "openGalaxyCRL";
static const char     *server_basename                     = "server";
static const char     *serverkey_basename                  = "serverKEY";
static const char     *client_unencrypt_basename           = "credentials";
static const char     *client_encrypted_basename           = "credentials-enc";
static const char     *credentials_key_basename            = "credentialsKEY";
static const char     *credentials_pubkey_basename         = "credentialsPUBKEY";

// Variables that have all capital names are assumed to be malloced
// and are free'd automaticaly at program exit by atexit_clean_vars().
static char           *OPENSSL_VERSION                     = NULL;
static char           *FN_CAKEY_PARAM                      = NULL;
char           *FN_CAKEY                            = NULL;
char           *FN_CAPUBKEY                         = NULL;
static char           *FN_CAREQ                            = NULL;
char           *FN_CAPEM                            = NULL;
static char           *FN_CACRT                            = NULL;
static char           *FN_CAPWD                            = NULL;
char           *FN_CRL                              = NULL;
static char           *FN_SERVERKEY_PARAM                  = NULL;
char           *FN_SERVERKEY                        = NULL;
static char           *FN_SERVERREQ                        = NULL;
char           *FN_SERVERPEM                        = NULL;
static char           *FN_CACNF                            = NULL;
static char           *FN_SERVERCNF                        = NULL;
static char           *FN_CLIENTBASECNF                    = NULL;
static char           *FN_CLIENTCNF                        = NULL;
static char           *CA_EMAIL_ADDRESS                    = NULL;
static int             CA_KEY_SIZE                         = 2048;
static long            CA_DAYS_VALID                       = 3650;
static char           *SERVER_EMAIL_ADDRESS                = NULL;
static char           *SERVER_URL                          = NULL;
static char           *SERVER_ALT_URL                      = NULL;
static char           *SERVER_ALT_IP                       = NULL;
static int             SERVER_KEY_SIZE                     = 2048;
static long            SERVER_DAYS_VALID                   = 3650;
static char           *SERVER_ALT                          = NULL;
static char           *CLIENT_NAME                         = NULL;
static char           *CLIENT_MAIL                         = NULL;
static int             CLIENT_KEY_SIZE                     = 2048;
static long            CLIENT_DAYS_VALID                   = 365;
static char           *CLIENT_CERT_NAME                    = NULL;
char           *CERTFILES                           = NULL;
char           *FN_CRED_KEY                         = NULL;
char           *FN_CRED_PUBKEY                      = NULL;
static char           *FN_TMP_UNENCRYPTED                  = NULL;
static char           *FN_TMP_ENCRYPTED                    = NULL;

//******************************
//     OpenSSL executeable
//******************************
static const char     *fmt_openssl_dir                     = "";
static const char     *fmt_openssl_exe                     = "openssl"EXE_SUFFIX;

// non-zero when a file exists (checked by cert_check_certificate_subtree())
static int             have_cakey                          = 0;
static int             have_careq                          = 0;
static int             have_capem                          = 0;
static int             have_cacrt                          = 0;
static int             have_crl                            = 0;
static int             have_servercnf                      = 0;
static int             have_serverkey                      = 0;
static int             have_serverreq                      = 0;
static int             have_serverpem                      = 0;

// non-zero when the user has entered this variable on the clients notebook tab
static int             have_clientname                     = 0;
static int             have_clientsurname                  = 0;
static int             have_clientemail                    = 0;
static int             have_clientlogin                    = 0;
static int             have_clientpassword                 = 0;

// translatable strings
static const char     *cmd_title_ca_key                    = "Generate CA private key";
static const char     *cmd_title_ca_req                    = "Create CA certificate request";
static const char     *cmd_title_ca_pem                    = "Sign CA certificate";
static const char     *cmd_title_ca_revoke                 = "Revoke CA certificate";
static const char     *cmd_title_server_key                = "Generate server private key";
static const char     *cmd_title_server_req                = "Create server certificate request";
static const char     *cmd_title_server_pem                = "Sign server certificate";
static const char     *cmd_title_server_revoke             = "Revoke server certificate";
static const char     *cmd_title_client_key                = "Generate client private key.";
static const char     *cmd_title_client_req                = "Create client certificate request";
static const char     *cmd_title_client_pem                = "Sign client certificate";
static const char     *cmd_title_client_revoke             = "Revoke client certificate";
static const char     *str_main_title                      = "openGalaxyCA";
static const char     *str_enter_client_name               = "Enter a name...";
static const char     *str_enter_client_surname            = "Enter a surname...";
static const char     *str_enter_client_email              = "Enter an email address...";
static const char     *str_enter_client_login              = "Enter a username...";
static const char     *str_enter_client_password           = "Enter a password...";
static const char     *str_primary_url                     = "the primary URL";
static const char     *str_alt_url                         = "the alternative URL(s)";
static const char     *str_alt_ip                          = "the alternative IP address(es)";
static const char     *str_alt_email                       = "the administrative email address";
static const char     *str_client_name                     = "the client name";
static const char     *str_client_surname                  = "the client surname";
static const char     *str_client_email                    = "the email address";
static const char     *str_client_login                    = "the username";
static const char     *str_client_password                 = "the password";
static const char     *msg_error                           = "Error";
static const char     *msg_outofmem                        = "Out of memory!";
static const char     *msg_daterange                       = "Date out of range!";
static const char     *msg_fail_cert_read                  = "Could not open a certificate file for reading!";
static const char     *msg_fail_cert_dir_open              = "Could not open the clients certificate directory!";
static const char     *fmt_fail_cnf_missing_value          = "Error in configuration file:\n%s\n\nThe value for \'%s\' is empty!";
static const char     *msg_fail_cnf_write                  = "Could not write .cnf file!";
static const char     *msg_need_primary                    = "The primary DNS name or IP address must contain a value!";
static const char     *fmt_msg_fail_cert_dir               = "The certificates directory (/usr[/local]/share/galaxy/ssl) could not be created or was not accessible! Please check the file permissions or execute opengalaxy-ca as root/administrator.\n\nThe error was: %s (%d)\n";
static const char     *fmt_msg_fail_exec_openssl           = "OpenSSL could not be executed, please make sure that openssl"EXE_SUFFIX" can be found in your systems path.\n\nThe error was: %s (%d)\n";
static const char     *fmt_msg_fail_cert_tree              = "Error initializing the certificate directory tree.\n\nThe error was: %s (%d)\n";
static const char     *fmt_msg_fail_parameters             = "Error retrieving parameters from existing certificate files.\n\nThe error was: %s (%d)\n";
static const char     *fmt_msg_fail_tmp_file               = "Error initializing some temporary files.\n\nThe error was: %s (%d)\n";
static const char     *fmt_msg_fail_file_write             = "Failed to write the file: \"%s\"";
static const char     *fmt_msg_fail_file_write_errno       = "The file '%s' could not be (re)written.\n\nThe error was: %s (%d)\n";
static const char     *fmt_msg_fail_client_exists          = "The client \"%s %s\" with login \"%s\" allready exists, please provide other credentials.";
static const char     *fmt_msg_fail_variables              = "Could not initialize program variables.\n\nThe error is: %s (%d)\n";
static const char     *fmt_msg_string_validate             = "Invalid characters were found in %s.\nPlease correct it to continue.";
static const char     *fmt_msg_fail_glade                  = "Could not parse Glade XML data:\n%s";
static const char     *fmt_msg_fail_encrypt                = "Could not encrypt user credentials!\n%s";
static const char     *fmt_msg_fail_passphrase             = "Could not open/read passphrase file!\n%s";
static const char     *fmt_msg_fail_load_pkey              = "Could not load RSA key!\n%s";
#if ! __linux__
static const char     *msg_error_registry_read             = "Could not read from the system registry!";
static const char     *fmt_msg_fail_registry_inst_path     = "Could not retrieve installation path '%s' from the registry.\n\nThe error is: %s (%d)\n";
static const char     *fmt_msg_fail_registry_cert_dir      = "Could not set up certificates directory '%s'.\n\nThe error is: %s (%d)\n";
#endif

// non translateable strings
static const char     *str_default_server_ip               = "localhost";
static const char     *str_default_server_alt_url          = "";
static const char     *str_default_server_alt_ip           = "127.0.0.1";
static const char     *str_default_server_email            = "<empty>";
static const char     *str_default_ca_commonname           = "openGalaxyCA";
static const char     *str_default_ca_organization         = "openGalaxy";
static const char     *str_default_ca_organizationalunit   = "openGalaxy websocket interface";
static const char     *str_default_ca_email                = "<empty>";
static const char     *str_fn_default_passphrase           = "passphrase.txt";
static const char     *cmd_openssl_version                 = "%s%s version 2>&1";

// Commands for the CA key
#if CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
static const char     *cmd_print_cakey                     = "%s%s rsa -text -noout -in \"%s\" -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%d -aes-256-cbc -out \"%s\" -pass \"file:%s\" 2>&1";
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
static const char     *cmd_print_cakey                     = "%s%s dsa -text -noout -in \"%s\" -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_cakey_param                 = "%s%s genpkey -genparam -algorithm DSA -out \"%s\" -pkeyopt dsa_paramgen_bits:%d 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -des3 -out \"%s\" -pass \"file:%s\" 2>&1";
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
static const char     *cmd_print_cakey                     = "%s%s ec -in \"%s\" -noout -text -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_cakey_param                 = "%s%s genpkey -genparam -algorithm EC -out \"%s\" -pkeyopt ec_paramgen_curve:prime256v1 ec_param_enc:named_curve 2>&1"; // aka secp256r1
static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -out \"%s\" -aes-256-cbc -pass \"file:%s\" 2>&1";
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
static const char     *cmd_print_cakey                     = "%s%s dh -in \"%s\" -noout -text -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_cakey_param                 = "%s%s genpkey -genparam -algorithm DH -out \"%s\" -pkeyopt dh_paramgen_prime_len:2048 dh_paramgen_generator:224 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -out \"%s\" -des3 -pass \"file:%s\" 2>&1";
#else
#error No CA_GENPKEY_ALGORITHM selected
#endif

// Commands for the server key
#if SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
static const char     *cmd_print_srvkey                    = "%s%s rsa -text -noout -in \"%s\" 2>&1";
static const char     *cmd_gen_srvkey                      = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%u -out \"%s\" 2>&1";
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
static const char     *cmd_print_srvkey                    = "%s%s dsa -text -noout -in \"%s\" 2>&1";
static const char     *cmd_gen_srvkey_param                = "%s%s genpkey -genparam -algorithm DSA -out \"%s\" -pkeyopt dsa_paramgen_bits:%u 2>&1";
static const char     *cmd_gen_srvkey                      = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
static const char     *cmd_print_srvkey                    = "%s%s ec -in \"%s\" -noout -text 2>&1";
static const char     *cmd_gen_srvkey_param                = "%s%s genpkey -genparam -algorithm EC -out \"%s\" -pkeyopt ec_paramgen_curve:prime256v1 ec_param_enc:named_curve 2>&1"; // aka secp256r1
static const char     *cmd_gen_srvkey                      = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
static const char     *cmd_print_srvkey                    = "%s%s dh -in \"%s\" -noout -text 2>&1";
static const char     *cmd_gen_srvkey_param                = "%s%s genpkey -genparam -algorithm DH -out \"%s\" -pkeyopt dh_paramgen_prime_len:2048 dh_paramgen_generator:224 2>&1";
static const char     *cmd_gen_srvkey                      = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
#else
#error No SERVER_GENPKEY_ALGORITHM selected
#endif

// Commands for the client key
#if CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
static const char     *cmd_print_clkey                     = "%s%s rsa -text -noout -in \"%s\" 2>&1";
static const char     *cmd_gen_clkey                       = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%u -out \"%s\" 2>&1";
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
static const char     *cmd_print_clkey                     = "%s%s dsa -text -noout -in \"%s\" 2>&1";
static const char     *cmd_gen_clkey_param                 = "%s%s genpkey -genparam -algorithm DSA -out \"%s\" -pkeyopt dsa_paramgen_bits:%u 2>&1";
static const char     *cmd_gen_clkey                       = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
static const char     *cmd_print_clkey                     = "%s%s ec -in \"%s\" -noout -text 2>&1";
static const char     *cmd_gen_clkey_param                 = "%s%s genpkey -genparam -algorithm EC -out \"%s\" -pkeyopt ec_paramgen_curve:prime256v1 ec_param_enc:named_curve 2>&1"; // aka secp256r1
static const char     *cmd_gen_clkey                       = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
static const char     *cmd_print_clkey                     = "%s%s dh -in \"%s\" -noout -text 2>&1";
static const char     *cmd_gen_clkey_param                 = "%s%s genpkey -genparam -algorithm DH -out \"%s\" -pkeyopt dh_paramgen_prime_len:2048 dh_paramgen_generator:224 2>&1";
static const char     *cmd_gen_clkey                       = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
#else
#error No CLIENT_GENPKEY_ALGORITHM selected
#endif

/*
#if GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_MIX
static const char     *cmd_print_key                       = "%s%s rsa -text -noout -in \"%s\" 2>&1";
static const char     *cmd_print_cakey                     = "%s%s dsa -text -noout -in \"%s\" -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_key                         = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%u -out \"%s\" 2>&1";
static const char     *cmd_gen_cakey_param                 = "%s%s genpkey -genparam -algorithm DSA -out \"%s\" -pkeyopt dsa_paramgen_bits:%d 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -aes-256-cbc -out \"%s\" -pass \"file:%s\" 2>&1";
#endif

#if GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
// rsa
static const char     *cmd_print_key                       = "%s%s rsa -text -noout -in \"%s\" 2>&1";
static const char     *cmd_print_cakey                     = "%s%s rsa -text -noout -in \"%s\" -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_key                         = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%u -out \"%s\" 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%d -aes-256-cbc -out \"%s\" -pass \"file:%s\" 2>&1";

// This is what we want to use, but openssl is broken
//static const char     *cmd_gen_cakey                       = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:%d -aes-128-gcm -out \"%s\" -pass \"file:%s\" 2>&1";

#endif

#if GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
// dsa
static const char     *cmd_print_key                       = "%s%s dsa -text -noout -in \"%s\" 2>&1";
static const char     *cmd_print_cakey                     = "%s%s dsa -text -noout -in \"%s\" -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_key_param                   = "%s%s genpkey -genparam -algorithm DSA -out \"%s\" -pkeyopt dsa_paramgen_bits:%u 2>&1";
static const char     *cmd_gen_cakey_param                 = "%s%s genpkey -genparam -algorithm DSA -out \"%s\" -pkeyopt dsa_paramgen_bits:%d 2>&1";
static const char     *cmd_gen_key                         = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
//static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -aes-256-cbc -out \"%s\" -pass \"file:%s\" 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -des3 -out \"%s\" -pass \"file:%s\" 2>&1";
#endif

#if GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
static const char     *cmd_print_key                       = "%s%s ec -in \"%s\" -noout -text 2>&1";
static const char     *cmd_print_cakey                     = "%s%s ec -in \"%s\" -noout -text -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_key_param                   = "%s%s genpkey -genparam -algorithm EC -out \"%s\" -pkeyopt ec_paramgen_curve:prime256v1 ec_param_enc:named_curve 2>&1"; // aka secp256r1
static const char     *cmd_gen_cakey_param                 = "%s%s genpkey -genparam -algorithm EC -out \"%s\" -pkeyopt ec_paramgen_curve:prime256v1 ec_param_enc:named_curve 2>&1"; // aka secp256r1
static const char     *cmd_gen_key                         = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -out \"%s\" -aes-256-cbc -pass \"file:%s\" 2>&1";
#endif

#if GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
static const char     *cmd_print_key                       = "%s%s dh -in \"%s\" -noout -text 2>&1";
static const char     *cmd_print_cakey                     = "%s%s dh -in \"%s\" -noout -text -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_key_param                   = "%s%s genpkey -genparam -algorithm DH -out \"%s\" -pkeyopt dh_paramgen_prime_len:2048 dh_paramgen_generator:224 2>&1";
static const char     *cmd_gen_cakey_param                 = "%s%s genpkey -genparam -algorithm DH -out \"%s\" -pkeyopt dh_paramgen_prime_len:2048 dh_paramgen_generator:224 2>&1";
static const char     *cmd_gen_key                         = "%s%s genpkey -paramfile \"%s\" -out \"%s\" 2>&1";
static const char     *cmd_gen_cakey                       = "%s%s genpkey -paramfile \"%s\" -out \"%s\" -des3 -pass \"file:%s\" 2>&1";
#endif
*/

static const char     *cmd_gen_careq                       = "%s%s req -config \"%s\" -new -key \"%s\" -out \"%s\" -passin \"file:%s\" 2>&1";
static const char     *cmd_gen_server_req                  = "%s%s req -config \"%s\" -new -days %ld -out \"%s\" -key \"%s\" -nodes 2>&1";
static const char     *cmd_gen_client_req                  = "%s%s req -config \"%s\" -new -out \"%s\" -key \"%s\" -nodes 2>&1";

static const char     *cmd_gen_capem                       = "%s%s ca -config \"%s\" -create_serial -days %ld -batch -selfsign -extensions v3_ca -passin \"file:%s\" -out \"%s\" -keyfile \"%s\" -infiles \"%s\" 2>&1";
static const char     *cmd_gen_server_pem                  = "%s%s ca -batch -config \"%s\" -policy policy_match -extensions v3_req_server -passin \"file:%s\" -days %ld -out \"%s\" -infiles \"%s\" 2>&1";
static const char     *cmd_gen_client_pem                  = "%s%s ca -batch -config \"%s\" -policy policy_match -extensions v3_req_client -passin \"file:%s\" -days %u -out \"%s\" -infiles \"%s\" 2>&1";

static const char     *cmd_gen_crl                         = "%s%s ca -config \"%s\" -gencrl -out \"%s\" -passin \"file:%s\" 2>&1";
//static const char     *cmd_gen_server_crt                  = "%s%s x509 -sha512 -in \"%s\" -outform DER -out \"%s\" 2>&1";
static const char     *cmd_gen_server_crt                  = "%s%s x509 -in \"%s\" -outform DER -out \"%s\" 2>&1";
static const char     *cmd_gen_client_p12                  = "%s%s pkcs12 -clcerts -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -export -in \"%s\" -inkey \"%s\" -name \"%s %s\" -passout pass: -out \"%s\" 2>&1";
//static const char     *cmd_gen_client_p12                  = "%s%s pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -descert -export -in \"%s\" -inkey \"%s\" -name \"%s %s\" -passout pass: -out \"%s\" 2>&1";
//static const char     *cmd_gen_client_p12                  = "%s%s pkcs12 -aes256 -certpbe PBE-SHA1-3DES -export -in \"%s\" -inkey \"%s\" -name \"%s %s\" -passout pass: -out \"%s\" 2>&1";
static const char     *cmd_revoke_cert                     = "%s%s ca -config \"%s\" -revoke \"%s\" -passin \"file:%s\" 2>&1";
static const char     *cmd_print_cert                      = "%s%s x509 -text -noout -in \"%s\" 2>&1";

static const char     *cmd_gen_capubkey                    = "%s%s rsa  -passin \"file:%s\" -in \"%s\" -out \"%s\" -outform PEM -pubout 2>&1";
static const char     *cmd_cred_gen_key                    = "%s%s genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out \"%s\" 2>&1";
static const char     *cmd_cred_gen_pubkey                 = "%s%s rsa -in \"%s\" -out \"%s\" -outform PEM -pubout 2>&1";

static const char     *str_openssl                         = "OpenSSL";
static const char     *str_empty                           = "";
static const char     *str_ip                              = "IP:";
static const char     *str_dns                             = "DNS:";
static const char     *str_comma                           = ",";
static const char     *str_not_before                      = "Not Before: ";
static const char     *str_not_after                       = "Not After : ";
static const char     *fmt_file_path                       = "%s/%s";
static const char     *fmt_file_path_key_param             = "%s/private/%s.param.pem";
static const char     *fmt_file_path_key                   = "%s/private/%s.pem";
static const char     *fmt_file_path_credentials           = "%s/private/%s.dat";
static const char     *fmt_file_path_req                   = "%s/req/%s.csr";
static const char     *fmt_file_path_pem                   = "%s/certs/%s.pem";
static const char     *fmt_file_path_crt                   = "%s/certs/%s.crt";
static const char     *fmt_file_path_cnf                   = "%s/certs/%s.cnf";
static const char     *fmt_file_path_ca_cnf                = "%s/CACNF-XXXXXX";
static const char     *fmt_file_path_client_cnf            = "%s/certs/users/%s.cnf";
static const char     *fmt_file_path_client_key_param      = "%s/private/users/%s-KEY.param.pem";
static const char     *fmt_file_path_client_key            = "%s/private/users/%s-KEY.pem";
static const char     *fmt_file_path_client_req            = "%s/req/users/%s.csr";
static const char     *fmt_file_path_client_pem            = "%s/certs/users/%s.pem";
static const char     *fmt_file_path_client_p12            = "%s/certs/users/%s.pfx";
static const char     *fmt_file_path_clients               = "%s/certs/users";
static const char     *fmt_file_path_newcerts              = "%s/newcerts/%s";
static const char     *token_opengalaxy                    = "opengalaxy";
static const char     *token_client_name                   = "name";
static const char     *token_client_surname                = "surname";
static const char     *token_client_email                  = "email";
static const char     *token_client_login                  = "login";
static const char     *token_client_password               = "password";
static const char     *token_server_url                    = "server_url";
static const char     *token_server_alt_url                = "server_alt_url";
static const char     *token_server_alt_ip                 = "server_alt_ip";
static const char     *token_server_email                  = "server_email";
static const char     *token_delim_1                       = " \t\n\r";
static const char     *token_delim_2                       = "=\" \t\n\r";
static const char     *token_delim_2_1                     = "=\"\t\n\r";
static const char     *token_delim_2_2                     = "=";
static const char     *token_delim_3                       = " \t";
static const char     *token_delim_4                       = "] \t";
static const char     *token_delim_5                       = "()";
#if ! __linux__
static const char     *str_registry_data_dir               = "DataDirectory";
static const char     *str_registry_opengalaxy_bindir      = "openGalaxyDirectory";
static const char     *fmt_file_current_dir                = "./%s";
static const char     *fmt_environment_path                = "PATH=\"%s\"";
#endif
static const char     *str_signal_destroy                  = "destroy";
static const char     *str_signal_clicked                  = "clicked";
static const char     *str_signal_changed                  = "changed";
static const char     *str_signal_value_changed            = "value-changed";
static const char     *str_signal_activate                 = "activate";

// CNF Base (please do not modify the order of the parameters...)
static const char cnf_base[] =
  "[ ca ]"CRLF
  "default_ca              = CA_default"CRLF
  ""CRLF
  "[ CA_default ]"CRLF
  "dir                     = \"%s\""CRLF              // 1. CERTFILES
  "certs                   = $dir/certs"CRLF
  "crl_dir                 = $dir/certs"CRLF
  "database                = $dir/index.txt"CRLF
  "new_certs_dir           = $dir/newcerts"CRLF
  "certificate             = $dir/certs/%s.pem"CRLF   // 2. ca_basename
  "private_key             = $dir/private/%s.pem"CRLF // 3. cakey_basename
  "serial                  = $dir/serial"CRLF
  "crl                     = $dir/certs/%s.pem"CRLF   // 4. crl_basename
  "crlnumber               = $dir/crlnumber"CRLF
  "default_days            = 3650"CRLF
  "default_crl_days        = 3650"CRLF
#if CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
  "default_md              = sha384"CRLF
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
  "default_md              = sha256"CRLF
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
  "default_md              = sha384"CRLF
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
  "default_md              = dss1"CRLF
#endif
  "preserve                = no"CRLF
  "policy                  = policy_match"CRLF
  ""CRLF
  "# Set to 'no' to allow creation of several certificates with same subject."CRLF
  "unique_subject          = no"CRLF
  ""CRLF
  "name_opt                = ca_default"CRLF
  "cert_opt                = ca_default"CRLF
  ""CRLF
  "RANDFILE                = /dev/random"CRLF
  ""CRLF
  "[ policy_match ]"CRLF
  "countryName             = optional"CRLF
  "stateOrProvinceName     = optional"CRLF
  "organizationName        = match"CRLF
  "organizationalUnitName  = optional"CRLF
  "commonName              = supplied"CRLF
  "emailAddress            = optional"CRLF
  ""CRLF
  "[ req ]"CRLF
  "prompt                  = no"CRLF
  "default_bits            = 4096"CRLF
  "distinguished_name      = req_distinguished_name"CRLF
  "attributes              = req_attributes"CRLF
  "string_mask             = utf8only"CRLF
  ""CRLF
  "[ req_distinguished_name ]"CRLF
  "0.organizationName      = \"openGalaxy\""CRLF
  "organizationalUnitName  = \"openGalaxy websocket interface\""CRLF
  "commonName              = \"%s\""CRLF              // 5. ca_basename / SERVER_URL / client->name+client->surname
  "emailAddress            = \"%s\""CRLF              // 6. CA_EMAIL_ADDRESS / SERVER_EMAIL_ADDRESS / client->email
  ""CRLF
  "[ req_attributes ]"CRLF
  "unstructuredName        = \"openGalaxy websocket interface\""CRLF
  ""CRLF
  "[ v3_ca ]"CRLF
  "subjectKeyIdentifier    = hash"CRLF
  "authorityKeyIdentifier  = keyid:always,issuer"CRLF
  "basicConstraints        = critical,CA:true, pathlen:0"CRLF
  ""CRLF
  "#The supporte names are: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly and decipherOnly"CRLF
  "keyUsage                = critical, cRLSign, keyCertSign"CRLF
  ""CRLF
  "#The supporte names are: serverAuth, clientAuth, codeSigning, emailProtection, timeStamping"CRLF
  "#extendedKeyUsage        = critical, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping"CRLF
  ""CRLF
  "# PKIX recommendation"CRLF
  "subjectAltName          = email:copy"CRLF
  "issuerAltName           = issuer:copy"CRLF
  ""CRLF
  "[ v3_req_server ]"CRLF
  "subjectKeyIdentifier    = hash"CRLF
  "authorityKeyIdentifier  = keyid:always,issuer"CRLF
  "basicConstraints        = CA:FALSE"CRLF
  "keyUsage                = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment"CRLF
  "extendedKeyUsage        = serverAuth"CRLF
  "subjectAltName          = \"%s\""CRLF              // 7. - / SERVER_ALT / -
  "issuerAltName           = issuer:copy"CRLF
  ""CRLF
  "[ v3_req_client ]"CRLF
  "subjectKeyIdentifier    = hash"CRLF
  "authorityKeyIdentifier  = keyid:always,issuer"CRLF
  "basicConstraints        = CA:FALSE"CRLF
  "keyUsage                = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment"CRLF
  "extendedKeyUsage        = critical, clientAuth"CRLF
  "subjectAltName          = critical, otherName:"OTHERNAME_OID";UTF8:%s"CRLF // 8. - / - / base64 encoded json object
  ""CRLF
  "# This special section contains info for the openGalaxyCA certificate management tool."CRLF
  "# Please do not modify it!"CRLF
  "[ opengalaxy ]"CRLF
//
// TODO: verwijder alle client info, behalve email en voeg 'credentials' to
//
  "name                    = \"%s\""CRLF // 9  for client cert only
  "surname                 = \"%s\""CRLF // 10 for client cert only
  "email                   = \"%s\""CRLF // 11 for client cert only
  "login                   = \"%s\""CRLF // 12 for client cert only
  "password                = \"%s\""CRLF // 13 for client cert only
  "server_url              = \"%s\""CRLF // 14 for server cert only
  "server_alt_url          = \"%s\""CRLF // 15 for server cert only
  "server_alt_ip           = \"%s\""CRLF // 16 for server cert only
  "server_email            = \"%s\""CRLF // 17 for server cert only
  ""CRLF;

// A list of all client certificates
static struct client_t {
  int have_cnf;
  int have_key;
  int have_req;
  int have_pem;
  int have_p12;
  int key_size;
  int days_valid;
  char *name;
  char *surname;
  char *email;
  char *login;
  char *password;
  char *fn_cnf;
  char *fn_key_param;
  char *fn_key;
  char *fn_req;
  char *fn_pem;
  char *fn_p12;
  struct client_t *next;
} *client_list = NULL, *current_client = NULL;


//
// Free all memory used by the variables
//
static void atexit_clean_vars( void )
{
  if( FN_CACNF !=NULL         ){ remove( FN_CACNF ); free( FN_CACNF ); }
  if( FN_SERVERCNF !=NULL     ){ free( FN_SERVERCNF ); }
  if( FN_CLIENTBASECNF !=NULL ){ remove( FN_CLIENTBASECNF ); free( FN_CLIENTBASECNF ); }
  if( FN_CLIENTCNF !=NULL     ){ remove( FN_CLIENTBASECNF ); free( FN_CLIENTCNF ); }

  if( FN_CRL != NULL ) free( FN_CRL );

  if( FN_CAKEY_PARAM != NULL ) free( FN_CAKEY_PARAM );
  if( FN_CAKEY != NULL ) free( FN_CAKEY );
  if( FN_CAPUBKEY != NULL ) free( FN_CAPUBKEY );
  if( FN_CAREQ != NULL ) free( FN_CAREQ );
  if( FN_CAPEM != NULL ) free( FN_CAPEM );
  if( FN_CACRT != NULL ) free( FN_CACRT );
  if( FN_CAPWD != NULL ) free( FN_CAPWD );

  if( FN_SERVERKEY_PARAM != NULL ) free( FN_SERVERKEY_PARAM );
  if( FN_SERVERKEY != NULL ) free( FN_SERVERKEY );
  if( FN_SERVERREQ != NULL ) free( FN_SERVERREQ );
  if( FN_SERVERPEM != NULL ) free( FN_SERVERPEM );

  if( CA_EMAIL_ADDRESS !=NULL )        free( CA_EMAIL_ADDRESS );
  if( SERVER_EMAIL_ADDRESS !=NULL )    free( SERVER_EMAIL_ADDRESS );
  if( SERVER_URL !=NULL )              free( SERVER_URL );
  if( SERVER_ALT_URL !=NULL )          free( SERVER_ALT_URL );
  if( SERVER_ALT_IP !=NULL )           free( SERVER_ALT_IP );
  if( SERVER_ALT !=NULL )              free( SERVER_ALT );
  if( CLIENT_NAME !=NULL )             free( CLIENT_NAME );
  if( CLIENT_MAIL !=NULL )             free( CLIENT_MAIL );
  if( CLIENT_CERT_NAME !=NULL )        free( CLIENT_CERT_NAME );
  if( CERTFILES !=NULL )               free( CERTFILES );

  if( FN_CRED_KEY !=NULL )             free( FN_CRED_KEY );
  if( FN_CRED_PUBKEY !=NULL )          free( FN_CRED_PUBKEY );
  if( FN_TMP_UNENCRYPTED !=NULL )      free( FN_TMP_UNENCRYPTED );
  if( FN_TMP_ENCRYPTED !=NULL )        free( FN_TMP_ENCRYPTED );

  if( OPENSSL_VERSION ) free( OPENSSL_VERSION );
}


#if ! __linux__
//
// Retrieves the data directory path from the Registry key written by the NSIS installer
//
static char* GetRegistry( const char *key )
{
  DWORD dwType = REG_SZ;
  HKEY hKey = 0;
  char value[1024], *out;
  DWORD value_length = sizeof( value );
  const char* subkey = "Software\\openGalaxy";
  value[0] = '\0';
  RegOpenKey( HKEY_CURRENT_USER, subkey, &hKey );
  if( RegQueryValueEx( hKey, key, NULL, &dwType, ( LPBYTE )&value, &value_length ) != ERROR_SUCCESS ){
    return NULL;
  }
  RegCloseKey( hKey );
  if( strlen(value) > 2 ){
    for( int t=0; t<strlen(value); t++ ) if( value[t] == '\\' ) value[t] = '/';
    if( *value == '\"' ){ // remove the quotes
      int t = strlen( value ) - 1;
      if( t > 0 && t < value_length ) value[ t ] = '\0';
      out = strdup( &value[1] );
    }
    else out = strdup( value );
  }
  else out = NULL;

  return out;
}
#endif


//
// Initialize all variables used to manipulate certitificates
//
// char *err   : buffer to write error messages 
// size_t size : size of the buffer
//
// Returns !0 on error
//
static int cert_init_all_vars( char *err, size_t size )
{
  char buf[4096]; // buffer to convert strings

#ifdef _WIN32

  // Retrieve the installation path from the registry
  char *instdir = GetRegistry( str_registry_data_dir );
  char *cert = NULL, *conf = NULL, *share = NULL;
  if( instdir ){
    snprintf( buf, sizeof( buf ), fmt_file_path, instdir, cert_dir );
    cert = strdup( buf );
    snprintf( buf, sizeof( buf ), fmt_file_path, instdir, config_dir );
    conf = strdup( buf );
    snprintf( buf, sizeof( buf ), fmt_file_path, instdir, share_dir );
    share = strdup( buf );
    if( ( ! cert ) || ( ! conf ) || ( ! share ) ){
      snprintf( err, size, fmt_msg_fail_registry_inst_path, buf, strerror( ENOMEM ), ENOMEM );
      return( -1 );
    }
    cert_dir = cert;
    config_dir = conf;
    share_dir = share;
    free( instdir );
  }
  // Or use the current working directory
  else {
    snprintf( buf, sizeof( buf ), fmt_file_current_dir, cert_dir );
    cert = strdup( buf );
    snprintf( buf, sizeof( buf ), fmt_file_current_dir, config_dir );
    conf = strdup( buf );
    snprintf( buf, sizeof( buf ), fmt_file_current_dir, share_dir );
    share = strdup( buf );
    if( ( ! cert ) || ( ! conf ) || ( ! share ) ){
      snprintf( err, size, fmt_msg_fail_registry_cert_dir, buf, strerror( ENOMEM ), ENOMEM );
      return( -1 );
    }
    cert_dir = cert;
    config_dir = conf;
    share_dir = share;
  }
  // Also get the path to the openssl executable from the registry
  char *openssl = GetRegistry( str_registry_opengalaxy_bindir );
  if( ! openssl ){
    snprintf( err, size, "%s", msg_error_registry_read );
    return( -1 );
  }
  // Modify the PATH environment so popen() can find our openssl.exe
  static char envbuf[8192];
  snprintf( envbuf, sizeof( envbuf ), fmt_environment_path, openssl );
  putenv( envbuf );
  free( openssl );

#endif

  if( SERVER_URL == NULL ) SERVER_URL = strdup( str_default_server_ip );
  if( SERVER_ALT_URL == NULL ) SERVER_ALT_URL = strdup( str_default_server_alt_url );
  if( SERVER_ALT_IP == NULL ) SERVER_ALT_IP = strdup( str_default_server_alt_ip );
  if( CA_EMAIL_ADDRESS == NULL ) CA_EMAIL_ADDRESS = strdup( str_default_server_email );
  if( SERVER_EMAIL_ADDRESS == NULL ) SERVER_EMAIL_ADDRESS = strdup( str_default_ca_email );

  // place to store certificates
  if( CERTFILES ) free( CERTFILES );
  CERTFILES = strdup( cert_dir );

  if( CERTFILES ){
    // CA private key parameter file
    if( FN_CAKEY_PARAM ) free( FN_CAKEY_PARAM );
    snprintf( buf, sizeof( buf ), fmt_file_path_key_param, CERTFILES, cakey_basename );
    FN_CAKEY_PARAM = strdup( buf );

    // CA private key file
    if( FN_CAKEY ) free( FN_CAKEY );
    snprintf( buf, sizeof( buf ), fmt_file_path_key, CERTFILES, cakey_basename );
    FN_CAKEY = strdup( buf );

    // CA public key file
    if( FN_CAPUBKEY ) free( FN_CAPUBKEY );
    snprintf( buf, sizeof( buf ), fmt_file_path_key, CERTFILES, capubkey_basename );
    FN_CAPUBKEY = strdup( buf );

    // CA req file
    if( FN_CAREQ ) free( FN_CAREQ );
    snprintf( buf, sizeof( buf ), fmt_file_path_req, CERTFILES, ca_basename );
    FN_CAREQ = strdup( buf );

    // CA pem file
    if( FN_CAPEM ) free( FN_CAPEM );
    snprintf( buf, sizeof( buf ), fmt_file_path_pem, CERTFILES, ca_basename );
    FN_CAPEM = strdup( buf );

    // CA crt file
    if( FN_CACRT ) free( FN_CACRT );
    snprintf( buf, sizeof( buf ), fmt_file_path_crt, CERTFILES, ca_basename );
    FN_CACRT = strdup( buf );

    // CA pwd file
    if( FN_CAPWD ) free( FN_CAPWD );
    snprintf( buf, sizeof( buf ), fmt_file_path, share_dir, str_fn_default_passphrase );
    FN_CAPWD = strdup( buf );

    // CRL file
    if( FN_CRL ) free( FN_CRL );
    snprintf( buf, sizeof( buf ), fmt_file_path_pem, CERTFILES, crl_basename );
    FN_CRL = strdup( buf );

    // Server cnf file
    if( FN_SERVERCNF ) free( FN_SERVERCNF );
    snprintf( buf, sizeof( buf ), fmt_file_path_cnf, CERTFILES, server_basename );
    FN_SERVERCNF = strdup( buf );

    // Server private key parameters file
    if( FN_SERVERKEY_PARAM ) free( FN_SERVERKEY_PARAM );
    snprintf( buf, sizeof( buf ), fmt_file_path_key_param, CERTFILES, serverkey_basename );
    FN_SERVERKEY_PARAM = strdup( buf );

    // Server private key file_PARAM
    if( FN_SERVERKEY ) free( FN_SERVERKEY );
    snprintf( buf, sizeof( buf ), fmt_file_path_key, CERTFILES, serverkey_basename );
    FN_SERVERKEY = strdup( buf );

    // Server req file
    if( FN_SERVERREQ ) free( FN_SERVERREQ );
    snprintf( buf, sizeof( buf ), fmt_file_path_req, CERTFILES, server_basename );
    FN_SERVERREQ = strdup( buf );

    // Server pem file
    if( FN_SERVERPEM ) free( FN_SERVERPEM );
    snprintf( buf, sizeof( buf ), fmt_file_path_pem, CERTFILES, server_basename );
    FN_SERVERPEM = strdup( buf );

    // Credentials private key
    if( FN_CRED_KEY ) free( FN_CRED_KEY );
    snprintf( buf, sizeof( buf ), fmt_file_path_key, CERTFILES, credentials_key_basename );
    FN_CRED_KEY = strdup( buf );

    // Credentials public key
    if( FN_CRED_PUBKEY ) free( FN_CRED_PUBKEY );
    snprintf( buf, sizeof( buf ), fmt_file_path_key, CERTFILES, credentials_pubkey_basename );
    FN_CRED_PUBKEY = strdup( buf );

    // Client unencrypted credentials (temporary file)
    if( FN_TMP_UNENCRYPTED ) free( FN_TMP_UNENCRYPTED );
    snprintf( buf, sizeof( buf ), fmt_file_path_credentials, CERTFILES, client_unencrypt_basename );
    FN_TMP_UNENCRYPTED = strdup( buf );

    // Client encrypted credentials (temporary file)
    if( FN_TMP_ENCRYPTED ) free( FN_TMP_ENCRYPTED );
    snprintf( buf, sizeof( buf ), fmt_file_path_credentials, CERTFILES, client_encrypted_basename );
    FN_TMP_ENCRYPTED = strdup( buf );
  }

  // sanity check
  if(
    ( CA_EMAIL_ADDRESS == NULL ) ||
    ( SERVER_EMAIL_ADDRESS == NULL ) ||
    ( CERTFILES == NULL ) ||
    ( FN_CAKEY_PARAM == NULL ) ||
    ( FN_CAKEY == NULL ) ||
    ( FN_CAPUBKEY == NULL ) ||
    ( FN_CAREQ == NULL ) ||
    ( FN_CAPEM == NULL ) ||
    ( FN_CACRT == NULL ) ||
    ( FN_CAPWD == NULL ) ||
    ( FN_CRL == NULL ) ||
    ( FN_SERVERKEY_PARAM == NULL ) ||
    ( FN_SERVERKEY == NULL ) ||
    ( FN_SERVERREQ == NULL ) ||
    ( FN_SERVERPEM == NULL ) ||
    ( FN_CRED_KEY == NULL ) ||
    ( FN_CRED_PUBKEY == NULL ) ||
    ( FN_TMP_UNENCRYPTED == NULL ) ||
    ( FN_TMP_ENCRYPTED == NULL )
  ){
    int errn = ENOMEM;
#if __linux__
    char err_buf[80];
    snprintf( err, size, fmt_msg_fail_variables, strerror_r( errn, err_buf, sizeof( err_buf ) ), errn );
#else
    snprintf( err, size, fmt_msg_fail_variables, strerror( errn ), errn );
#endif
    return( -1 );
  }

  return( 0 );
}


//
// Write ca.cnf to a temporary file.
// This file is used in openssl ca certificate operations
//
// Returns: !0 on errror
//
static int fd_FN_CACNF = -1;
#if __linux__
static void atexit_close_fd_FN_CACNF( void ){ close( fd_FN_CACNF ); }
#endif
static int cert_write_FN_CACNF( void )
{
  FILE *fp;
  char buf[4096]; // used as filename buffer for mkstemp()
#ifdef __linux__
  snprintf( buf, sizeof( buf ), fmt_file_path_ca_cnf, CERTFILES );
#else
  char *tmp = getenv("TEMP"); // try to get TEMP environment variable
  if( ! tmp ) tmp = "."; // fall back to current directory
  snprintf( buf, sizeof( buf ), fmt_file_path_ca_cnf, tmp );
#endif
  FN_CACNF = malloc( strlen( buf ) + 1 );
  if( FN_CACNF ){
    strcpy( FN_CACNF, buf );
    if( ( fd_FN_CACNF = mkstemp( FN_CACNF ) ) < 0 ){
      free( FN_CACNF );
      FN_CACNF = NULL;
      return -1;
    }
  }
  else {
    errno = ENOMEM;
    return -1;
  }
#if ! __linux__
  // On windows, the use of mkstemp() does not allow us to open the file
  //  for writing using FILE functions while the handle is open.
  close( fd_FN_CACNF );
#endif
  fp = fopen( FN_CACNF, "w+" );
  if( !fp ) return -1;
  if( fprintf( fp, cnf_base, CERTFILES, ca_basename, cakey_basename,
      crl_basename, ca_basename, CA_EMAIL_ADDRESS, str_empty, str_empty, str_empty, str_empty, str_empty, str_empty, str_empty, str_empty, str_empty, str_empty, str_empty ) < 0 ){
    fclose( fp );
    free( FN_CACNF );
    FN_CACNF = NULL;
    return -1;
  }
  fflush( fp );
  fclose( fp );
#if __linux__
  atexit( atexit_close_fd_FN_CACNF );
#endif
  return 0;
}


//
// Write server.cnf to a temporary file
// This file is used in openssl server certificate operations
//
// Returns: !0 on errror
//
static int cert_write_FN_SERVERCNF( void )
{
  int retv = 0;
  FILE *fp = fopen( FN_SERVERCNF, "w+" );
  if( !fp ){
    retv = -1;
    goto error;
  }
  if( fprintf(
   fp,
   cnf_base,
      CERTFILES,              // 1
      ca_basename,            // 2
      cakey_basename,         // 3
      crl_basename,           // 4
      SERVER_URL,             // 5
      SERVER_EMAIL_ADDRESS,   // 6
      SERVER_ALT,             // 7
      str_empty,              // 8
      str_empty,              // 9
      str_empty,              // 10
      str_empty,              // 11
      str_empty,              // 12
      str_empty,              // 13
      SERVER_URL,             // 14
      SERVER_ALT_URL,         // 15
      SERVER_ALT_IP,          // 16
      SERVER_EMAIL_ADDRESS    // 17
  ) < 0 ){
    retv = -1;
  }
  fflush( fp );
  fclose( fp );
error:
  if( is_regular_file( FN_SERVERCNF ) == 0 ){
    have_servercnf = 1;
    set_opengalaxy_gid( FN_SERVERCNF );
    chmod( FN_SERVERCNF, 0660 );
  }
  else {
    have_servercnf = 0;
  }
  return retv;
}

//
// The callack that openssl will call to get the password for the
// CA private key.
//
int pass_cb(char *buf, int size, int rwflag, void *u)
{
#if __linux__
  gchar buf_err[1024];
#endif
  BIO *pwdbio = BIO_new_file(FN_CAPWD, "r");
  int i = BIO_gets(pwdbio, buf, size);
  BIO_free_all(pwdbio);
  if(i <= 0){
#if __linux__
    _gtk_display_error_dialog( (GtkWidget*)u, fmt_msg_fail_passphrase, strerror_r( errno, buf_err, sizeof( buf_err ) ), errno );
#else
    _gtk_display_error_dialog( (GtkWidget*)u, fmt_msg_fail_passphrase, strerror( errno ), errno );
#endif
    return 0;
  }
  if(i > size) i = size;
  char *tmp = strchr(buf, '\n');
  if(tmp){
    *tmp = 0;
    i = strlen(buf);
  }
  //printf("'%s' (%u)\n", buf, i);
  return i;
}

//
// Use the info in 'client' to write a new client cnf file
// This file is used in openssl client certificate operations
// for that client only.
// (this also encrypts the client credentials)
//
// Returns: !0 on errror
//
static int cert_write_FN_CLIENTCNF( struct client_t *client, GtkWidget *parent )
{
  int retv = 0;
  char *buf = NULL, *json = NULL;//, *b64 = NULL;
#if __linux__
  gchar buf_err[1024];
#endif

  buf = g_malloc( strlen( client->name ) + strlen( client->surname ) + 2 );
  if( ! buf ){
    errno = ENOMEM;
    retv = -1;
    goto nofp;
  }
  FILE *fp = fopen( client->fn_cnf, "w+" );
  if( !fp ){
    retv = -1;
    goto nofp;
  }
  sprintf( buf, "%s %s", client->name, client->surname );

  // prepare struct for encryption
  client_credentials c;
  c.fullname = buf;
  c.login = client->login;
  c.password = client->password;

  // get the RSA keys and encrypt the credentials
  // - use the CA key to sign
  // - use the 'cred' public key to encrypt
  EVP_PKEY *sign_key = NULL, *encrypt_key = NULL;
  if(
    !ssl_evp_rsa_load_private_key(FN_CAKEY, &sign_key, pass_cb, (char*)parent) ||
    !ssl_evp_rsa_load_public_key(FN_CRED_PUBKEY, &encrypt_key)
  ){
    errno = EACCES;
#if __linux__
    _gtk_display_error_dialog( parent, fmt_msg_fail_load_pkey, strerror_r( errno, buf_err, sizeof( buf_err ) ), errno );
#else
    _gtk_display_error_dialog( parent, fmt_msg_fail_load_pkey, strerror( errno ), errno );
#endif
    retv = -1;
    goto error;
  }
  json = client_credentials_encrypt(&c, sign_key, encrypt_key);
  if(!json){
    errno = EINVAL;
#if __linux__
    _gtk_display_error_dialog( parent, fmt_msg_fail_encrypt, strerror_r( errno, buf_err, sizeof( buf_err ) ), errno );
#else
    _gtk_display_error_dialog( parent, fmt_msg_fail_encrypt, strerror( errno ), errno );
#endif
    retv = -1;
    goto error;
  }

  // Write the CNF file
  if( fprintf(
   fp,
   cnf_base,
   CERTFILES,         // 1
   ca_basename,       // 2
   cakey_basename,    // 3
   crl_basename,      // 4
   buf,               // 5
   client->email,     // 6
   str_empty,         // 7
   json,              // 8
   client->name,      // 9
   client->surname,   // 10
   client->email,     // 11
   client->login,     // 12
   client->password,  // 13
   str_empty,         // 14
   str_empty,         // 15
   str_empty,         // 16
   str_empty          // 17
  ) < 0 ){
    retv = -1;
  }

  fflush( fp );
error:
  fclose( fp );
nofp:
  g_free( buf );
  ssl_pkey_free(sign_key);
  ssl_pkey_free(encrypt_key);
  ssl_free( json );
  if(is_regular_file( client->fn_cnf )){
    client->have_cnf = 0;
  }
  else {
    client->have_cnf = 1;
    set_opengalaxy_gid( client->fn_cnf );
    chmod( client->fn_cnf, 0660 );
  }
  return retv;
}


//
// Makes sure that we can can read/write to _CERT_DIR_
//  creating it if needed
//
// Needs: cert_init_all_vars()
//
// Returns: !0 on errror
//
static int cert_check_certificate_directory( void )
{
  struct stat st;
  int retv = 0;

  // if the certificate dir could not be created:
  if( mkpath( CERTFILES, 0775 ) != 0 ){
    // Could not create the directory
    retv = -1;
  }
  else {
    // Does the directory exist?
    if( stat( CERTFILES, &st ) != 0 ){
      // No.
      retv = -1;
    }
    else {
      // get the id of the current user/group
#if __linux__
      uid_t uid = getuid();
      gid_t gid = getgid();
#endif
      int have_r = 0, have_w = 0, have_x = 0;
      // Can we read from dir
      if(
#if __linux__
        ( uid == st.st_uid ) &&
#endif
        ( st.st_mode & S_IRUSR )
      ) have_r = 1;
      else if(
#if __linux__
        ( gid == st.st_gid ) &&
#endif
        ( st.st_mode & S_IRGRP )
      ) have_r = 1;
      else if( st.st_mode & S_IROTH ) have_r = 1;
      // Can we write to dir
      if(
#if __linux__
        ( uid == st.st_uid ) &&
#endif
        ( st.st_mode & S_IWUSR )
      ) have_w = 1;
      else if(
#if __linux__
        ( gid == st.st_gid ) &&
#endif
        ( st.st_mode & S_IWGRP )
      ) have_w = 1;
      else if( st.st_mode & S_IWOTH ) have_w = 1;
      // Can we execute dir
      if(
#if __linux__
        ( uid == st.st_uid ) &&
#endif
        ( st.st_mode & S_IXUSR )
      ) have_x = 1;
      else if(
#if __linux__
        ( gid == st.st_gid ) &&
#endif
        ( st.st_mode & S_IXGRP )
      ) have_x = 1;
      else if( st.st_mode & S_IXOTH ) have_x = 1;
      if( !have_r || !have_w || !have_x ) {
        errno = EACCES;
        retv = -1;
      }
    }
  }
  return( retv );
}


//
// Makes sure that the used certificate directory tree is there
//  by checking for and creating any missing directories and some files,
//  while also checking witch certificate files are present.
//
// Needs: cert_init_all_vars() cert_check_certificate_directory()
//
// Returns: !0 on errror
//
//
static int cert_check_certificate_subtree( void )
{
  int retv = 0;
  FILE *fp;
  char buf[4096];

  // (re)create the paths
  snprintf( buf, sizeof( buf ), fmt_file_path, CERTFILES, "newcerts" );
  if( mkpath ( buf, 0775 ) != 0 ) retv = -1;

  snprintf( buf, sizeof( buf ), fmt_file_path, CERTFILES, "private/users" );
  if( mkpath ( buf, 0775 ) != 0 ) retv = -1;

  snprintf( buf, sizeof( buf ), fmt_file_path, CERTFILES, "certs/users" );
  if( mkpath ( buf, 0775 ) != 0 ) retv = -1;

  snprintf( buf, sizeof( buf ), fmt_file_path, CERTFILES, "req/users" );
  if( mkpath ( buf, 0775 ) != 0 ) retv = -1;

  // Check serial file
  srand( time( NULL ) ); // Seed the random number generator
  snprintf( buf, sizeof( buf ), fmt_file_path, CERTFILES, "serial" );
  if( is_regular_file( buf ) ){
    // seed serial with a  pseudo random number between 1000000000 and 9999999999
    if( ( fp = fopen( buf, "w" ) ) ){
      if( fprintf( fp, "%llu"CRLF, rand() % 8999999999ull + 1000000000ull ) < 0 ) retv = -1;
      fflush( fp );
      fclose( fp );
      set_opengalaxy_gid( buf );
      chmod( buf, 0660 );
    }
    else retv = -1;
  }

  // Check crlnumber file
  snprintf( buf, sizeof( buf ), fmt_file_path, CERTFILES, "crlnumber" );
  if( is_regular_file( buf ) ){
    // Reset CRL number
    if( ( fp = fopen( buf, "w" ) ) ){
      if( fprintf( fp, "%s"CRLF, "01" ) < 0 ) retv = -1;
      fflush( fp );
      fclose( fp );
      set_opengalaxy_gid( buf );
      chmod( buf, 0660 );
    }
    else retv = -1;
  }

  // Check index file
  snprintf( buf, sizeof( buf ), fmt_file_path, CERTFILES, "index.txt" );
  if( is_regular_file( buf ) ){
    // Create empty index.txt
    if( ( fp = fopen( buf, "w" ) ) ){
      fflush( fp );
      fclose( fp );
      set_opengalaxy_gid( buf );
      chmod( buf, 0660 );
    }
    else retv = -1;
  }

  // Test for ca and credentials key files
  if(
    is_regular_file( FN_CAKEY ) ||
    is_regular_file( FN_CAPUBKEY ) ||
    is_regular_file( FN_CRED_KEY ) ||
    is_regular_file( FN_CRED_PUBKEY )
  ) have_cakey = 0;
  else have_cakey = 1;

  // Test for ca certificate request file
  if( is_regular_file( FN_CAREQ ) ) have_careq = 0;
  else have_careq = 1;

  // Test for ca certificate file
  if( is_regular_file( FN_CAPEM ) ) have_capem = 0;
  else have_capem = 1;

  // Test for ca certificate DER file
  if( is_regular_file( FN_CACRT ) ) have_cacrt = 0;
  else have_cacrt = 1;

  // Test for certificate revocation list file
  if( is_regular_file( FN_CRL ) ) have_crl = 0;
  else have_crl = 1;

  // Test for server private key file
  if( is_regular_file( FN_SERVERKEY ) ) have_serverkey = 0;
  else have_serverkey = 1;

  // Test for server certificate request file
  if( is_regular_file( FN_SERVERREQ ) ) have_serverreq = 0;
  else have_serverreq = 1;

  // Test for server certificate file
  if( is_regular_file( FN_SERVERPEM ) ) have_serverpem = 0;
  else have_serverpem = 1;

  return retv;
}


//
// Retrieve parameters from the existing keys/requests/certs for the current client's certificates
// Used to be able to display the parameters of the currently existing certificate files
//
// Returns: !0 on errror
//
static int cert_check_client_certificate_parameters( struct client_t *client )
{
  GtkTextIter start, end;
  char cmd[CMD_MAX_LEN];
  int retv = 0, l;
  char *saveptr, *p;
  time_t tStart = 0;
  time_t tEnd = 0;

  // textbuffer to store command output
  GtkTextBuffer *buf = NULL;
  if( ! ( buf = gtk_text_buffer_new( NULL ) ) ){
    _gtk_display_error_dialog( window, msg_error, msg_outofmem );
    retv = -1;
    goto error;
  }

  // If it exists, extract current_client->key_size from this clients private key
  //
  if( ! is_regular_file( client->fn_key ) ){
    client->have_key = 1;
    // Create a command to print the private key and execute it
    snprintf( cmd, sizeof( cmd ), cmd_print_clkey,
      fmt_openssl_dir, fmt_openssl_exe,
#if CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
      client->fn_key_param
#else
      client->fn_key
#endif
    );
    if( ( retv = _gtk_popen( cmd, buf ) ) != 0 ){
#if CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
      goto error;
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
      // openssl returns nonzero even if the command was successfull!?
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
      goto error;
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
      goto error;
#endif
    }
    // Get the output from the textbuffer
#if CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
    gtk_text_buffer_get_iter_at_line( buf, &start, 0 ); // We only need the first line
    gtk_text_buffer_get_iter_at_line( buf, &end, 1 );
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#endif
    gchar *out = gtk_text_buffer_get_text( buf, &start, &end, FALSE ); // out = "Private-Key: (xxxx bit)"
    // Convert the string into a value
    strtok_r( out, token_delim_5, &saveptr );
    char *t = strtok_r( NULL, token_delim_5, &saveptr ); // t = "xxxx bit"
    if( t ) client->key_size = strtol( t, NULL, 10 );
    free( out );
  }
  else {
    // Set a default key size if the file could no be read
    client->key_size = CLIENT_KEY_SIZE;
    client->have_key = 1;
  }

  if( buf ) g_object_unref( buf );
  if( ! ( buf = gtk_text_buffer_new( NULL ) ) ){
    _gtk_display_error_dialog( window, msg_error, msg_outofmem );
    retv = -1;
    goto error;
  }

  // If it exists, extract current_client->days_valid from this clients certificate
  //
  if( ! is_regular_file( client->fn_pem ) ){
    client->have_pem = 1;
    // Create a command to print the ca private key and execute it
    snprintf( cmd, sizeof( cmd ), cmd_print_cert,
      fmt_openssl_dir, fmt_openssl_exe, client->fn_pem );
    if( ( retv = _gtk_popen( cmd, buf ) ) != 0 ) goto error;
    // Get the output from the textbuffer
    gtk_text_buffer_get_start_iter( buf, &start );
    gtk_text_buffer_get_end_iter( buf, &end );
    gchar *out = gtk_text_buffer_get_text( buf, &start, &end, FALSE );
    // Get 'Not Before' date
    if( ( p = strstr( out, str_not_before ) ) ){
      p += 12; // p now points to: "not before date\n...."
      l = 0; // l = length of string
      while( p[l] != '\0' && p[l] != '\n' ) l++; // scan for end of line
      if( l ){
        char b[l];
        strncpy( b, p, l );
        b[l] = '\0'; // b = "not before date\0" example "Feb 23 23:58:00 2015 GMT\0"
        if( ( tStart = date2epoch( b ) ) == -1 ){
          _gtk_display_error_dialog( window, msg_error, msg_daterange );
          retv = -1;
          goto error;
        }
      }
    }
    // Get 'Not After' date
    if( ( p = strstr( out, str_not_after ) ) ){
      p += 12; // p now points to: "not after date\n...."
      l = 0; // l = length of string
      while( p[l] != '\0' && p[l] != '\n' ) l++; // scan for end of line
      if( l ){
        char b[l];
        strncpy( b, p, l );
        b[l] = '\0'; // b = "not after date\0"
        if( ( tEnd = date2epoch( b ) ) == -1 ){
          _gtk_display_error_dialog( window, msg_error, msg_daterange );
          retv = -1;
          goto error;
        }
      }
    }
    // seconds between dates / seconds per day = number of days
    client->days_valid = ( (double)difftime( tEnd, tStart ) ) / 86400.0;
    free( out );
  }
  else {
    client->have_pem = 0;
    client->days_valid = CLIENT_DAYS_VALID;
  }

error:
  if( buf ) g_object_unref( buf );
  return retv;
}


//
// Retrieve parameters from the server.cnf
//
// Returns: !0 on errror
//
static int parse_server_cnf( void )
{
  int retv = 0;
  FILE *fp;
  char line_buf[CMD_MAX_LEN];
  char *token, *p;
  char *saveptr;
  char *url = NULL, *alt_url = NULL, *alt_ip = NULL, *email = NULL;

  if( is_regular_file( FN_SERVERCNF ) != 0 ){
    retv = 0;
    goto error;
  }

  // Open the server cnf file
  if( ( fp = fopen( FN_SERVERCNF, "rt" ) ) == NULL ) {
    retv = -1;
    goto error;
  }
  // Parse the file line by line
  while( fgets( line_buf, sizeof( line_buf ), fp ) ){
    // p points to the current line
    p = line_buf;
    // skip leading spaces and tabs
    while( *p == ' ' || *p == '\t' ) p++;
    // read a token
    if( ( token = strtok_r( p, token_delim_3, &saveptr ) ) ){
      // Search for a '[ opengalaxy ]' section
      if( token && token[0]=='[' ){
        // Found a section, put its name in token
        token = strtok_r( NULL, token_delim_4, &saveptr ); 
        // Is it the section we are interested in?
        if( strcmp( token, token_opengalaxy ) == 0 ){
          // yes, read client parameters from it
          while( fgets( line_buf, sizeof( line_buf ), fp ) ){
            // p points to the current line
            p = line_buf;
            // skip leading spaces and tabs
            while( *p == ' ' || *p == '\t' ) p++;
            // read a token
            if( ( token = strtok_r( p, token_delim_1, &saveptr ) ) ){
              //
              // Anything we're looking for?
              //
              if( strcmp( token, token_server_url ) == 0 ){
                // yes, url
                if( ( token = strtok_r( NULL, token_delim_2, &saveptr ) ) ){ 
                  url = strdup( token );
                }
              }
              else if( strcmp( token, token_server_alt_url ) == 0 ){
                // yes, alt_url
                // skip over = sign
                if( ( token = strtok_r( NULL, token_delim_2_2, &saveptr ) ) ){
                  strtrim( saveptr );
                  if( ( token = strtok_r( NULL, token_delim_2_1, &saveptr ) ) ){ 
                    alt_url = strdup( token );
                  }
                }
              }
              else if( strcmp( token, token_server_alt_ip ) == 0 ){
                // yes, alt_ip
                // skip over = sign
                if( ( token = strtok_r( NULL, token_delim_2_2, &saveptr ) ) ){
                  strtrim( saveptr );
                  if( ( token = strtok_r( NULL, token_delim_2_1, &saveptr ) ) ){ 
                    alt_ip = strdup( token );
                  }
                }
              }
              else if( strcmp( token, token_server_email ) == 0 ){
                // yes, email
                if( ( token = strtok_r( NULL, token_delim_2, &saveptr ) ) ){ 
                  email = strdup( token );
                }
              }
              //
              // Ends value search
              //
            }
          }

          if( url ){
            SERVER_URL = url;
          }
          if( alt_url ){
            SERVER_ALT_URL = alt_url;
          }
          if( alt_ip ){
            SERVER_ALT_IP = alt_ip;
          }
          if( email ){
            SERVER_EMAIL_ADDRESS = email;
          }

        }
      }
    }
  }
  fclose( fp );

  return retv;

error:
  if( url ) free( url );
  if( alt_url ) free( alt_url );
  if( alt_ip ) free( alt_ip );
  return retv;
}


//
// Retrieve parameters from the existing keys/requests/certs for the CA an Server certificates
// Also retrieve parameters from the server.cnf if it exists
//
// Returns: !0 on errror
//
static int cert_check_certificate_parameters( void )
{
  GtkTextIter start, end;
  char cmd[CMD_MAX_LEN];
  int retv = 0, l;
  char *saveptr, *p;
  time_t tStart = 0;
  time_t tEnd = 0;

  // textbuffer to store command output
  GtkTextBuffer *buf = NULL;
  if( ! ( buf = gtk_text_buffer_new( NULL ) ) ){
    errno = ENOMEM;
    retv = -1;
    goto error;
  }

  // If it exists, extract CA_KEY_SIZE from the CA private key
  //
  if( ! is_regular_file( FN_CAKEY ) ){
    // Create a command to print the ca private key and execute it
    snprintf( cmd, sizeof( cmd ), cmd_print_cakey,
      fmt_openssl_dir, fmt_openssl_exe,
#if CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
      FN_CAKEY_PARAM,
#else
      FN_CAKEY,
#endif
      FN_CAPWD );

    if( ( retv = _gtk_popen( cmd, buf ) ) != 0 ){
#if CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
      goto error;
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
      // openssl returns nonzero even if the command was successfull!?
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
      goto error;
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
      goto error;
#endif
    }
    // Get the output from the textbuffer
#if CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
    gtk_text_buffer_get_iter_at_line( buf, &start, 0 ); // We only need the first line
    gtk_text_buffer_get_iter_at_line( buf, &end, 1 );
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#endif
    gchar *out = gtk_text_buffer_get_text( buf, &start, &end, FALSE ); // out = "Private-Key: (xxxx bit)"
    // Convert the string into a value
    strtok_r( out, token_delim_5, &saveptr );
    char *t = strtok_r( NULL, token_delim_5, &saveptr ); // t = "xxxx bit"
    if( t ) CA_KEY_SIZE = strtol( t, NULL, 10 );
    free( out );
  }

  if( buf ) g_object_unref( buf );
  if( ! ( buf = gtk_text_buffer_new( NULL ) ) ){
    errno = ENOMEM;
    retv = -1;
    goto error;
  }

  // If it exists, extract SERVER_KEY_SIZE from the server private key
  //
  if( ! is_regular_file( FN_SERVERKEY ) ){
    // Create a command to print the server private key and execute it
    snprintf( cmd, sizeof( cmd ), cmd_print_srvkey,
      fmt_openssl_dir, fmt_openssl_exe,
#if SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
      FN_SERVERKEY_PARAM
#else
      FN_SERVERKEY
#endif
    );
    if( ( retv = _gtk_popen( cmd, buf ) ) != 0 ){
#if SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
      goto error;
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
      // openssl returns nonzero even if the command was successfull!?
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
      goto error;
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
      goto error;
#endif
    }
    // Get the output from the textbuffer
#if SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
    gtk_text_buffer_get_iter_at_line( buf, &start, 0 ); // We only need the first line
    gtk_text_buffer_get_iter_at_line( buf, &end, 1 );
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
    gtk_text_buffer_get_iter_at_line( buf, &start, 1 ); // We only need the second line
    gtk_text_buffer_get_iter_at_line( buf, &end, 2 );
#endif
    gchar *out = gtk_text_buffer_get_text( buf, &start, &end, FALSE ); // out = "Private-Key: (xxxx bit)"
    // Convert the string into a value
    strtok_r( out, token_delim_5, &saveptr );
    char *t = strtok_r( NULL, token_delim_5, &saveptr ); // t = "xxxx bit"
    if( t ) SERVER_KEY_SIZE = strtol( t, NULL, 10 );
    free( out );
  }

  if( buf ) g_object_unref( buf );
  if( ! ( buf = gtk_text_buffer_new( NULL ) ) ){
    errno = ENOMEM;
    retv = -1;
    goto error;
  }

  // If it exists, extract CA_DAYS_VALID from the CA certificate
  //
  if( ! is_regular_file( FN_CAPEM ) ){
    // Create a command to print the ca certificate and execute it
    snprintf( cmd, sizeof( cmd ), cmd_print_cert,
      fmt_openssl_dir, fmt_openssl_exe, FN_CAPEM );
    if( ( retv = _gtk_popen( cmd, buf ) ) != 0 ) goto error;
    // Get the output from the textbuffer
    gtk_text_buffer_get_start_iter( buf, &start );
    gtk_text_buffer_get_end_iter( buf, &end );
    gchar *out = gtk_text_buffer_get_text( buf, &start, &end, FALSE );
    // Get 'Not Before' date
    if( ( p = strstr( out, str_not_before ) ) ){
      p += 12; // p now points to: "not before date\n...."
      l = 0; // l = length of string
      while( p[l] != '\0' && p[l] != '\n' ) l++; // scan for end of line
      if( l ){
        char b[l];
        strncpy( b, p, l );
        b[l] = '\0'; // b = "not before date\0" example "Feb 23 23:58:00 2015 GMT\0"
        if( ( tStart = date2epoch( b ) ) == -1 ){
          errno = ERANGE;
          retv = -1;
          goto error;
        }

      }
    }
    // Get 'Not After' date
    if( ( p = strstr( out, str_not_after ) ) ){
      p += 12; // p now points to: "not after date\n...."
      l = 0; // l = length of string
      while( p[l] != '\0' && p[l] != '\n' ) l++; // scan for end of line
      if( l ){
        char b[l];
        strncpy( b, p, l );
        b[l] = '\0'; // b = "not after date\0"
        if( ( tEnd = date2epoch( b ) ) == -1 ){
          errno = ERANGE;
          retv = -1;
          goto error;
        }
      }
    }
    // seconds between dates / seconds per day = number of days
    CA_DAYS_VALID = ( (double)difftime( tEnd, tStart ) ) / 86400.0;
    free( out );
  }

  if( buf ) g_object_unref( buf );
  if( ! ( buf = gtk_text_buffer_new( NULL ) ) ){
    errno = ENOMEM;
    retv = -1;
    goto error;
  }

  // If it exists, extract SERVER_DAYS_VALID from the Server certificate
  //
  if( ! is_regular_file( FN_SERVERPEM ) ){
    // Create a command to print the ca cert and execute it
    snprintf( cmd, sizeof( cmd ), cmd_print_cert,
      fmt_openssl_dir, fmt_openssl_exe, FN_SERVERPEM );
    if( ( retv = _gtk_popen( cmd, buf ) ) != 0 ) goto error;
    // Get the output from the textbuffer
    gtk_text_buffer_get_start_iter( buf, &start );
    gtk_text_buffer_get_end_iter( buf, &end );
    gchar *out = gtk_text_buffer_get_text( buf, &start, &end, FALSE );
    // Get 'Not Before' date
    if( ( p = strstr( out, str_not_before ) ) ){
      p += 12; // p now points to: "not before date\n...."
      l = 0; // l = length of string
      while( p[l] != '\0' && p[l] != '\n' ) l++; // scan for end of line
      if( l ){
        char b[l];
        strncpy( b, p, l );
        b[l] = '\0'; // b = "not before date\0" example "Feb 23 23:58:00 2015 GMT\0"
        if( ( tStart = date2epoch( b ) ) == -1 ){
          errno = ERANGE;
          retv = -1;
          goto error;
        }
      }
    }
    // Get 'Not After' date
    if( ( p = strstr( out, str_not_after ) ) ){
      p += 12; // p now points to: "not after date\n...."
      l = 0; // l = length of string
      while( p[l] != '\0' && p[l] != '\n' ) l++; // scan for end of line
      if( l ){
        char b[l];
        strncpy( b, p, l );
        b[l] = '\0'; // b = "not after date\0"
        if( ( tEnd = date2epoch( b ) ) == -1 ){
          errno = ERANGE;
          retv = -1;
          goto error;
        }
      }
    }
    // seconds between dates / seconds per day = number of days
    SERVER_DAYS_VALID = ( (double)difftime( tEnd, tStart ) ) / 86400.0;
    free( out );
  }

  retv = parse_server_cnf();

error:
  if( buf ) g_object_unref( buf );
  return retv;
}


//
// Free a client_t *
//
static void free_client_t( struct client_t *client )
{
  if( client ){
    if( client->name ) free( client->name );
    if( client->surname ) free( client->surname );
    if( client->email ) free( client->email );
    if( client->login ) free( client->login );
    if( client->password ) free( client->password );
    if( client->fn_cnf ) free( client->fn_cnf );
    if( client->fn_key_param ) free( client->fn_key_param );
    if( client->fn_key ) free( client->fn_key );
    if( client->fn_req ) free( client->fn_req );
    if( client->fn_pem ) free( client->fn_pem );
    if( client->fn_p12 ) free( client->fn_p12 );
    free( client );
  }
}


//
// List all the certificates in the client certificates directory
// Certificates are detected by the presense of a .cnf file
// Used to fill the list of clients at program startup
//
// return !0 on error
//
// TODO: add privileges, remove cleartext password from cnf
static int cert_get_client_list( void )
{
  int retv = 0;
  struct dirent *ep;
  char dirname[4096];
  FILE *fp;
  char line_buf[CMD_MAX_LEN];
  char *tmp = line_buf;
  char *token, *p;
  char *saveptr;
  char *name = NULL, *surname = NULL, *email = NULL, *login = NULL, *password = NULL;
  struct client_t *client = NULL;

  // Open the client certs directory
  snprintf( dirname, sizeof( dirname ), fmt_file_path_clients, cert_dir );
  DIR *dp = opendir( dirname );
  if( dp != NULL ){
    // List all files in the directory
    while( ( ep = readdir (dp) ) != NULL ){
      //is it a .cnf file?
      if( strstr( ep->d_name, ".cnf" ) || strstr( ep->d_name, ".CNF" ) ){
        // reset before each file
        name = surname = email = login = NULL;
        client = NULL;
        // Get the path to, and open the file
        snprintf( line_buf, sizeof( line_buf ), "%s/%s", dirname, ep->d_name );
        if( ( fp = fopen( line_buf, "rt" ) ) == NULL ) {
          _gtk_display_error_dialog( window, msg_error, msg_fail_cert_read );
          retv = -1;
          goto error;
        }
        // Parse the file line by line
        while( fgets( line_buf, sizeof( line_buf ), fp ) ){
          // p points to the current line
          p = line_buf;
          // skip leading spaces and tabs
          while( *p == ' ' || *p == '\t' ) p++;
          // read a token
          if( ( token = strtok_r( p, token_delim_3, &saveptr ) ) ){
            // Search for a '[ opengalaxy ]' section
            if( token && token[0]=='[' ){
              // Found a section, put its name in token
              token = strtok_r( NULL, token_delim_4, &saveptr ); 
              // Is it the section we are interested in?
              if( strcmp( token, token_opengalaxy ) == 0 ){
                // yes, read client parameters from it
                while( fgets( line_buf, sizeof( line_buf ), fp ) ){
                  // p points to the current line
                  p = line_buf;
                  // skip leading spaces and tabs
                  while( *p == ' ' || *p == '\t' ) p++;
                  // read a token
                  if( ( token = strtok_r( p, token_delim_1, &saveptr ) ) ){
                    //
                    // Anything we're looking for?
                    //
                    if( strcmp( token, token_client_name ) == 0 ){
                      // yes, name
                      // skip over = sign
                      if( ( token = strtok_r( NULL, token_delim_2_2, &saveptr ) ) ){
                        strtrim( saveptr );
                        if( ( token = strtok_r( NULL, token_delim_2_1, &saveptr ) ) ){ 
                          name = strdup( token );
                        }
                      }
                    }
                    else if( strcmp( token, token_client_surname ) == 0 ){
                      // yes, surname
                      // skip over = sign
                      if( ( token = strtok_r( NULL, token_delim_2_2, &saveptr ) ) ){
                        strtrim( saveptr );
                        if( ( token = strtok_r( NULL, token_delim_2_1, &saveptr ) ) ){ 
                          surname = strdup( token );
                        }
                      }
                    }
                    else if( strcmp( token, token_client_email ) == 0 ){
                      // yes, email
                      // skip over = sign
                      if( ( token = strtok_r( NULL, token_delim_2_2, &saveptr ) ) ){
                        strtrim( saveptr );
                        if( ( token = strtok_r( NULL, token_delim_2_1, &saveptr ) ) ){ 
                          email = strdup( token );
                        }
                      }
                    }
                    else if( strcmp( token, token_client_login ) == 0 ){
                      // yes, login
                      // skip over = sign
                      if( ( token = strtok_r( NULL, token_delim_2_2, &saveptr ) ) ){
                        strtrim( saveptr );
                        if( ( token = strtok_r( NULL, token_delim_2_1, &saveptr ) ) ){ 
                          login = strdup( token );
                        }
                      }
                    }
                    else if( strcmp( token, token_client_password ) == 0 ){
                      // yes, password
                      // skip over = sign
                      if( ( token = strtok_r( NULL, token_delim_2_2, &saveptr ) ) ){
                        strtrim( saveptr );
                        if( ( token = strtok_r( NULL, token_delim_2_1, &saveptr ) ) ){ 
                          password = strdup( token );
                        }
                      }
                    }
                    //
                    // Ends value search
                    //
                  }
                }

                // Add a new client to the client_list of struct client_t
                if( ( client = malloc( sizeof( struct client_t ) ) ) != NULL ){
                  memset( client, 0, sizeof( struct client_t ) );
                  //
                  // Add the parameters to the new client_t
                  // and append it to client_list
                  //
                  client->name = name;
                  client->surname = surname;
                  client->email = email;
                  client->login = login;
                  client->password = password;

                  // Create the base filename for this certificate
                  char fn_client_basename[4096];
                  snprintf( fn_client_basename, sizeof( fn_client_basename ), "%s-%s-%s", client->name, client->surname, client->login );
                  while( ( p = strchr( fn_client_basename, ' ' ) ) != NULL ){
                    *p = '_'; // replace spaces with underscores
                  }
                  for( p = fn_client_basename; *p != '\0'; p++ ){
                    *p = tolower( *p ); // convert to lower case
                  }

                  // Create a suitable filename for the cnf file for this client
                  snprintf( tmp, CMD_MAX_LEN, fmt_file_path, dirname, ep->d_name );
                  client->fn_cnf = strdup( tmp );
                  client->have_cnf = 1;

                  // Create a suitable filename for the private key file for this client
                  snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_key_param, cert_dir, fn_client_basename );
                  client->fn_key_param = strdup( tmp );

                  // Create a suitable filename for the private key file for this client
                  snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_key, cert_dir, fn_client_basename );
                  client->fn_key = strdup( tmp );

                  // Create a suitable filename for the certificate request file for this client
                  snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_req, cert_dir, fn_client_basename );
                  client->fn_req = strdup( tmp );

                  // Create a suitable filename for the certificate file for this client
                  snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_pem, cert_dir, fn_client_basename );
                  client->fn_pem = strdup( tmp );

                  // Create a suitable filename for the certificate file for this client
                  snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_p12, cert_dir, fn_client_basename );
                  client->fn_p12 = strdup( tmp );

                  //
                  // Replace any empty values with an empty string,
                  // and inform the user of the missing value.
                  //
                  if ( ! client->name ){
                    client->name = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Name" );
                  }
                  if ( ! client->surname ){
                    client->surname = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Surname" );
                  }
                  if ( ! client->email ){
                    client->email = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Email Address" );
                  }
                  if ( ! client->login ){
                    client->login = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Username" );
                  }
                  if ( ! client->password ){
                    client->password = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Password" );
                  }
                  if ( ! client->fn_cnf ){
                    client->fn_cnf = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, ".CNF filename" );
                  }
                  if ( ! client->fn_key_param ){
                    client->fn_key_param = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Private Key Parameters " );
                  }
                  if ( ! client->fn_key ){
                    client->fn_key = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Private Key filename" );
                  }
                  if ( ! client->fn_req ){
                    client->fn_req = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client Certificate Request filename" );
                  }
                  if ( ! client->fn_pem ){
                    client->fn_pem = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client .PEM filename" );
                  }
                  if ( ! client->fn_p12 ){
                    client->fn_p12 = strdup("");
                    _gtk_display_error_dialog( window, msg_error, fmt_fail_cnf_missing_value, ep->d_name, "Client .P12 filename" );
                  }

                  //
                  // test which certificate files are present
                  //
                  if( is_regular_file( client->fn_key ) == 0 ) client->have_key = 1;
                  else client->have_key = 0;
                  if( is_regular_file( client->fn_req ) == 0 ) client->have_req = 1;
                  else client->have_req = 0;
                  if( is_regular_file( client->fn_pem ) == 0 ) client->have_pem = 1;
                  else client->have_pem = 0;
                  if( is_regular_file( client->fn_p12 ) == 0 ) client->have_p12 = 1;
                  else client->have_p12 = 0;

                  // Scan private key for key_size
                  // Scan certificate for days_valid
                  cert_check_client_certificate_parameters( client );

                  // Add the completed client to the client list
                  client->next = client_list;
                  client_list = client;
                }
                else {
                  _gtk_display_error_dialog( window, msg_error, msg_outofmem );
                }

                //
                // Reset now stored allocated values in case of an error later on
                //
                name = surname = email = login = password = NULL;
                client = NULL;
                // Stop any further parsing of the current file
                break;
                // Ends '[ opengalaxy ]' section
              }
            }
          }
        }
        fclose( fp );
      }
    }
    closedir (dp);
  }
  else {
    _gtk_display_error_dialog( window, msg_error, msg_fail_cert_dir_open );
    retv = -1;
    goto error;
  }

  return retv;

error:

  if( name ) free( name );
  if( surname ) free( surname );
  if( email ) free( email );
  if( login ) free( login );
  if( password ) free( password );
  if( client ) free( client );
  return retv;
}


//
// Call to update the clickable state of the widgets on the CA tab of the notebook
// This ensures that the user may only perform tasks that are valid at the current state
//
static void widget_ca_is_sensitive( void )
{
  int key = FALSE, req = FALSE, sign = FALSE, revoke = FALSE;

  if( have_cakey ){
    key = FALSE;
    req = TRUE;
  }
  else {
    key = TRUE;
    req = FALSE;
    sign = FALSE;
    revoke = FALSE;
  }

  if( have_careq ){
    sign = TRUE;
  }

  if( have_capem ){
    req = FALSE;
    sign = FALSE;
    revoke = TRUE;
  }
  else {
    key = TRUE;
  }

  gtk_widget_set_sensitive( button_cakey, key );
  gtk_widget_set_sensitive( box_cakeysize, key );
  gtk_widget_set_sensitive( comboboxtext_cakeysize, key );
  gtk_widget_set_sensitive( button_careq, req );
  gtk_widget_set_sensitive( button_casign, sign );
  gtk_widget_set_sensitive( box_cadays, sign );
  gtk_widget_set_sensitive( spinbutton_cadays, sign );
  gtk_widget_set_sensitive( button_carevoke, revoke );
}


//
// Call to update the clickable state of the widgets on the Server tab of the notebook
// This ensures that the user may only perform tasks that are valid at the current state
//
static void widget_server_is_sensitive( void )
{
  int key = FALSE, req = FALSE, sign = FALSE, revoke = FALSE, params = FALSE;

  if( have_capem ){

    if( have_serverkey ){
      key = FALSE;
      req = TRUE;
    }
    else {
      key = TRUE;
      req = FALSE;
      sign = FALSE;
      revoke = FALSE;
    }

    if( have_serverreq ){
      sign = TRUE;
    }

    if( have_serverpem ){
      req = FALSE;
      sign = FALSE;
      revoke = TRUE;
    }
    else {
      key = TRUE;
    }

  }

  if( have_serverreq == FALSE ){
    params = TRUE;
  }

  gtk_widget_set_sensitive( button_serverkey, key );
  gtk_widget_set_sensitive( box_serverkeysize, key );
  gtk_widget_set_sensitive( comboboxtext_serverkeysize, key );
  gtk_widget_set_sensitive( button_serverreq, req );
  gtk_widget_set_sensitive( button_serversign, sign );
  gtk_widget_set_sensitive( box_serverdays, sign );
  gtk_widget_set_sensitive( spinbutton_serverdays, sign );
  gtk_widget_set_sensitive( button_serverrevoke, revoke );
  gtk_widget_set_sensitive( frame_servercommonname, params );
  gtk_widget_set_sensitive( frame_serveraltname, params );
  gtk_widget_set_sensitive( frame_serveremail, params );
}


//
// Call to update the clickable state of the widgets on the Clients tab of the notebook
// This ensures that the user may only perform tasks that are valid at the current state
//
static void widget_client_is_sensitive( void )
{
  int key = FALSE, req = FALSE, sign = FALSE, revoke = FALSE;
  int list = FALSE, name = FALSE, surname = FALSE, email = FALSE, login = FALSE, new = FALSE;
  int delete = FALSE;
  int password = FALSE;

  if( have_capem ){
    new = TRUE;

    if( ( new && req ) || sign || revoke ){
      delete = TRUE;
    }

    if( current_client && current_client->have_key ){
      key = FALSE;
      req = TRUE;
    }
    else if( current_client ){
      key = TRUE;
      req = FALSE;
      sign = FALSE;
      revoke = FALSE;
    }

    if( current_client && current_client->have_req ){
      sign = TRUE;
    }

    if( current_client && current_client->have_pem ){
      req = FALSE;
      sign = FALSE;
      revoke = TRUE;
    }
    else {
      if( current_client ) key = TRUE;
    }

  }

  if( client_list ){
    list = TRUE;
  }

  delete = revoke;

  if(key && !sign && !revoke){
    password = TRUE;
  }

  gtk_widget_set_sensitive( button_clientkey, key );
  gtk_widget_set_sensitive( box_clientkeysize, key );
  gtk_widget_set_sensitive( comboboxtext_clientkeysize, key );
  gtk_widget_set_sensitive( button_clientreq, req );
  gtk_widget_set_sensitive( button_clientsign, sign );
  gtk_widget_set_sensitive( box_clientdays, sign );
  gtk_widget_set_sensitive( spinbutton_clientdays, sign );
  gtk_widget_set_sensitive( button_clientrevoke, revoke );
  gtk_widget_set_sensitive( button_clientdelete, delete );
  gtk_widget_set_sensitive( label_clientlist, list );
  gtk_widget_set_sensitive( combobox_clientlist, list );
  gtk_widget_set_sensitive( box_clientname, name );
  gtk_widget_set_sensitive( entry_clientname, name );
  gtk_widget_set_sensitive( box_clientsurname, surname );
  gtk_widget_set_sensitive( entry_clientsurname, surname );
  gtk_widget_set_sensitive( box_clientemail, email );
  gtk_widget_set_sensitive( entry_clientemail, email );
  gtk_widget_set_sensitive( box_clientlogin, login );
  gtk_widget_set_sensitive( entry_clientlogin, login );
  gtk_widget_set_sensitive( box_clientpassword, password );
  gtk_widget_set_sensitive( entry_clientpassword, password );
  gtk_widget_set_sensitive( button_clientnew, new );
}


//
// Updates the sensitive state of all widgets
//
static void widget_is_sensitive( void )
{
  int upload = FALSE;
  widget_ca_is_sensitive();
  widget_server_is_sensitive();
  widget_client_is_sensitive();
  if( have_cakey && have_capem && have_serverpem && have_serverkey ) upload = TRUE;
  gtk_widget_set_sensitive( button_upload, upload );
}


//
// Callback function for the 'changed' signal of:
// 'comboboxtext_cakeysize' GtkComboBoxText on the 'CA' notebook tab
//
void G_MODULE_EXPORT changed_CaKeySize( GtkWidget *widget, gpointer data )
{
  // Get the new value for CA_KEY_SIZE from the widget
  gchar *cakeysize = gtk_combo_box_text_get_active_text( (GtkComboBoxText *)widget );
  CA_KEY_SIZE = strtol( cakeysize, NULL, 10 );
  free( cakeysize );
}


//
// Callback function for the 'changed' signal of:
// 'spinbutton_cadays' GtkSpinButton on the 'CA' notebook tab
//
void G_MODULE_EXPORT changed_CaDays( GtkWidget *widget, gpointer data )
{
  CA_DAYS_VALID = gtk_spin_button_get_value( (GtkSpinButton *)widget );
}


//
// Callback function for the 'changed' signal of:
// 'comboboxtext_serverkeysize' GtkComboBoxText on the 'Server' notebook tab
//
void G_MODULE_EXPORT changed_ServerKeySize( GtkWidget *widget, gpointer data )
{
  // Get the new value for CA_KEY_SIZE from the widget
  gchar *serverkeysize = gtk_combo_box_text_get_active_text( (GtkComboBoxText *)widget );
  SERVER_KEY_SIZE = strtol( serverkeysize, NULL, 10 );
  free( serverkeysize );
}

//
// Callback function for the 'changed' signal of:
// 'spinbutton_serverdays' GtkSpinButton on the 'Server' notebook tab
//
void G_MODULE_EXPORT changed_ServerDays( GtkWidget *widget, gpointer data )
{
  SERVER_DAYS_VALID = gtk_spin_button_get_value( (GtkSpinButton *)widget );
}





//
// Create a new private key for the CA certificate
// (Also creates a public key for the CA key and
// another key pair for encryption of client credentials)
//
// Callback function for the 'clicked' signal of:
// 'button-cakey' GtkButton on the 'CA' notebook tab
//
void G_MODULE_EXPORT button_CaNewPrivateKey( GtkWidget *widget, gpointer data )
{
  char buf[80];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }


  if(
    // Command to generate private key
#if CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_cakey, fmt_openssl_dir, fmt_openssl_exe,
      CA_KEY_SIZE, FN_CAKEY, FN_CAPWD ) ||
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_cakey_param, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAKEY_PARAM, CA_KEY_SIZE ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_cakey, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAKEY_PARAM, FN_CAKEY, FN_CAPWD ) ||
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_cakey_param, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAKEY_PARAM ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_cakey, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAKEY_PARAM, FN_CAKEY, FN_CAPWD ) ||
#elif CA_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_cakey_param, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAKEY_PARAM ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_cakey, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAKEY_PARAM, FN_CAKEY, FN_CAPWD ) ||
#endif
    // Command to create the CA public key from the CA private key
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_capubkey, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAPWD, FN_CAKEY, FN_CAPUBKEY ) ||
    // Command to create the credentials private key
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_cred_gen_key, fmt_openssl_dir, fmt_openssl_exe,
      FN_CRED_KEY ) ||
    // Command to create the credentials public key from the private key
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_cred_gen_pubkey, fmt_openssl_dir, fmt_openssl_exe,
      FN_CRED_KEY, FN_CRED_PUBKEY )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  // Execute all commands
  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_ca_key, cmdlist, 1 );

  // check output
  if(
    is_regular_file( FN_CAKEY ) ||
    is_regular_file( FN_CAPUBKEY ) ||
    is_regular_file( FN_CRED_KEY ) ||
    is_regular_file( FN_CRED_PUBKEY )
  ){
    have_cakey = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CAKEY );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_cakey = 1;

    // Delete the req/pem/p12/crl beacause they are now invalid
    if( ! is_regular_file( FN_CAREQ ) ){
      remove( FN_CAREQ );
      have_careq = 0;
    }
    if( ! is_regular_file( FN_CAPEM ) ){
      remove( FN_CAPEM );
      have_capem = 0;
    }
    if( ! is_regular_file( FN_CRL ) ){
      remove( FN_CRL );
      have_crl = 0;
    }
    struct client_t *c;
    for( c = client_list; c != NULL; c = c->next ){
      remove( c->fn_req );
      remove( c->fn_pem );
      remove( c->fn_p12 );
      c->have_req = 0;
      c->have_pem = 0;
      c->have_p12 = 0;
    }

    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CAKEY );
    chmod( FN_CAKEY, 0660 );
    set_opengalaxy_gid( FN_CAPUBKEY );
    chmod( FN_CAPUBKEY, 0666 );
    set_opengalaxy_gid( FN_CRED_KEY );
    chmod( FN_CRED_KEY, 0660 );
    set_opengalaxy_gid( FN_CRED_PUBKEY );
    chmod( FN_CRED_PUBKEY, 0666 );

  }
  widget_is_sensitive();

error:
  _gtk_dialog_exec_free_list( cmdlist );
}


//
// Create a new CA certificate request
//
// Callback function for the 'clicked' signal of:
// 'button_careq' GtkButton on the 'CA' notebook tab
//
void G_MODULE_EXPORT button_CaNewReq( GtkWidget *widget, gpointer data )
{
  char buf[80];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );
  // Execute the command and send the output to a new dialog window
  _gtk_dialog_exec_printf(
    GTK_WINDOW( toplevel ),
    cmd_title_ca_req,
    cmd_gen_careq,
    fmt_openssl_dir, fmt_openssl_exe,
    FN_CACNF, FN_CAKEY, FN_CAREQ, FN_CAPWD
  );

  if( is_regular_file( FN_CAREQ ) ){
    have_careq = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CAREQ );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_careq = 1;

    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CAREQ );
    chmod( FN_CAREQ, 0660 );
  }

  widget_is_sensitive();
}


//
// Signs the current CA certificate request and
// also signs the current server certificate request and
// also signs all client certificates and
// also creates a new certificate revocation list
//
// Callback function for the 'clicked' signal of:
// 'button_casign' GtkButton on the 'CA' notebook tab
//
void G_MODULE_EXPORT button_CaSign( GtkWidget *widget, gpointer data )
{
  struct client_t *c;
  char buf[ CMD_MAX_LEN ];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  if(
    // Command to selfsign the CA cert
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_capem, fmt_openssl_dir, fmt_openssl_exe,
      FN_CACNF, CA_DAYS_VALID, FN_CAPWD, FN_CAPEM, FN_CAKEY, FN_CAREQ ) ||
    // Command to generate a new DER encoded certificate
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_server_crt, fmt_openssl_dir, fmt_openssl_exe,
      FN_CAPEM, FN_CACRT )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  // Command to resign server certificate request
  if( have_serverreq ){
    // Command to selfsign the CA cert
    if( _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_server_pem, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERCNF, FN_CAPWD, SERVER_DAYS_VALID, FN_SERVERPEM, FN_SERVERREQ ) ){
      _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
      goto error;
    }
  }

  // Commands to resign the client certificate requests and generate new PKCS#12 bundles
  for( c = client_list; c != NULL; c = c->next ){
    if( c->have_req ){
      if(
        // Command to sign client cert
        _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_client_pem, fmt_openssl_dir, fmt_openssl_exe,
          c->fn_cnf, FN_CAPWD, c->days_valid, c->fn_pem, c->fn_req ) ||
        // Command to generate a pkcs#12 bundle for this client cert
        _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_client_p12, fmt_openssl_dir, fmt_openssl_exe,
          c->fn_pem, c->fn_key, c->name, c->surname, c->fn_p12 )
      ){
        _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
        goto error;
      }
    }
  }

  // Generate a new CRL
  if( _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_crl, fmt_openssl_dir, fmt_openssl_exe,
    FN_CACNF, FN_CRL, FN_CAPWD ) ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  // Execute all commands
  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_ca_pem, cmdlist, 1 );

  // Test if the files were written to disk
  for( c = client_list; c != NULL; c = c->next ){
    if( c->have_req ){
      if( is_regular_file( c->fn_pem ) ){
        c->have_pem = 0;
        snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, c->fn_pem );
        _gtk_display_error_dialog( toplevel, msg_error, buf );
      }
      else {
        c->have_pem = 1;
        // Set the correct group id and file permissions
        set_opengalaxy_gid( c->fn_pem );
        chmod( c->fn_pem, 0664 );
      }
      if( is_regular_file( c->fn_p12 ) ){
        c->have_p12 = 0;
        snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, c->fn_p12 );
        _gtk_display_error_dialog( toplevel, msg_error, buf );
      }
      else {
        c->have_p12 = 1;
        // Set the correct group id and file permissions
        set_opengalaxy_gid( c->fn_p12 );
        chmod( c->fn_p12, 0664 );
      }
    }
  }
  if( is_regular_file( FN_CAPEM ) ){
    have_capem = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CAPEM );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_capem = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CAPEM );
    chmod( FN_CAPEM, 0664 );
  }
  if( have_serverreq ){
    if( is_regular_file( FN_SERVERPEM ) ){
      have_serverpem = 0;
      snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_SERVERPEM );
      _gtk_display_error_dialog( toplevel, msg_error, buf );
    }
    else {
      have_serverpem = 1;
      // Set the correct group id and file permissions
      set_opengalaxy_gid( FN_SERVERPEM );
      chmod( FN_SERVERPEM, 0664 );
    }
  }
  if( is_regular_file( FN_CACRT ) ){
    have_cacrt = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CACRT );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_cacrt = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CACRT );
    chmod( FN_CACRT, 0664 );
  }
  if( is_regular_file( FN_CRL ) ){
    have_crl = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CRL );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_crl = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CRL );
    chmod( FN_CRL, 0664 );
  }

  // Enable/disable widgets
  widget_is_sensitive();

error:
  // Free the cmdlist
  _gtk_dialog_exec_free_list( cmdlist );
}


//
// Revokes the current CA certificate and
// also revokes the current server certificate and
// also revokes all client certificates and
// also creates a new certificate revocation list
//
// Callback function for the 'clicked' signal of:
// 'button_carevoke' GtkButton on the 'CA' notebook tab
//
void G_MODULE_EXPORT button_CaRevoke( GtkWidget *widget, gpointer data )
{
  struct client_t *c;
  char buf[ CMD_MAX_LEN ];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  // Commands to revoke client certs
  for( c = client_list; c != NULL; c = c->next ){
    if( c->have_pem ){
      if( _gtk_dialog_exec_list_printf( &cmdlist, cmd_revoke_cert, fmt_openssl_dir, fmt_openssl_exe,
        c->fn_cnf, c->fn_pem, FN_CAPWD ) ){
        _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
        goto error;
      }
    }
  }

  // Revoke server certificate
  if( have_serverpem ){
    if( _gtk_dialog_exec_list_printf( &cmdlist, cmd_revoke_cert, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERCNF, FN_SERVERPEM, FN_CAPWD ) ){
      _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
      goto error;
    }
  }

  if(
    // Revoke CA certificate
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_revoke_cert, fmt_openssl_dir, fmt_openssl_exe,
      FN_CACNF, FN_CAPEM, FN_CAPWD ) ||
    // Generate a new CRL
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_crl, fmt_openssl_dir, fmt_openssl_exe,
      FN_CACNF, FN_CRL, FN_CAPWD )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  // Execute all commands
  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_ca_revoke, cmdlist, 1 );

  // delete the now revoked certificates
  for( c = client_list; c != NULL; c = c->next ){
    if( c->have_pem ){
      remove( c->fn_pem );
      remove( c->fn_p12 );
    }
  }
  remove( FN_CAPEM );
  remove( FN_SERVERPEM );

  // Test if the files were written to disk
  for( c = client_list; c != NULL; c = c->next ){
    c->have_pem = 0;
    c->have_p12 = 0;
  }
  have_capem = 0;
  have_serverpem = 0;
  if( is_regular_file( FN_CRL ) ){
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CRL );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
    have_crl = 0;
  }
  else {
    have_crl = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CRL );
    chmod( FN_CRL, 0664 );
  }

  // Refresh button sensitive states
  widget_is_sensitive();

error:
  // Free the cmdlist
  _gtk_dialog_exec_free_list( cmdlist );
}


//
// Create a new private key for the server certificate
//
// Callback function for the 'clicked' signal of:
// 'button_serversign' GtkButton on the 'Server' notebook tab
//
void G_MODULE_EXPORT button_ServerNewPrivateKey( GtkWidget *widget, gpointer data )
{
  char buf[80];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  if(
    // Command to generate private key
#if SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_srvkey, fmt_openssl_dir, fmt_openssl_exe,
      SERVER_KEY_SIZE, FN_SERVERKEY )
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_srvkey_param, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERKEY_PARAM, SERVER_KEY_SIZE ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_srvkey, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERKEY_PARAM, FN_SERVERKEY )
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_srvkey_param, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERKEY_PARAM ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_srvkey, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERKEY_PARAM, FN_SERVERKEY )
#elif SERVER_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_srvkey_param, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERKEY_PARAM ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_srvkey, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERKEY_PARAM, FN_SERVERKEY )
#endif
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  // Execute all commands
  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_server_key, cmdlist, 1 );

  // Test for server private key file
  if( is_regular_file( FN_SERVERKEY ) ){
    have_serverkey = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_SERVERKEY );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_serverkey = 1;

    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_SERVERKEY );
    chmod( FN_SERVERKEY, 0660 );

    if( ! is_regular_file( FN_SERVERREQ ) ){
      remove( FN_SERVERREQ );
      remove( FN_SERVERCNF );
      have_serverreq = 0;
      have_servercnf = 0;
    }
    if( ! is_regular_file( FN_SERVERPEM ) ){
      remove( FN_SERVERPEM );
      have_serverpem = 0;
    }
  }

  widget_is_sensitive();

error:
  _gtk_dialog_exec_free_list( cmdlist );
}


//
// Make a new certificate request fort the server certificate
//
// Callback function for the 'clicked' signal of:
// 'button_serverreq' GtkButton on the 'Server' notebook tab
//
void G_MODULE_EXPORT button_ServerNewReq( GtkWidget *widget, gpointer data )
{
  int comma_flag;
  int len;
  char *token;
  char *saveptr;

  char line_buf[CMD_MAX_LEN];
  char buf[CMD_MAX_LEN];
  char *tmp = buf;

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // Get the relevant data from the widgets
  const gchar *url = gtk_entry_buffer_get_text( entrybuffer_servercommonname );
  const gchar *alt_url = gtk_entry_buffer_get_text( entrybuffer_serveraltdns );
  const gchar *alt_ip = gtk_entry_buffer_get_text( entrybuffer_serveraltip );
  const gchar *email = gtk_entry_buffer_get_text( entrybuffer_serveremail );

  // Invalid characters check the parameters
  if( has_invalid_characters( url, url_invalid_chars ) ){
    sprintf( tmp, fmt_msg_string_validate, str_primary_url );
    gtk_widget_grab_focus( entry_servercommonname );
    _gtk_display_error_dialog( toplevel, msg_error, tmp );
    return;
  }
  if( has_invalid_characters( alt_url, url_invalid_chars ) ){
    sprintf( tmp, fmt_msg_string_validate, str_alt_url );
    gtk_widget_grab_focus( entry_serveraltdns );
    _gtk_display_error_dialog( toplevel, msg_error, tmp );
    return;
  }
  if( has_invalid_characters( alt_ip, url_invalid_chars ) ){
    sprintf( tmp, fmt_msg_string_validate, str_alt_ip );
    gtk_widget_grab_focus( entry_serveraltip );
    _gtk_display_error_dialog( toplevel, msg_error, tmp );
    return;
  }
  if( has_invalid_characters( email, email_invalid_chars ) ){
    sprintf( tmp, fmt_msg_string_validate, str_alt_email );
    gtk_widget_grab_focus( entry_serveremail );
    _gtk_display_error_dialog( toplevel, msg_error, tmp );
    return;
  }

  // Create final list of alternative IP addressess and DNS names in 'line_buf'
  line_buf[0] = '\0';
  len = sizeof( line_buf ) - 1;
  comma_flag = 0;

#define _ADD_TO_SERVER_ALT( type, var )\
  strncpy( buf, var, sizeof( buf ) );\
  if( ( token = strtok_r( buf, token_delim_3, &saveptr ) ) ){\
    if( comma_flag ){\
      strncat( line_buf, str_comma, len );\
      len -= strlen( str_comma );\
    }\
    else comma_flag = 1;\
    strncat( line_buf, type, len );\
    len -= strlen( type );\
    strncat( line_buf, token, len );\
    len -= strlen( token );\
    while( ( token = strtok_r( NULL, token_delim_3, &saveptr ) ) ){\
      strncat( line_buf, str_comma, len );\
      len -= strlen( str_comma );\
      strncat( line_buf, type, len );\
      len -= strlen( type );\
      strncat( line_buf, token, len );\
      len -= strlen( token );\
    }\
  }

  if( !is_ip_address( url ) ){ _ADD_TO_SERVER_ALT( str_ip, url ); }
  else { _ADD_TO_SERVER_ALT( str_dns, url ); }
  _ADD_TO_SERVER_ALT( str_ip, alt_ip )
  _ADD_TO_SERVER_ALT( str_dns, alt_url )
#undef _ADD_TO_SERVER_ALT

  // Create the final certificate parameters
  if( SERVER_URL ) free( SERVER_URL );
  if( SERVER_ALT_URL ) free( SERVER_ALT_URL );
  if( SERVER_ALT_IP ) free( SERVER_ALT_IP );
  if( SERVER_ALT ) free( SERVER_ALT );
  if( SERVER_EMAIL_ADDRESS ) free( SERVER_EMAIL_ADDRESS );
  SERVER_URL = strdup( url );
  SERVER_ALT_URL = strdup( alt_url );
  SERVER_ALT_IP = strdup( alt_ip );
  SERVER_ALT = strdup( line_buf );
  SERVER_EMAIL_ADDRESS = strdup( email );

  // Sanity check
  if(
    ( SERVER_URL == NULL ) ||
    ( SERVER_ALT_URL == NULL ) ||
    ( SERVER_ALT_IP == NULL ) ||
    ( SERVER_ALT == NULL ) ||
    ( SERVER_EMAIL_ADDRESS == NULL )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  // Strip leading/trailing spaces/tabs
  if(
    strtrim( SERVER_URL ) ||
    strtrim( SERVER_ALT_URL ) ||
    strtrim( SERVER_ALT_IP ) ||
    strtrim( SERVER_ALT ) ||
    strtrim( SERVER_EMAIL_ADDRESS )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  // Test primary url for empty string
  if( strlen( SERVER_URL ) == 0 ){
    gtk_widget_grab_focus( entry_servercommonname );
    _gtk_display_error_dialog( toplevel, msg_error, msg_need_primary );
    return;
  }

  // Test email for empty string
  if( strlen( SERVER_EMAIL_ADDRESS ) == 0 ){
    free( SERVER_EMAIL_ADDRESS );
    SERVER_EMAIL_ADDRESS = strdup( str_default_server_email );
    if( SERVER_EMAIL_ADDRESS == NULL ){
      _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
      return;
    }
  }

  //
  // Write the cnf file to disk
  //
  if( cert_write_FN_SERVERCNF() ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_fail_cnf_write );
    return;
  }

  //
  // Execute the command to make a certificate request and send it's STDOUT/STDERR to a new dialog window
  //
  _gtk_dialog_exec_printf( GTK_WINDOW( toplevel ), cmd_title_server_req, cmd_gen_server_req, fmt_openssl_dir, fmt_openssl_exe,
    FN_SERVERCNF, SERVER_DAYS_VALID, FN_SERVERREQ, FN_SERVERKEY );

  // Test if the server certificate request file was written to disk
  if( is_regular_file( FN_SERVERREQ ) ){
    have_serverreq = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_SERVERREQ );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_serverreq = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_SERVERREQ );
    chmod( FN_SERVERREQ, 0664 );
  }

  widget_is_sensitive();
}


//
// Signs the current server certificate request
//
// Callback function for the 'clicked' signal of:
// 'button_serversign' GtkButton on the 'Server' notebook tab
//
void G_MODULE_EXPORT button_ServerSign( GtkWidget *widget, gpointer data )
{
  char buf[80];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );
  // Execute the command and send the output to a new dialog window
  _gtk_dialog_exec_printf( GTK_WINDOW( toplevel ), cmd_title_server_pem, cmd_gen_server_pem, fmt_openssl_dir, fmt_openssl_exe,
    FN_SERVERCNF, FN_CAPWD, SERVER_DAYS_VALID, FN_SERVERPEM, FN_SERVERREQ );

  // Test for server certificate file
  if( is_regular_file( FN_SERVERPEM ) ){
    have_serverpem = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_SERVERPEM );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_serverpem = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_SERVERPEM );
    chmod( FN_SERVERPEM, 0664 );
  }

  widget_is_sensitive();
}


//
// Revokes the current server certificate
//
// Callback function for the 'clicked' signal of:
// 'button_serverrevoke' GtkButton on the 'Server' notebook tab
//
void G_MODULE_EXPORT button_ServerRevoke( GtkWidget *widget, gpointer data )
{
  char buf[80];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  if(
    // revoke cert
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_revoke_cert, fmt_openssl_dir, fmt_openssl_exe,
      FN_SERVERCNF, FN_SERVERPEM, FN_CAPWD ) ||
    // gen new crl
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_crl, fmt_openssl_dir, fmt_openssl_exe,
      FN_CACNF, FN_CRL, FN_CAPWD )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_server_revoke, cmdlist, 1 );

  remove( FN_SERVERPEM );
  have_serverpem = 0;

  if( is_regular_file( FN_CRL ) ){
    have_crl = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CRL );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_crl = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CRL );
    chmod( FN_CRL, 0664 );
  }

  widget_is_sensitive();

error:
  _gtk_dialog_exec_free_list( cmdlist );
}


//
// Start entering paramaters for a new client by
// clearing all the GtkEntry widgets
//
// Callback function for the 'clicked' signal of:
// 'button_clientnew' GtkButton on the 'Client' notebook tab
//
void G_MODULE_EXPORT button_ClientNew( GtkWidget *widget, gpointer data )
{
  current_client = NULL;

  // Clear the entrybuffers
  gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientname ), str_empty, -1 );
  gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientsurname ), str_empty, -1 );
  gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientemail ), str_empty, -1 );
  gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientlogin ), str_empty, -1 );
  gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientpassword ), str_empty, -1 );

  // 'Tell' the user to fill the entrybuffers
  gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientname ), str_enter_client_name );
  gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientsurname ), str_enter_client_surname );
  gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientemail ), str_enter_client_email );
  gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientlogin ), str_enter_client_login );
  gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientpassword ), str_enter_client_password );

  // Enable the entry widgets
  current_client = NULL;
  widget_client_is_sensitive();
  gtk_widget_set_sensitive( box_clientname, TRUE );
  gtk_widget_set_sensitive( entry_clientname, TRUE );
  gtk_widget_set_sensitive( box_clientsurname, TRUE );
  gtk_widget_set_sensitive( entry_clientsurname, TRUE );
  gtk_widget_set_sensitive( box_clientemail, TRUE );
  gtk_widget_set_sensitive( entry_clientemail, TRUE );
  gtk_widget_set_sensitive( box_clientlogin, TRUE );
  gtk_widget_set_sensitive( box_clientpassword, TRUE );
  gtk_widget_set_sensitive( entry_clientlogin, TRUE );
  gtk_widget_set_sensitive( entry_clientpassword, TRUE );
  gtk_widget_set_sensitive( button_clientnew, FALSE );

  gtk_combo_box_set_active( GTK_COMBO_BOX( combobox_clientlist ), -1 );

  // set the focus on the first GtkEntry
  gtk_widget_grab_focus( entry_clientname );
}


//
// Sets the visibility of the create private key button and its parameters
//
// Called by:
//  changed_ClientName()
//  changed_ClientSurname()
//  changed_ClientEmail()
//  changed_ClientLogin()
//  changed_ClientPassword()
//
static void have_client_parameters( void )
{
  // Do all fields have a value
  if( have_clientname && have_clientsurname && have_clientemail && have_clientlogin && have_clientpassword ){
    // yes, so unlock generating a private key
    gtk_widget_set_sensitive( button_clientkey, TRUE );
    gtk_widget_set_sensitive( box_clientkeysize, TRUE );
    gtk_widget_set_sensitive( comboboxtext_clientkeysize, TRUE );
  }
  else {
    gtk_widget_set_sensitive( button_clientkey, FALSE );
    gtk_widget_set_sensitive( box_clientkeysize, FALSE );
    gtk_widget_set_sensitive( comboboxtext_clientkeysize, FALSE );
  }
}


//
// Used to determine if all GtkEntry widgets have a valid value
// If so, the 'button_clientkey' GtkButton is made available
//
// Callback function for the 'changed' signal of:
// 'entry_clientname' GtkEntry on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientName( GtkWidget *widget, gpointer data )
{
  if( gtk_entry_buffer_get_length( entrybuffer_clientname ) > 0 ){
    have_clientname = 1;
  }
  else {
    have_clientname = 0;
  }
  have_client_parameters();
}


//
// Used to determine if all GtkEntry widgets have a valid value
// If so, the 'button_clientkey' GtkButton is made available
//
// Callback function for the 'changed' signal of:
// 'entry_clientsurname' GtkEntry on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientSurname( GtkWidget *widget, gpointer data )
{
  if( gtk_entry_buffer_get_length( entrybuffer_clientsurname ) > 0 ){
    have_clientsurname = 1;
  }
  else {
    have_clientsurname = 0;
  }
  have_client_parameters();
}


//
// Used to determine if all GtkEntry widgets have a valid value
// If so, the 'button_clientkey' GtkButton is made available
//
// Callback function for the 'changed' signal of:
// 'entry_clientemail' GtkEntry on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientEmail( GtkWidget *widget, gpointer data )
{
  if( gtk_entry_buffer_get_length( entrybuffer_clientemail ) > 0 ){
    have_clientemail = 1;
  }
  else {
    have_clientemail = 0;
  }
  have_client_parameters();
}


//
// Used to determine if all GtkEntry widgets have a valid value
// If so, the 'button_clientkey' GtkButton is made available
//
// Callback function for the 'changed' signal of:
// 'entry_clientlogin' GtkEntry on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientLogin( GtkWidget *widget, gpointer data )
{
  if( gtk_entry_buffer_get_length( entrybuffer_clientlogin ) > 0 ){
    have_clientlogin = 1;
  }
  else {
    have_clientlogin = 0;
  }
  have_client_parameters();
}


//
// Used to determine if all GtkEntry widgets have a valid value
// If so, the 'button_clientkey' GtkButton is made available
//
// Callback function for the 'changed' signal of:
// 'entry_clientpassword' GtkEntry on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientPassword( GtkWidget *widget, gpointer data )
{
  if( gtk_entry_buffer_get_length( entrybuffer_clientpassword ) > 0 ){
    have_clientpassword = 1;
  }
  else {
    have_clientpassword = 0;
  }
  have_client_parameters();
}


//
// Used to set the size of the private key generated for this client
//
// Callback function for the 'changed' signal of:
// 'comboboxtext_clientkeysize' GtkComboBoxText on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientKeySize( GtkWidget *widget, gpointer data )
{
  // Get the new value for CA_KEY_SIZE from the widget
  gchar *clientkeysize = gtk_combo_box_text_get_active_text( (GtkComboBoxText *)widget );
  CLIENT_KEY_SIZE = strtol( clientkeysize, NULL, 10 );
  free( clientkeysize );
}


//
// Used to set the number of days of validity when signing a client cerificate
//
// Callback function for the 'changed' signal of:
// 'comboboxtext_clientdays' GtkComboBoxText on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientDays( GtkWidget *widget, gpointer data )
{
  CLIENT_DAYS_VALID = gtk_spin_button_get_value( (GtkSpinButton *)widget );
  current_client->days_valid = CLIENT_DAYS_VALID;
}


//
// Populate the 'combobox_ClientList' GtkCombox
// and sends a 'changed' signal to the combobox 
//
// 'active' is the client_t to set as the selected combobox item
//
static void fill_client_liststore_combobox( struct client_t *active )
{
  GtkTreeIter iter;
  struct client_t *client = client_list;
  if( client) gtk_list_store_clear( liststore_clientlist );
  while( client ){
    // Add each client to the combobox's liststore
    gtk_list_store_append( liststore_clientlist, &iter );
    gtk_list_store_set( liststore_clientlist, &iter,
      0, ( gpointer )client,
      1, ( gchararray )client->name,
      2, ( gchararray )client->surname,
      3, ( gchararray )" (",
      4, ( gchararray )client->login,
      5, ( gchararray )")",
      -1
    );
    // This also triggers the 'changed' signal ...
    if( client == active ) gtk_combo_box_set_active_iter( GTK_COMBO_BOX( combobox_clientlist ), &iter );
    client = client->next;
  }
}


//
// Callback function for the 'changed' signal of:
// 'combobox_clientlist' GtkComboBox on the 'Client' notebook tab
//
void G_MODULE_EXPORT changed_ClientList( GtkComboBox *combo, gpointer data )
{
  GtkTreeIter iter;
  GtkTreeModel *model;
  char buf[64];
  struct client_t *client = NULL;

  // Get the client_t from the currently selected item of the combo box.
  // If nothing is selected, do nothing.
  if( gtk_combo_box_get_active_iter( combo, &iter ) ){
    // Get data model from the combo box.
    model = gtk_combo_box_get_model( combo );
    // Get pointer to client_t from the model.
    gtk_tree_model_get( model, &iter, 0, ( gpointer )&client, -1 );
  }

  // Change the currently selected client to this one
  current_client = client;
  if( client ){
    // Display the newly selected clients parameters in the entry widgets
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientname ), client->name, -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientsurname ), client->surname, -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientemail ), client->email, -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientlogin ), client->login, -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_clientpassword ), client->password, -1 );

    // 'Show' the user any empty entrybuffers
    gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientname ), str_enter_client_name );
    gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientsurname ), str_enter_client_surname );
    gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientemail ), str_enter_client_email );
    gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientlogin ), str_enter_client_login );
    gtk_entry_set_placeholder_text( GTK_ENTRY( entry_clientpassword ), str_enter_client_password );

    // Display/Set the current key size
    CLIENT_KEY_SIZE = client->key_size;
    switch( CLIENT_KEY_SIZE ){
      case 1024: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 0 ); break;
      case 2048: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 1 ); break;
      case 4096: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 2 ); break;
      default:
        snprintf( buf, sizeof( buf ), "%d", CLIENT_KEY_SIZE );
        gtk_combo_box_text_remove( GTK_COMBO_BOX_TEXT( comboboxtext_clientkeysize ), 3 );
        gtk_combo_box_text_insert_text( GTK_COMBO_BOX_TEXT( comboboxtext_clientkeysize ), 3, buf );
        gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 3 );
        break;
    }

    // Display/Set the current days valid
    gtk_spin_button_set_value( (GtkSpinButton *)spinbutton_clientdays, client->days_valid );

    // Refresh the widgets sensitive state
    widget_is_sensitive();
  }
  else {
    // Display/Set the current days valid
    if( current_client ) gtk_spin_button_set_value( (GtkSpinButton *)spinbutton_clientdays, current_client->days_valid );
    else gtk_spin_button_set_value( (GtkSpinButton *)spinbutton_clientdays, CLIENT_DAYS_VALID );
  }
}


//
// Create a new client_list entry if this is a new client
// and generate the private key for this (new) client
//
// Callback function for the 'clicked' signal of:
// 'button_clientkey' GtkButton on the 'Client' notebook tab
//
void G_MODULE_EXPORT button_ClientNewPrivateKey( GtkWidget *widget, gpointer data )
{
  char buf[80];
  char cmd[CMD_MAX_LEN];
  char *tmp = cmd;

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  // Add a new client or use the current
  struct client_t *client = current_client;
  if( client == NULL ){

    // check the validity of the parameters
    const gchar *name = gtk_entry_buffer_get_text( entrybuffer_clientname );
    const gchar *surname = gtk_entry_buffer_get_text( entrybuffer_clientsurname );
    const gchar *email = gtk_entry_buffer_get_text( entrybuffer_clientemail );
    const gchar *login = gtk_entry_buffer_get_text( entrybuffer_clientlogin );
    const gchar *password = gtk_entry_buffer_get_text( entrybuffer_clientpassword );
    if( has_invalid_characters( name, fn_invalid_chars ) ){
      sprintf( tmp, fmt_msg_string_validate, str_client_name );
      gtk_widget_grab_focus( entry_clientname );
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }
    if( has_invalid_characters( surname, fn_invalid_chars ) ){
      sprintf( tmp, fmt_msg_string_validate, str_client_surname );
      gtk_widget_grab_focus( entry_clientsurname );
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }
    if( has_invalid_characters( email, email_invalid_chars ) ){
      sprintf( tmp, fmt_msg_string_validate, str_client_email );
      gtk_widget_grab_focus( entry_clientemail );
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }
    if( has_invalid_characters( login, fn_invalid_chars ) ){
      sprintf( tmp, fmt_msg_string_validate, str_client_login );
      gtk_widget_grab_focus( entry_clientlogin );
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }
    if( has_invalid_characters( password, fn_invalid_chars ) ){
      sprintf( tmp, fmt_msg_string_validate, str_client_password );
      gtk_widget_grab_focus( entry_clientpassword );
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }

    // Allocate the new struct client_t
    if( ( client = malloc( sizeof( struct client_t ) ) ) == NULL ){
      _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
      goto error;
    }

    // Setup the struct members
    memset( client, 0, sizeof( struct client_t ) );
    client->name = strdup( name );  
    client->surname = strdup( surname );  
    client->email = strdup( email );  
    client->login = strdup( login );
    client->password = strdup( password );
    client->key_size = CLIENT_KEY_SIZE;
    client->days_valid = CLIENT_DAYS_VALID;

    // Create a base filename for this certificate
    char fn_client_basename[4096], *p;
    snprintf( fn_client_basename, sizeof( fn_client_basename ), "%s-%s-%s", client->name, client->surname, client->login );
    while( ( p = strchr( fn_client_basename, ' ' ) ) != NULL ){
      *p = '_'; // replace spaces with underscores
    }
    for( p = fn_client_basename; *p != '\0'; p++ ){
      *p = tolower( *p ); // convert to lower case
    }

    // Create a suitable filename for the cnf file for this client
    snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_cnf, cert_dir, fn_client_basename );
    client->fn_cnf = strdup( tmp );

    // Create a suitable filename for the private key file for this client
    snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_key_param, cert_dir, fn_client_basename );
    client->fn_key_param = strdup( tmp );

    // Create a suitable filename for the private key file for this client
    snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_key, cert_dir, fn_client_basename );
    client->fn_key = strdup( tmp );

    // Create a suitable filename for the certificate request file for this client
    snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_req, cert_dir, fn_client_basename );
    client->fn_req = strdup( tmp );

    // Create a suitable filename for the certificate file for this client
    snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_pem, cert_dir, fn_client_basename );
    client->fn_pem = strdup( tmp );

    // Create a suitable filename for the certificate file for this client
    snprintf( tmp, CMD_MAX_LEN, fmt_file_path_client_p12, cert_dir, fn_client_basename );
    client->fn_p12 = strdup( tmp );

    // Sanity test  
    if(
      ( ! client->name ) ||
      ( ! client->surname ) ||
      ( ! client->email ) ||
      ( ! client->login ) ||
      ( ! client->password ) ||
      ( ! client->fn_cnf ) ||
      ( ! client->fn_key_param ) ||
      ( ! client->fn_key ) ||
      ( ! client->fn_req ) ||
      ( ! client->fn_pem ) ||
      ( ! client->fn_p12 )
    ){
      _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
      goto error;
    }

    // It's an error if the cnf file allready exists
    if( is_regular_file( client->fn_cnf ) == 0 ){
      sprintf( tmp, fmt_msg_fail_client_exists, client->name, client->surname, client->login );
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }

    // write the cnf for this client
    if( cert_write_FN_CLIENTCNF( client, window ) != 0 ){
#if __linux__
      char buf_err[1024];
      snprintf( tmp, CMD_MAX_LEN, fmt_msg_fail_file_write_errno, client->fn_cnf, strerror_r( errno, buf_err, sizeof( buf_err ) ), errno );
#else
      snprintf( tmp, CMD_MAX_LEN, fmt_msg_fail_file_write_errno, client->fn_cnf, strerror( errno ), errno );
#endif
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }

    // Add the client to the list of clients
    client->next = client_list;
    client_list = client;

  }
  else {
    // This is a pre-existing client

    // update the private key size
    client->key_size = CLIENT_KEY_SIZE;

    // Get the (new) password from the entrybuffer
    const gchar *password = gtk_entry_buffer_get_text( entrybuffer_clientpassword );

    // Differs from the current password?
    if( strcmp( current_client->password, password ) != 0 ){
      // Yes, check for illigal characters
      if( has_invalid_characters( password, fn_invalid_chars ) ){
        gtk_widget_grab_focus( entry_clientpassword );
        _gtk_display_error_dialog( toplevel, msg_error, fmt_msg_string_validate, str_client_password );
        goto error;
      }
      // replace the old password
      free( current_client->password );
      current_client->password = strdup( password );
    }

    // (Re)generate the cnf file
    if( cert_write_FN_CLIENTCNF( client, window ) != 0 ){
#if __linux__
      char buf_err[1024];
      snprintf( tmp, CMD_MAX_LEN, fmt_msg_fail_file_write_errno, client->fn_cnf, strerror_r( errno, buf_err, sizeof( buf_err ) ), errno );
#else
      snprintf( tmp, CMD_MAX_LEN, fmt_msg_fail_file_write_errno, client->fn_cnf, strerror( errno ), errno );
#endif
      _gtk_display_error_dialog( toplevel, msg_error, tmp );
      goto error;
    }

  } // ends if( client == NULL ) else

  // Set this as the current client
  current_client = client;



  // Execute the command to create a private
  // key and send the output to a new dialog window
//  _gtk_dialog_exec_printf( GTK_WINDOW( toplevel ), cmd_title_client_key, cmd_gen_key,
//    fmt_openssl_dir, fmt_openssl_exe, client->fn_key, client->key_size );

  if(
    // Command to generate private key
#if CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_RSA
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_clkey, fmt_openssl_dir, fmt_openssl_exe,
      client->key_size, client->fn_key )
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DSA
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_clkey_param, fmt_openssl_dir, fmt_openssl_exe,
      client->fn_key_param, client->key_size ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_clkey, fmt_openssl_dir, fmt_openssl_exe,
      client->fn_key_param, client->fn_key )
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_EC
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_clkey_param, fmt_openssl_dir, fmt_openssl_exe,
      client->fn_key_param ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_clkey, fmt_openssl_dir, fmt_openssl_exe,
      client->fn_key_param, client->fn_key )
#elif CLIENT_GENPKEY_ALGORITHM == GENPKEY_ALGORITHM_DH
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_clkey_param, fmt_openssl_dir, fmt_openssl_exe,
      client->fn_key_param ) ||
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_clkey, fmt_openssl_dir, fmt_openssl_exe,
      client->fn_key_param, client->fn_key )
#endif
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  // Execute all commands
  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_client_key, cmdlist, 1 );




  // Test for client private key file
  if( is_regular_file( client->fn_key ) ){
    client->have_key = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, client->fn_key );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    client->have_key = 1;

    // Set the correct group id and file permissions
    set_opengalaxy_gid( client->fn_key );
    chmod( client->fn_key, 0664 );

    if( ! is_regular_file( client->fn_req ) ){
      remove( client->fn_req );
      client->have_req = 0;
    }
    if( ! is_regular_file( client->fn_pem ) ){
      remove( client->fn_pem );
      client->have_pem = 0;
    }
    if( ! is_regular_file( client->fn_p12 ) ){
      remove( client->fn_p12 );
      client->have_p12 = 0;
    }
   }

  // Update the list of client certificates on the 'clients' tab of the notebook widget.
  // Set 'client' as the active entry and send a 'changed' signal to the combo box widget.
  fill_client_liststore_combobox( client );

  // Refresh the widgets sensitive state
  widget_is_sensitive();

  return;

error:
  _gtk_dialog_exec_free_list( cmdlist );
  if( client ) free_client_t( client );
  return;
}


//
// Make  a new certificate request for the current client
//
// Callback function for the 'clicked' signal of:
// 'button_clientreq' GtkButton on the 'Client' notebook tab
//
void G_MODULE_EXPORT button_ClientNewReqConfirm( GtkWidget *widget, GtkWidget *dialog )
{
  char buf[1024];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // re-write the cnf for this client
  if( cert_write_FN_CLIENTCNF( current_client, window ) != 0 ){
#if __linux__
    char buf_err[80];
    snprintf( buf, 1024, fmt_msg_fail_file_write_errno, current_client->fn_cnf, strerror_r( errno, buf_err, sizeof( buf_err ) ), errno );
#else
    snprintf( buf, 1024, fmt_msg_fail_file_write_errno, current_client->fn_cnf, strerror( errno ), errno );
#endif
    _gtk_display_error_dialog( toplevel, msg_error, buf );
    goto exit;
  }

  // No, execute the command and send the output to a new dialog window
  _gtk_dialog_exec_printf( GTK_WINDOW( window ), cmd_title_client_req, cmd_gen_client_req, fmt_openssl_dir, fmt_openssl_exe,
    current_client->fn_cnf, current_client->fn_req, current_client->fn_key );

  // Test for server certificate request file
  if( is_regular_file( current_client->fn_req ) ){
    current_client->have_req = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, current_client->fn_key );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    current_client->have_req = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( current_client->fn_req );
    chmod( current_client->fn_req, 0664 );
  }

  // Close the password confirmation dialog
  gtk_widget_destroy( dialog );

  widget_is_sensitive();
exit:
  return;
}


//
// Used to determine if the password confirmation dialog contains the same password as the current client
// If so, the 'button_clientpassword_confirm' GtkButton is made available
//
// Callback function for the 'changed' signal of:
// 'entry_password' GtkEntry on the 'Confirm Password' dialog
//
void G_MODULE_EXPORT changed_ClientPasswordConfirm( GtkWidget *widget, gpointer data )
{
  const gchar *password = gtk_entry_buffer_get_text( entrybuffer_clientpassword_confirm );
  if( strcmp( current_client->password, password ) == 0 ){
    gtk_widget_set_sensitive( button_clientpassword_confirm, TRUE );
  }
}


//
// Confirm the username/password before a new certificate request for the current client
//
// Callback function for the 'clicked' signal of:
// 'button_clientreq' GtkButton on the 'Client' notebook tab
//
void G_MODULE_EXPORT button_ClientNewReq( GtkWidget *widget, gpointer data )
{
  GtkBuilder *builder;
  GtkWidget *dialog;
  GtkWidget *buttonBack;
  GtkWidget *entry_password;
  GtkEntryBuffer *entrybuffer_username;

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // update the private key size
  current_client->key_size = CLIENT_KEY_SIZE;

  // Get the (new) password from the entrybuffer
  const gchar *password = gtk_entry_buffer_get_text( entrybuffer_clientpassword );

  // Differs from the current password?
  if( strcmp( current_client->password, password ) != 0 ){
    // Yes, check for illigal characters
    if( has_invalid_characters( password, fn_invalid_chars ) ){
      gtk_widget_grab_focus( entry_clientpassword );
      _gtk_display_error_dialog( toplevel, msg_error, fmt_msg_string_validate, str_client_password );
      goto exit;
    }
    // replace the old password
    free( current_client->password );
    current_client->password = strdup( password );
  }

  // Create a gtk_builder object
  builder = gtk_builder_new();
  // And feed it our glade XML data
  if( 0 == gtk_builder_add_from_string( builder, (const gchar*)ca_password_dialog_glade, ca_password_dialog_glade_len, NULL ) ){
    _gtk_display_error_dialog( toplevel, msg_error, fmt_msg_fail_glade, "Password Dialog" );
    goto exit;
  }

  // Get the widgets from the gtk_builder object
  dialog = GTK_WIDGET( gtk_builder_get_object( builder, "dialogPassword" ) );
  button_clientpassword_confirm = GTK_WIDGET( gtk_builder_get_object( builder, "buttonConfirm" ) );
  buttonBack = GTK_WIDGET( gtk_builder_get_object( builder, "buttonBack" ) );
  entry_password = GTK_WIDGET( gtk_builder_get_object( builder, "entryPassword" ) );
  entrybuffer_username = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferUsername" ) );
  entrybuffer_clientpassword_confirm = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferPassword" ) );

  // Throw the gtk_builder object away
  g_object_unref( G_OBJECT( builder ) );

  // Make the dialog a child of our main-window
  gtk_window_set_transient_for( GTK_WINDOW( dialog ), GTK_WINDOW( toplevel ) );

  // Set the title for the dialog
  gtk_window_set_title( GTK_WINDOW( dialog ), "Please confirm the password..." );

  // Set callbacks for the buttons
  g_signal_connect_swapped( buttonBack, str_signal_clicked, G_CALLBACK( gtk_window_close ), dialog );
  g_signal_connect( button_clientpassword_confirm, str_signal_clicked, G_CALLBACK( button_ClientNewReqConfirm ), dialog );
  g_signal_connect( entry_password, str_signal_changed, G_CALLBACK( changed_ClientPasswordConfirm ), NULL );
  g_signal_connect( entry_password, str_signal_activate, G_CALLBACK( button_ClientNewReqConfirm ), dialog );

  gtk_widget_set_sensitive( button_clientpassword_confirm, FALSE );
  gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_username ), current_client->login, -1 );

  // Show the dialog
  gtk_widget_show( dialog );
exit:
  return;

  // TODO: do a confirm password dialog here before generating the request
//  button_ClientNewReqConfirm( widget, data );
}


//
// Sign the current client certificate request of the current client
//
// Callback function for the 'clicked' signal of:
// 'button_clientsign' GtkButton on the 'Client' notebook tab
//
void G_MODULE_EXPORT button_ClientSign( GtkWidget *widget, gpointer data )
{
  char buf[80];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  if(
    // cert
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_client_pem, fmt_openssl_dir, fmt_openssl_exe,
      current_client->fn_cnf, FN_CAPWD, current_client->days_valid, current_client->fn_pem, current_client->fn_req ) ||
    // p12 bundle
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_client_p12, fmt_openssl_dir, fmt_openssl_exe,
      current_client->fn_pem, current_client->fn_key, current_client->name, current_client->surname, current_client->fn_p12 )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_client_pem, cmdlist, 1 );

  // Test for server certificate file
  if( is_regular_file( current_client->fn_pem ) ){
    current_client->have_pem = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, current_client->fn_pem );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    current_client->have_pem = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( current_client->fn_pem );
    chmod( current_client->fn_pem, 0664 );
  }
  if( is_regular_file( current_client->fn_p12 ) ){
    current_client->have_p12 = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, current_client->fn_p12 );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    current_client->have_p12 = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( current_client->fn_p12 );
    chmod( current_client->fn_p12, 0664 );
  }

  widget_is_sensitive();

error:
  _gtk_dialog_exec_free_list( cmdlist );
}


//
// Revoke the current certificate of the current client
//
// Callback function for the 'clicked' signal of:
// 'button_clientrevoke' GtkButton on the 'Client' notebook tab
//
void G_MODULE_EXPORT button_ClientRevoke( GtkWidget *widget, gpointer data )
{
  char buf[80];

  // Get the topmost parent of the button widget (ie. the main window)
  GtkWidget *toplevel = gtk_widget_get_toplevel( widget );

  // A list of commands to execute
  char **cmdlist = _gtk_dialog_exec_new_list();
  if( cmdlist == NULL ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    return;
  }

  if(
    // revoke cert
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_revoke_cert, fmt_openssl_dir, fmt_openssl_exe,
      current_client->fn_cnf, current_client->fn_pem, FN_CAPWD ) ||
    // gen new crl
    _gtk_dialog_exec_list_printf( &cmdlist, cmd_gen_crl, fmt_openssl_dir, fmt_openssl_exe,
      FN_CACNF, FN_CRL, FN_CAPWD )
  ){
    _gtk_display_error_dialog( toplevel, msg_error, msg_outofmem );
    goto error;
  }

  _gtk_dialog_exec_list( GTK_WINDOW( toplevel ), cmd_title_client_revoke, cmdlist, 1 );
  remove( current_client->fn_pem );
  remove( current_client->fn_p12 );

  current_client->have_pem = 0;
  current_client->have_p12 = 0;
  if( is_regular_file( FN_CRL ) ){
    have_crl = 0;
    snprintf( buf, sizeof( buf ), fmt_msg_fail_file_write, FN_CRL );
    _gtk_display_error_dialog( toplevel, msg_error, buf );
  }
  else {
    have_crl = 1;
    // Set the correct group id and file permissions
    set_opengalaxy_gid( FN_CRL );
    chmod( FN_CRL, 0664 );
  }

  widget_is_sensitive();

error:
  _gtk_dialog_exec_free_list( cmdlist );
}


//
// Delete the current client
//
// Callback function for the 'clicked' signal of:
// 'button_clientdelete' GtkButton on the 'Client' notebook tab
//
void G_MODULE_EXPORT button_ClientDelete( GtkWidget *widget, gpointer data )
{
  struct client_t *c, *prev;

  button_ClientRevoke( widget, data );

  remove( current_client->fn_cnf );
  remove( current_client->fn_key );
  remove( current_client->fn_req );
  remove( current_client->fn_pem );
  remove( current_client->fn_p12 );

  c = client_list;
  prev = NULL;
  while( c != NULL ){
    if( current_client == c ) break;
    prev = c;
    c = c->next;
  }
  if( c ){
    if( prev ){
      prev->next = c->next;
    }
    else {
      client_list = c->next;
    }
    current_client = c->next;
    free_client_t( c );
  }

  if( current_client == NULL ){
    current_client = client_list;
    gtk_combo_box_set_active_iter( GTK_COMBO_BOX( combobox_clientlist ), NULL );
    gtk_entry_set_text( GTK_ENTRY( entry_clientname ), str_empty );
    gtk_entry_set_text( GTK_ENTRY( entry_clientsurname ), str_empty );
    gtk_entry_set_text( GTK_ENTRY( entry_clientemail ), str_empty );
    gtk_entry_set_text( GTK_ENTRY( entry_clientlogin ), str_empty );
    gtk_entry_set_text( GTK_ENTRY( entry_clientpassword ), str_empty );
    gtk_list_store_clear( liststore_clientlist );
  }
  fill_client_liststore_combobox( current_client );
  changed_ClientList( GTK_COMBO_BOX( combobox_clientlist ), NULL );
  widget_is_sensitive();
}


//
// Try to get the version of the local openssl executeable
// Used to test if openssl can successfully be executed
//
// return value:
//  0 = success
//  !0 = error
//
  char cmd[CMD_MAX_LEN];
static int check_openssl( void )
{
  int retv = -1;
  GtkTextBuffer *buf = NULL;
  GtkTextIter start, end;

  if( ! ( buf = gtk_text_buffer_new( NULL ) ) ){
    errno = ENOMEM;
    goto error;
  }

  snprintf( cmd, sizeof( cmd ), cmd_openssl_version, fmt_openssl_dir, fmt_openssl_exe );
  if( ( retv = _gtk_popen( cmd, buf ) ) != 0 ) goto error;

  gtk_text_buffer_get_start_iter( buf, &start );
  gtk_text_buffer_get_end_iter( buf, &end );
  OPENSSL_VERSION = gtk_text_buffer_get_text( buf, &start, &end, FALSE );

  if( strstr( OPENSSL_VERSION, str_openssl ) == NULL ){
    retv = -1;
  }

error:
  if( buf ) g_object_unref( buf );
  return( retv );
}


//
// Free's the client_list when the program exits
//
static void atexit_free_client_list( void )
{
  while( client_list ){
    struct client_t *c = client_list;
    client_list = c->next;
    free_client_t( c );
  }
}


static void dialog_startup_error( const char *fmt, int err )
{
  static gchar buf[1024];
#if __linux__
  gchar buf_err[1024];
    snprintf( buf, 1024, fmt, strerror_r( err, buf_err, sizeof( buf_err ) ), err );
#else
  snprintf( buf, 1024, fmt, strerror( err ), err );
#endif
  __gtk_display_error_dialog( buf, msg_error, NULL, G_CALLBACK( gtk_main_quit ) );
}


// Called in stead of gtk_main_quit()
void G_MODULE_EXPORT _gtk_main_quit( GtkWidget *widget, gpointer data )
{
  char buffer[4096];
  struct dirent *ep;
  DIR *dp;

  // Set correct ownership and write permissions for some files
  // so other members of group staff can access them.
  // openssl sets them to the current user only with read access for everybody

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "crlnumber" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "crlnumber.old" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "index.txt" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "index.txt.attr" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "index.txt.attr.old" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "index.txt.old" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "serial" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  snprintf( buffer, sizeof( buffer ), fmt_file_path, cert_dir, "serial.old" );
  set_opengalaxy_gid( buffer );
  chmod( buffer, 0664 );

  // Open the newcerts directory
  snprintf( buffer, sizeof( buffer ), fmt_file_path_newcerts, cert_dir, "" );
  dp = opendir( buffer );
  if( dp != NULL ){
    // List all files in the directory
    while( ( ep = readdir (dp) ) != NULL ){
      //is it a .pem file?
      if( strstr( ep->d_name, ".pem" ) || strstr( ep->d_name, ".PEM" ) ){
        snprintf( buffer, sizeof( buffer ), fmt_file_path_newcerts, cert_dir, ep->d_name );
        set_opengalaxy_gid( buffer );
        chmod( buffer, 0664 );
      }
    }
  }

  gtk_main_quit();
}

/////////////////////////////////////////////////////////////
// Certs uploading //////////////////////////////////////////
/////////////////////////////////////////////////////////////

void G_MODULE_EXPORT button_UploadCerts( GtkWidget *widget, gpointer data );



int main( int argc, char *argv[] )
{
  gchar buf[4096];

  OpenSSL_add_all_algorithms(); // needed by pass_cb()

#if ! __linux__
#if ! HAVE_DEBUG
  // On Windows we deliberately link as a 'console' application.
  // This causes a console window to be displayed whenever
  // openGalaxyCA is started.
  // Having this console window has the nice effect of preventing
  // another console window (briefly) popping up when we run
  // openssl using popen().
  // This command hides that console window.
  ShowWindow( GetConsoleWindow(), SW_HIDE );
#endif
#else
  // We need to call this function on Linux to initialize Xlib
  // support for concurrent threads.
  // ( needed by the malloc()/free() in the _gtk_dialog_exec*() functions )
  XInitThreads();
#endif

  // setup libwebsockets
  Websocket_InitThread();
  atexit(Websocket_ExitThread);

  // Cleanup variables at exit time.
  atexit( atexit_clean_vars );
  atexit( atexit_free_client_list );

  // Initialize gtk
  gtk_init( &argc, &argv );

  // Initialize variables and read the config file
  if( cert_init_all_vars( buf, sizeof( buf ) ) ){
    __gtk_display_error_dialog( buf, msg_error, NULL, G_CALLBACK( gtk_main_quit ) );
  }

  // Check/Create the certificates directory and check that the current user can read/write the directory
  else if( cert_check_certificate_directory() ){
    dialog_startup_error( fmt_msg_fail_cert_dir, errno );
  }

  // Make sure that we can run openssl
  else if( check_openssl() ){
    dialog_startup_error( fmt_msg_fail_exec_openssl, errno );
  }

  // Check/Create the certificate directory tree
  else if( cert_check_certificate_subtree() ){
    dialog_startup_error( fmt_msg_fail_cert_tree, errno );
  }

  // Extract information from the CA and Server certificates
  else if( cert_check_certificate_parameters() ){
    dialog_startup_error( fmt_msg_fail_parameters, errno );
  }

  // Create the temporary ca.cnf file
  else if( cert_write_FN_CACNF() ){
    dialog_startup_error( fmt_msg_fail_tmp_file, errno );
  }

  // Done initialising, create the Main Window for the program
  else {
    char buf[4096];
    GtkBuilder *builder;

    // Create a gtk_builder object
    builder = gtk_builder_new();

    // Load main-window XML data
    if( 0 == gtk_builder_add_from_string( builder, (const gchar*)ca_main_window_glade, ca_main_window_glade_len, NULL ) ){
      return(0);
    }

    // Get the widgets
    window                           = GTK_WIDGET(       gtk_builder_get_object( builder, "mainWindow" ) );
    // For the CA tab
    entrybuffer_caorganization       = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferCaOrganization" ) );
    entrybuffer_caorganizationalunit = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferCaOrganizationalUnit" ) );
    entrybuffer_cacommonname         = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferCaCommonName" ) );
    entrybuffer_caemail              = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferCaEmail" ) );
    button_cakey                     = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonCaKey" ) );
    button_careq                     = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonCaReq" ) );
    button_casign                    = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonCaSign" ) );
    button_carevoke                  = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonCaRevoke" ) );
    box_cakeysize                    = GTK_WIDGET(       gtk_builder_get_object( builder, "boxCaKeysize" ) );
    comboboxtext_cakeysize           = GTK_WIDGET(       gtk_builder_get_object( builder, "comboboxtextCaKeysize" ) );
    box_cadays                       = GTK_WIDGET(       gtk_builder_get_object( builder, "boxCaDays" ) );
    spinbutton_cadays                = GTK_WIDGET(       gtk_builder_get_object( builder, "spinbuttonCaDays" ) );
    // For the server tab
    entrybuffer_servercommonname     = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferServerCommonName" ) );
    entrybuffer_serveraltdns         = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferServerAltDns" ) );
    entrybuffer_serveraltip          = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferServerAltIp" ) );
    entrybuffer_serveremail          = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferServerEmail" ) );
    entry_servercommonname           = GTK_WIDGET(       gtk_builder_get_object( builder, "entryServerCommonName" ) );
    entry_serveraltdns               = GTK_WIDGET(       gtk_builder_get_object( builder, "entryServerAltDns" ) );
    entry_serveraltip                = GTK_WIDGET(       gtk_builder_get_object( builder, "entryServerAltIp" ) );
    entry_serveremail                = GTK_WIDGET(       gtk_builder_get_object( builder, "entryServerEmail" ) );
    button_serverkey                 = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonServerKey" ) );
    button_serverreq                 = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonServerReq" ) );
    button_serversign                = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonServerSign" ) );
    button_serverrevoke              = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonServerRevoke" ) );
    box_serverkeysize                = GTK_WIDGET(       gtk_builder_get_object( builder, "boxServerKeysize" ) );
    comboboxtext_serverkeysize       = GTK_WIDGET(       gtk_builder_get_object( builder, "comboboxtextServerKeysize" ) );
    box_serverdays                   = GTK_WIDGET(       gtk_builder_get_object( builder, "boxServerDays" ) );
    spinbutton_serverdays            = GTK_WIDGET(       gtk_builder_get_object( builder, "spinbuttonServerDays" ) );
    frame_servercommonname           = GTK_WIDGET(       gtk_builder_get_object( builder, "frameServerCommonName" ) );
    frame_serveraltname              = GTK_WIDGET(       gtk_builder_get_object( builder, "frameServerAltName" ) );
    frame_serveremail                = GTK_WIDGET(       gtk_builder_get_object( builder, "frameServerEmail" ) );
    // For the client tab
    button_clientkey                 = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonClientKey" ) );
    button_clientreq                 = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonClientReq" ) );
    button_clientsign                = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonClientSign" ) );
    button_clientrevoke              = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonClientRevoke" ) );
    button_clientdelete              = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonClientDelete" ) );
    box_clientkeysize                = GTK_WIDGET(       gtk_builder_get_object( builder, "boxClientKeysize" ) );
    comboboxtext_clientkeysize       = GTK_WIDGET(       gtk_builder_get_object( builder, "comboboxtextClientKeysize" ) );
    box_clientdays                   = GTK_WIDGET(       gtk_builder_get_object( builder, "boxClientDays" ) );
    spinbutton_clientdays            = GTK_WIDGET(       gtk_builder_get_object( builder, "spinbuttonClientDays" ) );
    label_clientlist                 = GTK_WIDGET(       gtk_builder_get_object( builder, "labelClientList" ) );
    combobox_clientlist              = GTK_WIDGET(       gtk_builder_get_object( builder, "comboboxClientList" ) );
    liststore_clientlist             = GTK_LIST_STORE(   gtk_builder_get_object( builder, "liststoreClientList" ) );
    box_clientname                   = GTK_WIDGET(       gtk_builder_get_object( builder, "boxClientName" ) );
    entry_clientname                 = GTK_WIDGET(       gtk_builder_get_object( builder, "entryClientName" ) );
    entrybuffer_clientname           = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferClientName" ) );
    box_clientsurname                = GTK_WIDGET(       gtk_builder_get_object( builder, "boxClientSurname" ) );
    entry_clientsurname              = GTK_WIDGET(       gtk_builder_get_object( builder, "entryClientSurname" ) );
    entrybuffer_clientsurname        = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferClientSurname" ) );
    box_clientemail                  = GTK_WIDGET(       gtk_builder_get_object( builder, "boxClientEmail" ) );
    entry_clientemail                = GTK_WIDGET(       gtk_builder_get_object( builder, "entryClientEmail" ) );
    entrybuffer_clientemail          = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferClientEmail" ) );
    box_clientlogin                  = GTK_WIDGET(       gtk_builder_get_object( builder, "boxClientLogin" ) );
    box_clientpassword               = GTK_WIDGET(       gtk_builder_get_object( builder, "boxClientPassword" ) );
    entry_clientlogin                = GTK_WIDGET(       gtk_builder_get_object( builder, "entryClientLogin" ) );
    entry_clientpassword             = GTK_WIDGET(       gtk_builder_get_object( builder, "entryClientPassword" ) );
    entrybuffer_clientlogin          = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferClientLogin" ) );
    entrybuffer_clientpassword       = GTK_ENTRY_BUFFER( gtk_builder_get_object( builder, "entrybufferClientPassword" ) );
    button_clientnew                 = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonClientNew" ) );
    // For the upload tab
    button_upload                    = GTK_WIDGET(       gtk_builder_get_object( builder, "buttonUpload" ) );
    // For the about tab
    textview_about                   = GTK_WIDGET(       gtk_builder_get_object( builder, "textviewAbout" ) );
    textview_gnu                     = GTK_WIDGET(       gtk_builder_get_object( builder, "textviewGNU" ) );
    label_version                    = GTK_WIDGET(       gtk_builder_get_object( builder, "labelVersion" ) );

    // Load our CSS
    GtkCssProvider *css_provider = gtk_css_provider_new();
    GdkDisplay *display = gdk_display_get_default();
    GdkScreen *screen = gdk_display_get_default_screen( display );
    gtk_style_context_add_provider_for_screen( screen, GTK_STYLE_PROVIDER( css_provider ), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION );
    gtk_css_provider_load_from_data( GTK_CSS_PROVIDER( css_provider ), (const gchar*)ca_gtk_css, ca_gtk_css_len, NULL );

    // Set the correct version string displayed on the About tab
    gtk_label_set_text( GTK_LABEL( label_version ), PACKAGE_VERSION );

    // Set the title for the main-window
    gtk_window_set_title( GTK_WINDOW( window ), str_main_title );

    // Fill the "comboboxtext-cakeysize" GtkComboBoxText with entries and
    // set the selected entry to the current CA_KEY_SIZE
    switch( CA_KEY_SIZE ){
      case 1024: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_cakeysize ), 0 ); break;
      case 2048: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_cakeysize ), 1 ); break;
      case 4096: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_cakeysize ), 2 ); break;
      default:
        snprintf( buf, sizeof( buf ), "%d", CA_KEY_SIZE );
        gtk_combo_box_text_insert_text( GTK_COMBO_BOX_TEXT( comboboxtext_cakeysize ), 3, buf );
        gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_cakeysize ), 3 );
        break;
    }
    // Do the same for "comboboxtext-serverkeysize" GtkComboBoxText
    switch( SERVER_KEY_SIZE ){
      case 1024: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_serverkeysize ), 0 ); break;
      case 2048: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_serverkeysize ), 1 ); break;
      case 4096: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_serverkeysize ), 2 ); break;
      default:
        snprintf( buf, sizeof( buf ), "%d", SERVER_KEY_SIZE );
        gtk_combo_box_text_insert_text( GTK_COMBO_BOX_TEXT( comboboxtext_serverkeysize ), 3, buf );
        gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_serverkeysize ), 3 );
        break;
    }
    // And for "comboboxtext_clientkeysize" GtkComboBoxText
    switch( CLIENT_KEY_SIZE ){
      case 1024: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 0 ); break;
      case 2048: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 1 ); break;
      case 4096: gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 2 ); break;
      default:
        snprintf( buf, sizeof( buf ), "%d", CLIENT_KEY_SIZE );
        gtk_combo_box_text_insert_text( GTK_COMBO_BOX_TEXT( comboboxtext_clientkeysize ), 3, buf );
        gtk_combo_box_set_active( GTK_COMBO_BOX( comboboxtext_clientkeysize ), 3 );
        break;
    }

    // Set the values for several widgets
    gtk_spin_button_set_value( GTK_SPIN_BUTTON( spinbutton_cadays ),     CA_DAYS_VALID );
    gtk_spin_button_set_value( GTK_SPIN_BUTTON( spinbutton_serverdays ), SERVER_DAYS_VALID );
    gtk_spin_button_set_value( GTK_SPIN_BUTTON( spinbutton_clientdays ), CLIENT_DAYS_VALID );

    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_caorganization ),       str_default_ca_organization,       -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_caorganizationalunit ), str_default_ca_organizationalunit, -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_cacommonname ),         str_default_ca_commonname,         -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_caemail ),              str_default_ca_email,              -1 );

    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_servercommonname ), SERVER_URL,           -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_serveraltdns ),     SERVER_ALT_URL,       -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_serveraltip ),      SERVER_ALT_IP,        -1 );
    gtk_entry_buffer_set_text( GTK_ENTRY_BUFFER( entrybuffer_serveremail ),      SERVER_EMAIL_ADDRESS, -1 );

    // Load existing client certificates info from disk
    cert_get_client_list();

    // Set signal callbacks:
    // - for the main window
    g_signal_connect( window,                     str_signal_destroy,       G_CALLBACK( _gtk_main_quit             ), NULL );
    // - for the CA tab
    g_signal_connect( button_cakey,               str_signal_clicked,       G_CALLBACK( button_CaNewPrivateKey     ), NULL );
    g_signal_connect( button_careq,               str_signal_clicked,       G_CALLBACK( button_CaNewReq            ), NULL );
    g_signal_connect( button_casign,              str_signal_clicked,       G_CALLBACK( button_CaSign              ), NULL );
    g_signal_connect( button_carevoke,            str_signal_clicked,       G_CALLBACK( button_CaRevoke            ), NULL );
    g_signal_connect( comboboxtext_cakeysize,     str_signal_changed,       G_CALLBACK( changed_CaKeySize          ), NULL );
    g_signal_connect( spinbutton_cadays,          str_signal_value_changed, G_CALLBACK( changed_CaDays             ), NULL );
    // - for the server tab
    g_signal_connect( button_serverkey,           str_signal_clicked,       G_CALLBACK( button_ServerNewPrivateKey ), NULL );
    g_signal_connect( button_serverreq,           str_signal_clicked,       G_CALLBACK( button_ServerNewReq        ), NULL );
    g_signal_connect( button_serversign,          str_signal_clicked,       G_CALLBACK( button_ServerSign          ), NULL );
    g_signal_connect( button_serverrevoke,        str_signal_clicked,       G_CALLBACK( button_ServerRevoke        ), NULL );
    g_signal_connect( comboboxtext_serverkeysize, str_signal_changed,       G_CALLBACK( changed_ServerKeySize      ), NULL );
    g_signal_connect( spinbutton_serverdays,      str_signal_value_changed, G_CALLBACK( changed_ServerDays         ), NULL );
    // - for the clients tab
    g_signal_connect( button_clientnew,           str_signal_clicked,       G_CALLBACK( button_ClientNew           ), NULL );
    g_signal_connect( entry_clientname,           str_signal_changed,       G_CALLBACK( changed_ClientName         ), NULL );
    g_signal_connect( entry_clientsurname,        str_signal_changed,       G_CALLBACK( changed_ClientSurname      ), NULL );
    g_signal_connect( entry_clientemail,          str_signal_changed,       G_CALLBACK( changed_ClientEmail        ), NULL );
    g_signal_connect( entry_clientlogin,          str_signal_changed,       G_CALLBACK( changed_ClientLogin        ), NULL );
    g_signal_connect( entry_clientpassword,       str_signal_changed,       G_CALLBACK( changed_ClientPassword     ), NULL );
    g_signal_connect( comboboxtext_clientkeysize, str_signal_changed,       G_CALLBACK( changed_ClientKeySize      ), NULL );
    g_signal_connect( button_clientkey,           str_signal_clicked,       G_CALLBACK( button_ClientNewPrivateKey ), NULL );
    g_signal_connect( combobox_clientlist,        str_signal_changed,       G_CALLBACK( changed_ClientList         ), NULL );
    g_signal_connect( button_clientreq,           str_signal_clicked,       G_CALLBACK( button_ClientNewReq        ), NULL );
    g_signal_connect( button_clientsign,          str_signal_clicked,       G_CALLBACK( button_ClientSign          ), NULL );
    g_signal_connect( spinbutton_clientdays,      str_signal_value_changed, G_CALLBACK( changed_ClientDays         ), NULL );
    g_signal_connect( button_clientrevoke,        str_signal_clicked,       G_CALLBACK( button_ClientRevoke        ), NULL );
    g_signal_connect( button_clientdelete,        str_signal_clicked,       G_CALLBACK( button_ClientDelete        ), NULL );
    // - for the upload tab
    g_signal_connect( button_upload,              str_signal_clicked,       G_CALLBACK( button_UploadCerts         ), NULL );

    // Populate the client list combo box
    fill_client_liststore_combobox( client_list );

    // Enable/disable widgets according to the certificates state
    widget_is_sensitive();

    // The css provider is no longer needed
    g_object_unref( G_OBJECT( css_provider ) );

    // The builder is no longer needed
    g_object_unref( G_OBJECT( builder ) );

    // Show the main-window
    gtk_widget_show( window );
  }

  // Enter the gtk main loop
  gtk_main();

  return 0;
}

