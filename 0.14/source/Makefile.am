# opengalaxy - a SIA receiver for Galaxy security control panels.
# Copyright (C) 2015, Alexander Bruines <alexander.bruines@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# as published by the Free Software Foundation, or (at your option)
# any later version.
#
# In addition, as a special exception, the author of this program
# gives permission to link the code of its release with the OpenSSL
# project's "OpenSSL" library (or with modified versions of it that
# use the same license as the "OpenSSL" library), and distribute the
# linked executables. You must obey the GNU General Public License
# in all respects for all of the code used other than "OpenSSL".
# If you modify this file, you may extend this exception to your
# version of the file, but you are not obligated to do so.
# If you do not wish to do so, delete this exception statement
# from your version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

OPENSSL_SOURCE = --branch=OpenSSL_1_0_2-stable https://github.com/openssl/openssl.git
OPENSSL_DIR = openssl

# source when installing from tar.gz
WEBSOCKETS_SOURCE_FILE = $(srcdir)/external-libs/libwebsockets.tar.gz
# If the above is left empty then we clone from github
WEBSOCKETS_SOURCE = --branch=master https://github.com/warmcat/libwebsockets.git
WEBSOCKETS_COMMIT = 57bb922f5617a054005c5ca4c64372dea8a73b23
WEBSOCKETS_DIR = libwebsockets

###
### List of glade XML files to be included with libgtkdata.a
###
GLADE_FILES = \
 src/glade/ca_main_window.glade \
 src/glade/ca_connect_dialog.glade \
 src/glade/ca_privileges_dialog.glade \
 src/glade/ca_zones_privileges_dialog.glade \
 src/glade/ca_upload_info.glade \
 src/glade/popen_window.glade \
 src/glade/error_dialog.glade \
 src/glade/ca_password_dialog.glade \
 src/glade/client_main_window.glade \
 src/glade/client_area_images.glade \
 src/glade/client_connect_dialog.glade \
 src/glade/client_password_dialog.glade \
 src/glade/info_dialog.glade

###
### List of CSS files to be included with libgtkdata.a
###
CSS_FILES = \
 src/glade/ca_gtk.css \
 src/glade/client_gtk.css

###
###  List of source files required to build the convenience library
###  with common functions.
###
OPENGALAXY_COMMON_SOURCE = \
 src/common/atomic.h \
 src/common/strtok_r.c       src/common/strtok_r.h \
 src/common/json.c           src/common/json.h \
 src/common/ssl_evp.c        src/common/ssl_evp.h \
 src/common/credentials.c    src/common/credentials.h \
 src/common/tmalloc.cpp      src/common/tmalloc.hpp


###
###  List of source files required for the server application
###

OPENGALAXY_SERVER_LLIBS = src/libcommon.a
OPENGALAXY_SERVER_SOURCE = \
 src/server/context_options.hpp \
 src/server/session_id.hpp \
 src/server/Array.hpp \
 src/server/opengalaxy.cpp          src/server/opengalaxy.hpp \
 src/server/Syslog.cpp              src/server/Syslog.hpp \
 src/server/Signal.cpp              src/server/Signal.hpp \
 src/server/Settings.cpp            src/server/Settings.hpp \
 src/server/Serial.cpp              src/server/Serial.hpp \
 src/server/Siablock.cpp            src/server/Siablock.hpp \
 src/server/SiaEvent.hpp \
 src/server/Sia.cpp                 src/server/Sia.hpp \
 src/server/Receiver.cpp            src/server/Receiver.hpp \
 src/server/Galaxy.cpp              src/server/Galaxy.hpp \
 src/server/Poll.cpp                src/server/Poll.hpp \
 src/server/Websocket.cpp           src/server/Websocket.hpp \
 src/server/Websocket-Http.cpp \
 src/server/Websocket-Ssl.cpp \
 src/server/Session.cpp             src/server/Session.hpp \
 src/server/Commander.cpp           src/server/Commander.hpp \
 src/server/Output.cpp              src/server/Output.hpp \
 src/server/Certificates.cpp        src/server/Certificates.hpp \
 src/server/main.cpp
if HAVE_EMAIL_PLUGIN
 OPENGALAXY_SERVER_SOURCE += src/server/Output-Email.cpp src/server/Output-Email.hpp
endif
if HAVE_MYSQL_PLUGIN
 OPENGALAXY_SERVER_SOURCE += src/server/Output-Mysql.cpp src/server/Output-Mysql.hpp
endif
if HAVE_FILE_PLUGIN
 OPENGALAXY_SERVER_SOURCE += src/server/Output-Text.cpp src/server/Output-Text.hpp
endif
if HAVE_WINDOWS
 OPENGALAXY_SERVER_SOURCE_NODIST = src/server/win-resource.rc
endif

OPENGALAXY_SERVER_WWW_FILES = \
 $(srcdir)/src/www/opengalaxy.css \
 $(srcdir)/src/www/opengalaxy.js \
 $(builddir)/src/www/index.html \
 $(srcdir)/src/www/tiles.png \
 $(srcdir)/src/www/RIO.png \
 $(srcdir)/src/www/favicon.ico

OPENGALAXY_SERVER_WWW_JQUERY_FILES = \
 $(srcdir)/src/www/external/jquery/jquery-2.2.3.js \
 $(srcdir)/src/www/external/jquery/jquery-2.2.3.min.js

OPENGALAXY_SERVER_WWW_JQUERYUI_FILES = \
 $(srcdir)/src/www/external/jquery-ui/index.html \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.css \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.js \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.min.css \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.min.js \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.structure.css \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.structure.min.css \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.theme.css \
 $(srcdir)/src/www/external/jquery-ui/jquery-ui.theme.min.css

OPENGALAXY_SERVER_WWW_JQUERYUI_IMAGES = \
 $(srcdir)/src/www/external/jquery-ui/images/ui-bg_glass_55_fbf9ee_1x400.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-bg_glass_65_ffffff_1x400.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-bg_glass_75_dadada_1x400.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-bg_glass_75_e6e6e6_1x400.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-bg_glass_95_fef1ec_1x400.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-bg_highlight-soft_75_cccccc_1x100.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-icons_222222_256x240.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-icons_2e83ff_256x240.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-icons_454545_256x240.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-icons_888888_256x240.png \
 $(srcdir)/src/www/external/jquery-ui/images/ui-icons_cd0a0a_256x240.png

###
### List of source files required to build the client application
###

if HAVE_EXTRAS
OPENGALAXY_CLIENT_LLIBS = src/libcommon.a src/libgtkdata.a
OPENGALAXY_CLIENT_SOURCE = \
 src/client/json-decode.c       src/client/json-decode.h \
 src/client/opengalaxy-client.c src/client/opengalaxy-client.h \
 src/client/websocket.c         src/client/websocket.h \
 src/client/log.c               src/client/log.h \
 src/client/commander.c         src/client/commander.h \
 src/client/broadcast.c         src/client/broadcast.h \
 src/client/support.c           src/client/support.h \
 src/client/connect.c           src/client/connect.h \
 src/client/areas.c             src/client/areas.h
if HAVE_WINDOWS
 OPENGALAXY_CLIENT_SOURCE_NODIST = src/client/win-resource.rc
endif
endif

###
###  List of source files required for the certificate management application
###

if HAVE_EXTRAS
OPENGALAXY_CA_LLIBS = src/libcommon.a src/libgtkdata.a
OPENGALAXY_CA_SOURCE = \
 src/ca/opengalaxy-ca.c \
 src/ca/support.c           src/ca/support.h \
 src/ca/websocket.c         src/ca/websocket.h \
 src/ca/upload.c \
 src/ca/certs_pkg.c
if HAVE_WINDOWS
 OPENGALAXY_CA_SOURCE_NODIST = src/ca/win-resource.rc
endif
endif

###
### Extra files to include with the 'dist' target
###

EXTRA_DIST = \
 doc/openGalaxy_Certificate_Manager.pdf \
 $(GLADE_FILES) $(CSS_FILES) \
 README COPYING changelog README-MSYS2.TXT README-BUILDING API.TXT README.QUICKSTART README-RaspberryPi\
 external-libs example src/www \
 src/config/CreateDatabase.sql src/config/CreateUser.sql \
 src/ca/passphrase.txt  \
 mingw-build debian build-debs

###
### List of PDF documents created from man pages
###

PDF_FILES = \
  $(builddir)/galaxy.conf.pdf \
  $(builddir)/opengalaxy.pdf \
  $(builddir)/opengalaxy-ca.pdf \
  $(builddir)/opengalaxy-client.pdf

###
### Manual pages we are installing
###
man8_MANS = $(builddir)/src/server/opengalaxy.man $(builddir)/src/ca/opengalaxy-ca.man
man1_MANS = $(builddir)/src/client/opengalaxy-client.man
man5_MANS = $(builddir)/src/server/galaxy.conf.man

##############################################################################
##############################################################################
##############################################################################

ACLOCAL_AMFLAGS = -I m4 --install

SUFFIXES = .glade .css .rc .pdf .man

vpath %.glade $(srcdir)/src/glade
vpath %.css $(srcdir)/src/glade
vpath %.man $(builddir)/src/ca $(builddir)/src/client $(builddir)/src/server

# _INSTALL_DIR_ is used by: client/support.c
# _CONFIG_DIR_  is used by: server/Settings.cpp ca/opengalaxy-ca.c client/support.c
# _WWW_DIR_     is used by: server/Settings.cpp client/support.c
# _CERT_DIR_    is used by: server/Settings.cpp ca/opengalaxy-ca.c client/support.c
# _SHARE_DIR_   is used by: ca/opengalaxy-ca.c client/support.c
# _LOG_DIR_     is used by: server/Settings.cpp server/main.cpp
#
# These are used to hardcode paths into opengalaxy
# On windows we use these as template (combined with the current working directory) or not at all (using the registry instead)
# On Linux we adhere to autoconf rules, using the directories set by the configure script
if HAVE_WINDOWS
 AM_CPPFLAGS = \
  -D_INSTALL_DIR_=\"\" \
  -D_CONFIG_DIR_=\"\" \
  -D_WWW_DIR_=\"www\" \
  -D_CERT_DIR_=\"ssl\" \
  -D_SHARE_DIR_=\"\" \
  -D_LOG_DIR_=\"\"
else
 AM_CPPFLAGS = \
 -D_INSTALL_DIR_=\"$(bindir)\" \
 -D_CONFIG_DIR_=\"$(sysconfdir)/galaxy\" \
 -D_WWW_DIR_=\"$(datadir)/galaxy/www\" \
 -D_CERT_DIR_=\"$(datadir)/galaxy/ssl\" \
 -D_SHARE_DIR_=\"$(datadir)/galaxy\" \
 -D_LOG_DIR_=\"$(localstatedir)/log/galaxy\"
endif


###
### Targets that need to be realized before the main build of openGalaxy
###
BUILT_SOURCES =
CLEANFILES =
###
### This triggers OpenSSL to be build from source,
### but only if we are not using the libraries the system provides.
###
if HAVE_OPENSSL
if ! HAVE_SYSTEM_OPENSSL
BUILT_SOURCES += $(builddir)/lib/usr/lib/libssl.a
BUILT_SOURCES += $(builddir)/lib/usr/lib/libcrypto.a
BUILT_SOURCES += $(builddir)/lib/usr/bin/openssl
endif
endif
###
### Build libwebsockets
###
BUILT_SOURCES += $(builddir)/lib/usr/lib/libwebsockets.a
###
### Bake .c and .h files from the Glade and CSS data files found in src/glade
### and put the in the libgtkdata.a library
###
if HAVE_EXTRAS
BUILT_SOURCES += $(GLADE_C_FILES) $(GLADE_H_FILES) $(CSS_C_FILES) $(CSS_H_FILES) $(builddir)/src/libgtkdata.a
CLEANFILES += $(GLADE_C_FILES) $(GLADE_H_FILES) $(GLADE_O_FILES) $(CSS_C_FILES) $(CSS_H_FILES) $(CSS_O_FILES) $(builddir)/src/libgtkdata.a
endif
###
### Convert the man pages to PDF on Windows
###
if HAVE_WINDOWS
BUILT_SOURCES += $(PDF_FILES)
CLEANFILES += $(PDF_FILES)
endif

###
### The convenience libraries we want to build
###
noinst_LIBRARIES = src/libcommon.a

###
### The openGalaxy targets
###
bin_PROGRAMS = src/server/opengalaxy$(EXEEXT)
if HAVE_EXTRAS
if ! HAVE_NO_SSL
bin_PROGRAMS += src/ca/opengalaxy-ca$(EXEEXT)
endif
bin_PROGRAMS += src/client/opengalaxy-client$(EXEEXT)
endif

###
###  The rules required to build the convenience library
###  with the glade and css data for the GTK gui.
###
if HAVE_EXTRAS
GLADE_H_FILES = $(foreach glade,$(patsubst %.glade,%.h,$(GLADE_FILES)),$(builddir)/$(glade))
GLADE_C_FILES = $(foreach glade,$(patsubst %.glade,%.c,$(GLADE_FILES)),$(builddir)/$(glade))
GLADE_O_FILES = $(foreach glade,$(patsubst %.glade,%.o,$(GLADE_FILES)),$(builddir)/$(glade))
CSS_H_FILES = $(foreach css,$(patsubst %.css,%.h,$(CSS_FILES)),$(builddir)/$(css))
CSS_C_FILES = $(foreach css,$(patsubst %.css,%.c,$(CSS_FILES)),$(builddir)/$(css))
CSS_O_FILES = $(foreach css,$(patsubst %.css,%.o,$(CSS_FILES)),$(builddir)/$(css))
$(builddir)/src/libgtkdata.a: $(GLADE_O_FILES) $(CSS_O_FILES)
	@echo "  AR       $@"
	@rm -f $@
	@ar cru $@ $^
	@ranlib $@
$(builddir)/src/glade/%.o: $(builddir)/src/glade/%.c
	@echo "  CC       $@"
	@$(CC) -c -o $@ $<
$(builddir)/src/glade/%.c: %.glade
	@echo "  XXD      $@"
	@$(XXD) -i $< | $(SED) "s/.[^ ]*\($(notdir $(basename $<))\)/ \1/g;s/unsigned char/const unsigned char/g;s/unsigned int/const unsigned int/g" >$@
$(builddir)/src/glade/%.c: %.css
	@echo "  XXD      $@"
	@$(XXD) -i $< | $(SED) "s/.[^ ]*\($(notdir $(basename $<))\)/ \1/g;s/unsigned char/const unsigned char/g;s/unsigned int/const unsigned int/g" >$@
$(builddir)/src/glade/%.h: $(builddir)/src/glade/%.c
	@echo "  C2H      $@"
	@echo "#ifndef __$(notdir $(basename $<))_xxd_h__" >$@
	@echo "#define __$(notdir $(basename $<))_xxd_h__" >>$@
	@head -n1 $< | awk '{print "extern "$$1" "$$2" "$$3" "$$4";"}' >>$@
	@tail -n1 $< | awk '{print "extern "$$1" "$$2" "$$3" "$$4";"}' >>$@
	@echo "#endif" >>$@
endif

###
### Autotools targets
###

### The common library
src_libcommon_a_SOURCES = $(OPENGALAXY_COMMON_SOURCE)

### The server application
src_server_opengalaxy_SOURCES = $(OPENGALAXY_SERVER_SOURCE)
if HAVE_WINDOWS
nodist_src_server_opengalaxy_SOURCES = $(OPENGALAXY_SERVER_SOURCE_NODIST)
endif
opengalaxy_confdir = $(sysconfdir)/galaxy
opengalaxy_conf_DATA = $(builddir)/src/config/galaxy.conf
opengalaxy_conf_DATA += $(srcdir)/src/config/CreateDatabase.sql
opengalaxy_conf_DATA += $(srcdir)/src/config/CreateUser.sql
if HAVE_EMAIL_PLUGIN
 opengalaxy_conf_DATA += $(builddir)/src/config/ssmtp.conf
endif

### The WWW files
# (www root directory)
if HAVE_WINDOWS
opengalaxy_wwwdir = $(datadir)/www
else
opengalaxy_wwwdir = $(datadir)/galaxy/www
endif
opengalaxy_www_DATA = $(OPENGALAXY_SERVER_WWW_FILES)
# (external directory)
if HAVE_WINDOWS
opengalaxy_www_externalsdir = $(datadir)/www/external
else
opengalaxy_www_externalsdir = $(datadir)/galaxy/www/external
endif
opengalaxy_www_externals_DATA =
# (jquery directory)
if HAVE_WINDOWS
opengalaxy_www_jquerydir = $(datadir)/www/external/jquery
else
opengalaxy_www_jquerydir = $(datadir)/galaxy/www/external/jquery
endif
opengalaxy_www_jquery_DATA = $(OPENGALAXY_SERVER_WWW_JQUERY_FILES)
# (jquery-ui directory)
if HAVE_WINDOWS
opengalaxy_www_jqueryuidir = $(datadir)/www/external/jquery-ui
else
opengalaxy_www_jqueryuidir = $(datadir)/galaxy/www/external/jquery-ui
endif
opengalaxy_www_jqueryui_DATA = $(OPENGALAXY_SERVER_WWW_JQUERYUI_FILES)
# smoothness theme images (jquery-ui/images directory)
if HAVE_WINDOWS
opengalaxy_www_jqueryui_imagesdir = $(datadir)/www/external/jquery-ui/images
else
opengalaxy_www_jqueryui_imagesdir = $(datadir)/galaxy/www/external/jquery-ui/images
endif
opengalaxy_www_jqueryui_images_DATA = $(OPENGALAXY_SERVER_WWW_JQUERYUI_IMAGES)

if HAVE_EXTRAS

src_ca_opengalaxy_ca_shareddir = $(datadir)/galaxy
src_ca_opengalaxy_ca_shared_DATA = $(srcdir)/src/ca/passphrase.txt
src_ca_opengalaxy_ca_SOURCES = $(OPENGALAXY_CA_SOURCE)
if HAVE_WINDOWS
nodist_src_ca_opengalaxy_ca_SOURCES = $(OPENGALAXY_CA_SOURCE_NODIST)
endif

src_client_opengalaxy_client_SOURCES = $(OPENGALAXY_CLIENT_SOURCE)
if HAVE_WINDOWS
nodist_src_client_opengalaxy_client_SOURCES = $(OPENGALAXY_CLIENT_SOURCE_NODIST)
endif

endif

###
### This section builds the openSSL library
###

OPENSSL_CONF_ARGS = --prefix=`readlink -f ../$(builddir)`/lib/usr
OPENSSL_CONF_ARGS += no-shared no-idea no-mdc2 no-rc5 no-zlib no-zlib-dynamic enable-tlsext no-ssl2 no-ssl3 enable-ec enable-ecdh enable-ecp
OPENSSL_CONF_ARGS64 = $(OPENSSL_CONF_ARGS) enable-ec_nistp_64_gcc_128

if DEBUG
OPENSSL_DEBUG = "debug-"
else
endif

$(builddir)/lib/usr/lib/libssl.a $(builddir)/lib/usr/lib/libcrypto.a $(builddir)/lib/usr/bin/openssl$(EXEEXT): openssl.configured

$(OPENSSL_DIR):
	git clone $(OPENSSL_SOURCE)

#$(OPENSSL_DIR): $(OPENSSL_SOURCE)
#	@tar xf $(OPENSSL_SOURCE)

openssl.configured: $(OPENSSL_DIR)
	-@cd $(OPENSSL_DIR) && rm -f Makefile
if HAVE_WINDOWS
if HAVE_AMD64_CPU
	@cd $(OPENSSL_DIR) && ./Configure $(OPENSSL_DEBUG)mingw64 $(OPENSSL_CONF_ARGS64)
else
	@cd $(OPENSSL_DIR) && ./Configure $(OPENSSL_DEBUG)mingw $(OPENSSL_CONF_ARGS)
endif
else
if HAVE_X86_CPU
if HAVE_AMD64_CPU
	@cd $(OPENSSL_DIR) && ./Configure $(OPENSSL_DEBUG)linux-x86_64 $(OPENSSL_CONF_ARGS64)
else
	@cd $(OPENSSL_DIR) && ./Configure $(OPENSSL_DEBUG)linux-x32 $(OPENSSL_CONF_ARGS)
endif
else
	@cd $(OPENSSL_DIR) && ./config $(OPENSSL_CONF_ARGS)
endif
endif
if ! HAVE_WINDOWS
	@cd $(OPENSSL_DIR) && $(SED) -i  's/CFLAG= /CFLAG= -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE=1 -fstack-protector-strong -fPIE /g' Makefile
endif
	@cd $(OPENSSL_DIR) && make depend
	@cd $(OPENSSL_DIR) && make build_libs build_apps build_tools
	@cd $(OPENSSL_DIR) && make install_sw
	@touch openssl.configured

###
### This sections builds libwebsockets
###

WEBSOCKETS_SSL_DEPS =
if ! HAVE_NO_SSL
if ! HAVE_SYSTEM_OPENSSL
WEBSOCKETS_SSL_DEPS += $(builddir)/lib/usr/lib/libssl.a $(builddir)/lib/usr/lib/libcrypto.a
endif
endif

WEBSOCKETS_CMAKE_ARGS = \
  -DCMAKE_C_FLAGS="$(EXPORT_CPPFLAGS) $(EXPORT_CFLAGS)" \
  -DCMAKE_INSTALL_PREFIX=`readlink -f ../../$(builddir)`/lib/usr \
  -DLWS_WITH_SHARED=OFF \
  -DLWS_WITH_STATIC=ON \
  -DLWS_WITHOUT_DAEMONIZE=ON \
  -DLWS_WITHOUT_TESTAPPS=ON \
  -DLWS_IPV6=OFF \
  -DLWS_USE_BUNDLED_ZLIB=OFF

if HAVE_SYSTEM_OPENSSL
WEBSOCKETS_CMAKE_ARGS += \
  -DLWS_WITH_SSL=ON  \
  -DLWS_WITH_HTTP2=OFF \
  -DLWS_HAVE_OPENSSL_ECDH_H=1 \
  -DLWS_SSL_CLIENT_USE_OS_CA_CERTS=OFF \
  -DLWS_SSL_SERVER_WITH_ECDH_CERT=1
else
WEBSOCKETS_CMAKE_ARGS += \
  -DLWS_WITH_SSL=ON  \
  -DLWS_WITH_HTTP2=OFF \
  -DLWS_HAVE_OPENSSL_ECDH_H=1 \
  -DLWS_SSL_CLIENT_USE_OS_CA_CERTS=OFF \
  -DLWS_SSL_SERVER_WITH_ECDH_CERT=1 \
  -DLWS_HAVE_SSL_CTX_set1_param=1 \
  -DLWS_OPENSSL_LIBRARIES="$(OPENSSL_LIBRARY_DIR)/libssl.a;$(OPENSSL_LIBRARY_DIR)/libcrypto.a" \
  -DLWS_OPENSSL_INCLUDE_DIRS=$(OPENSSL_INCLUDE_DIR)
endif

if DEBUG
WEBSOCKETS_CMAKE_ARGS += \
  -DCMAKE_BUILD_TYPE=Debug
else
WEBSOCKETS_CMAKE_ARGS += \
  -DCMAKE_BUILD_TYPE=Release
endif
if HAVE_WINDOWS
WEBSOCKETS_CMAKE_ARGS += \
   -G 'MSYS Makefiles'
endif

$(WEBSOCKETS_DIR):
	[ "x$(WEBSOCKETS_SOURCE_FILE)" == "x" ] && git clone $(WEBSOCKETS_SOURCE) || tar xf $(WEBSOCKETS_SOURCE_FILE)
	if [ "x$(WEBSOCKETS_SOURCE_FILE)" == "x" ]; then \
	 if [ "x$(WEBSOCKETS_COMMIT)" != "x" ]; then \
	  cd $(WEBSOCKETS_DIR) && git reset --hard $(WEBSOCKETS_COMMIT); \
	 fi; \
	fi
	cd $(WEBSOCKETS_DIR) && patch -p1 < ../$(srcdir)/external-libs/lws_get_ssl-master.patch
if HAVE_WINDOWS
	-cd $(WEBSOCKETS_DIR) && patch -p1 < ../$(srcdir)/external-libs/lws_msys2.patch
endif

#$(WEBSOCKETS_DIR): $(WEBSOCKETS_SOURCE)
#	tar xf $(WEBSOCKETS_SOURCE)
#	cd $(WEBSOCKETS_DIR) && patch -p1 < ../$(srcdir)/external-libs/lws_get_ssl-master.patch

websockets.configured: $(WEBSOCKETS_DIR) $(WEBSOCKETS_SSL_DEPS)
	-cd $(WEBSOCKETS_DIR) && mkdir build
	cd $(WEBSOCKETS_DIR)/build && cmake $(WEBSOCKETS_CMAKE_ARGS) ..
	touch websockets.configured

$(builddir)/lib/usr/lib/libwebsockets.a: websockets.configured
	cd $(WEBSOCKETS_DIR)/build && $(MAKE) && $(MAKE) install

###
### Utility rules
###

maintainer-clean-local:
	-rm -f aclocal.m4 Makefile.in config.h.in configure config.guess config.sub depcomp install-sh missing src/Makefile.in config.h.in~ compile

distclean-local:
if HAVE_OPENSSL
if ! HAVE_SYSTEM_OPENSSL
	-rm -fR lib openssl.configured $(OPENSSL_DIR)
endif
endif
	-rm -fR websockets.configured libwebsockets

clean-local:
#if HAVE_OPENSSL
#if ! HAVE_SYSTEM_OPENSSL
#	-cd $(OPENSSL_DIR) && $(MAKE) clean
#endif
#endif
#	-cd libwebsockets/build && $(MAKE) clean
#	-rm -f lib/usr/lib/libwebsockets* lib/usr/include/libwebsockets.h lib/usr/include/lws_config.h lib/usr/bin/libwebsockets*


###
### Resource compiler (windows)
###
if HAVE_WINDOWS
.rc.o:
	@echo -e "  RC       $@"
	@$(RC) -i $< $@
endif


###
### This target generates '.pdf' documents from man pages found in 'vpath %.man'
###
.man.pdf:
	@echo -e "  PS2PDF    $@"
	@man -t $< | ps2pdf - $@


###
### Hook to the install-data target to build the windows (NSIS) installer
###
username = `id -u`
if HAVE_WINDOWS
if HAVE_AMD64_CPU
INSTALLER_ARCH=Win64
NSIS_ARGS=-DARCH=x64 -DOUTFILE_ARCH=$(INSTALLER_ARCH)
else
INSTALLER_ARCH=Win32
NSIS_ARGS=-DARCH=x32 -DOUTFILE_ARCH=$(INSTALLER_ARCH)
endif
endif
install-data-hook:
	@# 
if HAVE_WINDOWS
	@# 
	@# Windows only installation tasks (creates NSIS installer package)
	@# 
if HAVE_MYSQL
	@# 
	@# Copy the libmysql DLL to the installation directory
	@# 
	$(INSTALL) "$(libmysqlclient_dir)/lib/libmysql.dll" "$(bindir)"
	$(INSTALL) "$(libmysqlclient_dir)/README" "$(bindir)/README.MySQL.txt"
endif
	@# 
	@# Copy the readme files to the installation directory
	@# 
	$(INSTALL) $(srcdir)/README $(bindir)/README.txt
	$(INSTALL) $(srcdir)/README.QUICKSTART $(bindir)/README.1ST.txt
	$(INSTALL) $(srcdir)/changelog $(bindir)/changelog.txt
	$(INSTALL) $(srcdir)/COPYING $(bindir)/COPYING.txt
	$(INSTALL) $(srcdir)/API.TXT $(bindir)/API.TXT
	$(INSTALL) $(builddir)/galaxy.conf.pdf $(bindir)/galaxy.conf.pdf
	$(INSTALL) $(builddir)/opengalaxy.pdf $(bindir)/opengalaxy.pdf
	$(INSTALL) $(srcdir)/doc/openGalaxy_Certificate_Manager.pdf "$(bindir)/openGalaxy Certificate Manager.pdf"
	$(INSTALL) $(builddir)/opengalaxy-client.pdf $(bindir)/opengalaxy-client.pdf
	@# 
	@# Convert some textfiles to DOS cr/lf format
	@# 
	$(SED) -i 's/$$/\r/' $(sysconfdir)/galaxy/galaxy.conf
if HAVE_MYSQL
	$(SED) -i 's/$$/\r/' $(bindir)/README.MySQL.txt
endif
	$(SED) -i 's/$$/\r/' $(bindir)/README.txt
	$(SED) -i 's/$$/\r/' $(bindir)/changelog.txt
	$(SED) -i 's/$$/\r/' $(bindir)/COPYING.txt
	$(SED) -i 's/$$/\r/' $(bindir)/README.1ST.txt
	$(SED) -i 's/$$/\r/' $(bindir)/galaxy/CreateDatabase.sql
	$(SED) -i 's/$$/\r/' $(bindir)/galaxy/CreateUser.sql
	$(SED) -i 's/$$/\r/' $(bindir)/API.TXT
	@# 
	@# Install the DLLs required for a standalone package
	@# 
	@#  ---------- GCC shared runtime. ---------- 
	-$(INSTALL) "`find $(MINGW_DIR) -name 'libgcc_s_dw2-*.dll' -print -quit`" "$(bindir)"
	-$(INSTALL) "`find $(MINGW_DIR) -name 'libgcc_s_seh-*.dll' -print -quit`" "$(bindir)"
	@# 
	@#  ---------- Pthreads shared runtime. ---------- 
	$(INSTALL) "`find $(MINGW_DIR) -name 'libwinpthread-1.dll' -print -quit`" "$(bindir)"
	@# 
	@#  ---------- C++ shared runtime. ---------- 
	$(INSTALL) "`find $(MINGW_DIR) -name 'libstdc++-*.dll' -print -quit`" "$(bindir)"
	@# 
	@#  ---------- SSP runtime. ---------- 
	$(INSTALL) "`find $(MINGW_DIR) -name 'libssp-*.dll' -print -quit`" "$(bindir)"
	@# 
	@#  ---------- GTK+ required libraries ---------- 
	@# 
	@# Epoxy is a library for handling OpenGL function pointer management
	$(INSTALL) "`find $(MINGW_DIR) -name 'libepoxy-*.dll' -print -quit`" "$(bindir)"
	@# Accessibility Toolkit runtime. Interface used by accessibility functions
	@# like high-contrast visual themes and keyboard modifiers.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libatk-*.dll' -print -quit`" "$(bindir)"
	@# Cairo runtime. Used internally by GDK-Pixbuf to draw surfaces.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libcairo-*.dll' -print -quit`" "$(bindir)"
	@# Cairo GObject binding runtime.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libcairo-go*.dll' -print -quit`" "$(bindir)"
	@# XML parser library runtime.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libexpat-*.dll' -print -quit`" "$(bindir)"
	@# LibFFI runtime. Bridge between interpreted and compiled code.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libffi-*.dll' -print -quit`" "$(bindir)"
	@# Fontconfig runtime. Font sets detection.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libfontconfig-*.dll' -print -quit`" "$(bindir)"
	@# FreeType runtime. Portable font engine.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libfreetype-*.dll' -print -quit`" "$(bindir)"
	@# GIMP Drawing Kit. Wraps low-level drawing and windowing functions
	$(INSTALL) "`find $(MINGW_DIR) -name 'libgdk-3-*.dll' -print -quit`" "$(bindir)"
	@# GDK-Pixbuf runtime. Image loading and pixel buffer manipulation.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libgdk_pixbuf-2.0-*.dll' -print -quit`" "$(bindir)"
	@# GIO runtime. Filesystem operations abstraction layer
	$(INSTALL) "`find $(MINGW_DIR) -name 'libgio-2.0-*.dll' -print -quit`" "$(bindir)"
	@# General-use abstraction layer between the software and the underlying OS.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libglib-2.0-*.dll' -print -quit`" "$(bindir)"
	@# GModule runtime. Provides GLib with dynamic module loading.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libgmodule-2.0-*.dll' -print -quit`" "$(bindir)"
	@# GObject runtime. Provides GLib with OOP functions.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libgobject-2.0-*.dll' -print -quit`" "$(bindir)"
	@# GTK+3 runtime. GIMP Toolkit.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libgtk-3-*.dll' -print -quit`" "$(bindir)"
	@# Iconv runtime. Text conversion between Unicode and traditional encoding.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libiconv-2.dll' -print -quit`" "$(bindir)"
	@# Gettext Internationalization runtime.
	@# Allows on-the-fly translation of text using locale files.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libintl-8.dll' -print -quit`" "$(bindir)"
	@# Pango runtime. Internationalized text rendering.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libpango-1.0-*.dll' -print -quit`" "$(bindir)"
	@# Pango Cairo runtime. Render text onto Cairo surfaces.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libpangocairo-1.0-*.dll' -print -quit`" "$(bindir)"
	@# Pango FreeType runtime.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libpangoft2-1.0-*.dll' -print -quit`" "$(bindir)"
	@# Pango Win32 runtime.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libpangowin32-1.0-*.dll' -print -quit`" "$(bindir)"
	@# Pixman runtime. Required by Cairo.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libpixman-1-*.dll' -print -quit`" "$(bindir)"
	@# LibPNG runtime. Renders PNG images.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libpng16-*.dll' -print -quit`" "$(bindir)"
	@# libz2 runtime. BZ2 compression support.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libbz2-*.dll' -print -quit`" "$(bindir)"
	@# zlib runtime. GZIP compression support.
	$(INSTALL) "`find $(MINGW_DIR) -name 'zlib1.dll' -print -quit`" "$(bindir)"
	@# Harfbuzz runtime. OpenType text shaping engine
	$(INSTALL) "`find $(MINGW_DIR) -name 'libharfbuzz-*.dll' -print -quit`" "$(bindir)"
	@# XML parser library runtime.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libxml2-*.dll' -print -quit`" "$(bindir)"
	@# PCRE runtime.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libpcre-*.dll' -print -quit`" "$(bindir)"
	@# Graphite2 runtime
	$(INSTALL) "`find $(MINGW_DIR) -name 'libgraphite*.dll' -print -quit`" "$(bindir)"
	@# 
	@# ---------- GTK+ optional libraries ---------- 
	@# 
	@# Cairo Script interpreter.
	-$(INSTALL) "`find $(MINGW_DIR) -name 'libcairo-script-interpreter-*.dll' -print -quit`" "$(bindir)"
	@# GTK+ Accessibility Implementation Library Utilities runtime.
	-$(INSTALL) "`find $(MINGW_DIR) -name 'libgailutil-3-*.dll' -print -quit`" "$(bindir)"
	@# GThread runtime. Provides GLib with thread management.
	-$(INSTALL) "`find $(MINGW_DIR) -name 'libgthread-2.0-*.dll' -print -quit`" "$(bindir)"
	@# JPEG-2000 runtime. Renders JPEG-2000 images.
	-$(INSTALL) "`find $(MINGW_DIR) -name 'libjpasper-*.dll' -print -quit`" "$(bindir)"
	@# LibJPEG runtime. Renders classic JPEG images.
	-$(INSTALL) "`find $(MINGW_DIR) -name 'libjpeg-*.dll' -print -quit`" "$(bindir)"
	@# 
	@# ---------- GTK+ - SVG support ---------- 
	@# 
	@# CSS2 Parsing library runtime. SVG support.
	$(INSTALL) "`find $(MINGW_DIR) -name 'libcroco-0.6-*.dll' -print -quit`" "$(bindir)"
	@# LibLZMA runtime. LZMA and XZ compression support. SVG support.
	$(INSTALL) "`find $(MINGW_DIR) -name 'liblzma-*.dll' -print -quit`" "$(bindir)"
	@# SVG runtime. Renders SVG images. SVG support.
	$(INSTALL) "`find $(MINGW_DIR) -name 'librsvg-2-*.dll' -print -quit`" "$(bindir)"
	@# 
	@# ---------- Install the openssl executable ---------- 
	@# 
	-$(INSTALL) "$(builddir)/lib/usr/bin/openssl.exe" "$(bindir)"
	@# 
	@# ---------- Install the icon theme we use ---------- 
	@# 
	$(MKDIR_P) $(bindir)/share/icons
	cp -R "$(MINGW_DIR)/share/icons/Adwaita" "$(bindir)/share/icons"
if ! DEBUG
if HAVE_UPX
	@# 
	@# ---------- Compress the executables and DLLs with upx ---------- 
	@# 
	-find $(bindir) ! -name 'libgcc_s_???-*.dll' -name '*.[de][lx][le]' -print0 | xargs -0 upx -9
endif
endif
if HAVE_NSIS
	@# 
	@# Create installation package with NSIS
	@# 
	$(INSTALL) "installer.nsi" "$(bindir)"
	cd $(bindir) && makensis $(NSIS_ARGS) installer.nsi
	mv $(bindir)/opengalaxy-v$(PACKAGE_VERSION)-Installer-$(INSTALLER_ARCH).exe .
endif
else
	@# 
	@# Extra installation tasks for Linux 
	@# 
	$(INSTALL) -D $(srcdir)/doc/openGalaxy_Certificate_Manager.pdf $(DESTDIR)$(datadir)/doc/galaxy/openGalaxy_Certificate_Manager.pdf
if ! HAVE_DEBIAN
	@# 
	@# Add a group staff if none exists
	getent group staff || addgroup staff
endif
	@# 
	@# Set correct owner, group and permission for the shared data directory
	chown $(username):staff "$(DESTDIR)$(src_ca_opengalaxy_ca_shareddir)"
	chmod u-s,u+rwx,g+rwx,g-s,o+rx,o-w "$(DESTDIR)$(src_ca_opengalaxy_ca_shareddir)"
	@# 
	@# Set correct owner, group and permission for the WWW directory
	chown $(username):staff "$(DESTDIR)$(src_ca_opengalaxy_ca_shareddir)/www"
	chmod u-s,u+rwx,g+rx,g-sw,o+rx,o-w "$(DESTDIR)$(src_ca_opengalaxy_ca_shareddir)/www"
	@# 
	@# Set correct owner, group and permission for passphrase.txt
	chown $(username):staff "$(DESTDIR)$(src_ca_opengalaxy_ca_shareddir)/passphrase.txt"
	chmod u+rw,u-x,g+r,g-wx,o-rwx "$(DESTDIR)$(src_ca_opengalaxy_ca_shareddir)/passphrase.txt"
	@# 
	@# Create the output directory for the textfile plugin
	mkdir -p "$(DESTDIR)${localstatedir}/log/galaxy"
	chown $(username):staff "$(DESTDIR)${localstatedir}/log/galaxy"
	chmod u-s,u+rwx,g+rwx,g-s,o+rx,o-w "$(DESTDIR)${localstatedir}/log/galaxy"
	@# 
	@# (Since we can/must build packages when using Debian,
	@# the specifics of menu entries are handled
	@# by the .deb files and not in this Makefile.)
	@# 
if ! HAVE_DEBIAN
	@# 
	@# Install desktop files
	$(INSTALL) -d $(DESTDIR)/usr/share/applications
	$(INSTALL) $(builddir)/src/ca/opengalaxy-ca.desktop $(DESTDIR)/usr/share/applications
	$(INSTALL) $(builddir)/src/server/opengalaxy-server.desktop $(DESTDIR)/usr/share/applications
	$(INSTALL) $(builddir)/src/client/opengalaxy-client.desktop $(DESTDIR)/usr/share/applications
endif
endif


