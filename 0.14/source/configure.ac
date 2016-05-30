dnl  This file is part of openGalaxy.
dnl
dnl  opengalaxy - a SIA receiver for Galaxy security control panels.
dnl  Copyright (C) 2015 - 2016 Alexander Bruines <alexander.bruines@gmail.com>
dnl
dnl  This program is free software: you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License version 2 as
dnl  as published by the Free Software Foundation, or (at your option)
dnl  any later version.
dnl
dnl  In addition, as a special exception, the author of this program
dnl  gives permission to link the code of its release with the OpenSSL
dnl  project's "OpenSSL" library (or with modified versions of it that
dnl  use the same license as the "OpenSSL" library), and distribute the
dnl  linked executables. You must obey the GNU General Public License
dnl  in all respects for all of the code used other than "OpenSSL".
dnl  If you modify this file, you may extend this exception to your
dnl  version of the file, but you are not obligated to do so.
dnl  If you do not wish to do so, delete this exception statement
dnl  from your version.
dnl
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program.  If not, see <http://www.gnu.org/licenses/>.
dnl
AC_PREREQ([2.69])
AC_INIT([opengalaxy], [0.14], [alexander.bruines@gmail.com], [], [http://sourceforge.net/projects/galaxy4linux/])
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz no-dist-gzip])
AC_CONFIG_SRCDIR([src/server/opengalaxy.cpp])
AC_CONFIG_HEADERS([config.h])
AM_SILENT_RULES([yes])
AC_PROG_RANLIB

dnl Include tests downloaded from http://www.gnu.org/software/autoconf-archive/
dnl
m4_include([m4/m4-ax_check_openssl.m4])
m4_include([m4/m4-ax_cxx_compile_stdcxx_11.m4])
m4_include([m4/m4-ax_check_zlib.m4])
m4_include([m4/m4-ax_pthread.m4])
m4_include([m4/m4-ax_lib_mysql.m4])

dnl The following sets CFLAGS/CXXFLAGS to empty if unset on command line. We do not want the default "-g -O2" that AC_PROG_CC sets automatically.
: ${CFLAGS=""}
: ${CXXFLAGS=""}

dnl Define some extra options
dnl

dnl With Email-output-plugin? (default is yes)
AC_ARG_WITH([email-plugin], [AS_HELP_STRING([--with-email-plugin], [Compile the email output plugin (default=yes)])],
  [enable_email_plugin=$withval],
  [enable_email_plugin="yes"]
)
dnl With MySQL-output-plugin? (default is yes)
AC_ARG_WITH([mysql-plugin], [AS_HELP_STRING([--with-mysql-plugin], [Compile the MySQL database output plugin (default=yes)])],
  [enable_mysql_plugin=$withval],
  [enable_mysql_plugin="yes"]
)
dnl With ODBC-output-plugin? (default is no)
enable_odbc_plugin="no"
#AC_ARG_WITH([odbc-plugin], [AS_HELP_STRING( [--with-odbc-plugin], [Compile the ODBC database output plugin (default=no)])],
#  [enable_odbc_plugin=$withval],
#  [enable_odbc_plugin="no"]
#)
dnl With File-output-plugin? (default is yes)
AC_ARG_WITH([file-plugin], [AS_HELP_STRING([--with-file-plugin], [Compile the textfile output plugin (default=yes)])],
  [enable_file_plugin=$withval],
  [enable_file_plugin="yes"]
)


dnl Enable maintainer mode (all warnings treated as errors) (default is no)
AC_ARG_ENABLE([maintainer], [AS_HELP_STRING([--enable-maintainer], [Enable generation of debugging information and makes all warnings an error (default is off)])],
  [],
  [enable_maintainer="no"]
)
dnl Enable debug mode (default is no)
AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug], [Enable generation of debugging information (default is off)])],
  [],
  [enable_debug="no"]
)
dnl Use my extra development settings? (default is no)
AC_ARG_ENABLE([private], [AS_HELP_STRING([--enable-private], [Enable the developers personal settings (default is off)])],
  [],
  [enable_private="no"]
)


dnl Enable SSL (default is yes)
#AC_ARG_ENABLE([ssl], [AS_HELP_STRING([--disable-ssl], [Disable SSL])],
#  [],
#  [enable_ssl="yes"]
#)
enable_ssl="yes"
dnl With static OpenSSL? (default is shared)
AC_ARG_WITH([system-openssl], [AS_HELP_STRING([--with-system-openssl], [Use system provided OpenSSL? (default=no)])],
  [enable_system_openssl="yes"],
  [enable_system_openssl="no"]
)

dnl Build all applications or just the server (default is all)
AC_ARG_ENABLE([extras], [AS_HELP_STRING([--disable-extras], [Disable building anything apart from the opengalaxy server application.])],
  [],
  [enable_extras="yes"]
)

dnl Windows: Enable self-elevation (to Administrator) of opengalaxy-ca
AC_ARG_ENABLE([uac], [AS_HELP_STRING([--enable-uac], [Enable UAC self-elevation for opengalaxy_ca (Windows only)])],
  [],
  [enable_uac="no"]
)

dnl Link with or without Google performance tools
dnl (Server only for now)
AC_ARG_WITH([gperftools], [AS_HELP_STRING([--with-gperftools], [Use Google performance tools (default=no)])],
  [enable_gperftools=$withval],
  [enable_gperftools="no"]
)

dnl tests for Windows
dnl
have_windows="no"
have_windows64="no"
MINGW_DIR=""
AS_IF([test "x$OSTYPE" = "xcygwin"], [AC_MSG_ERROR([Sorry, CygWin is not supported, use MSYS2 instead.])])
AC_MSG_CHECKING([for MSYS2/MinGW64])
AS_IF([test "x$MSYSTEM" = "xMINGW32"], [
 AC_MSG_RESULT([yes])
 AC_DEFINE([HAVE_WINDOWS], 1, [On Windows, using MSYS2 32bit])
 have_windows="yes"
 MINGW_DIR="/mingw32"
], [
 AS_IF([test "x$MSYSTEM" = "xMINGW64"], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_WINDOWS], 1, [On Windows, using MSYS2 64bit])
  have_windows="yes"
  have_windows64="yes"
  MINGW_DIR="/mingw64"
 ], [
  AC_MSG_RESULT([no])
 ])
])
AC_SUBST([MINGW_DIR])


dnl default directory for libmysqlclient (Linux only)
libmysqlclient_dir="/usr/local/mysql"

dnl Minimal acceptable version of libmysqlclient
need_libmysqlclient_version=5.5.43

dnl Decide what default settings to use in the opengalaxy configuration file
config_log_level="2"
config_serial_port_name="/dev/ttyUSB0"
config_baudrate="9600"
config_use_email_plugin="no"
config_email_from_address="Account-used-to-send-mail@gmail.com"
config_email_from_name="Security Manager"
config_email_recipients=""
config_use_mysql_plugin="no"
config_mysql_server="localhost"
config_mysql_user="Galaxy"
config_mysql_password="topsecret"
config_mysql_database="Galaxy"
config_use_file_plugin="yes"
config_file_textfile_name="sia.log"
config_file_textfile="$(eval echo $(eval echo ${localstatedir:-.}/log/galaxy/${default_config_file_textfile_name}))"
config_dip8="off"
config_alt_control_blocks="no"
config_blacklist_timeout="3"
config_session_timeout="180"
dnl Add windows specific stuff
AS_IF([test "x$have_windows" = "xyes"], [
 config_serial_port_name="COM1:"
])
AC_SUBST([config_log_level])
AC_SUBST([config_serial_port_name])
AC_SUBST([config_baudrate])
AC_SUBST([config_use_email_plugin])
AC_SUBST([config_email_from_address])
AC_SUBST([config_email_from_name])
AC_SUBST([config_email_recipients])
AC_SUBST([config_use_mysql_plugin])
AC_SUBST([config_mysql_server])
AC_SUBST([config_mysql_user])
AC_SUBST([config_mysql_password])
AC_SUBST([config_mysql_database])
AC_SUBST([config_use_file_plugin])
AC_SUBST([config_file_textfile_name])
AC_SUBST([config_file_textfile])
AC_SUBST([config_dip8])
AC_SUBST([config_alt_control_blocks])
AC_SUBST([config_blacklist_timeout])
AC_SUBST([config_session_timeout])


dnl test if we are on Debian
dnl
have_debian="no"
AS_IF([test "x$have_windows" = "xno"], [
 AC_MSG_CHECKING([for Debian GNU/Linux])
 AS_IF([test -x /etc/debian_version], [
  AC_MSG_RESULT([no])
 ],[
  AC_MSG_RESULT([`lsb_release -is`])
  have_debian="yes"
 ])
])


have_x86_cpu="no"
have_i386_cpu="no"
have_amd64_cpu="no"
AS_IF([test "x${target_cpu}" = "xx86_64"], [have_x86_cpu="yes"]);
AS_IF([test "x${target_cpu}" = "xx86_64"], [have_amd64_cpu="yes"]);
AS_IF([test "x${target_cpu}" = "xi386"], [have_x86_cpu="yes"]);
AS_IF([test "x${target_cpu}" = "xi386"], [have_i386_cpu="yes"]);
AS_IF([test "x$have_x86_cpu" = "xyes"],[
 AC_DEFINE([HAVE_X86_CPU], 1, [Are we configuring for i386 or x86_64])
])
AS_IF([test "x$have_amd64_cpu" = "xyes"],[
 AC_DEFINE([HAVE_AMD64_CPU], 1, [Are we configuring for 64bit])
])
AS_IF([test "x$have_i386_cpu" = "xyes"],[
 AC_DEFINE([HAVE_I386_CPU], 1, [Are we configuring for 32bit])
])


dnl gcc options to link with static libraries
LINK_STATIC="-Wl,-static"

dnl gcc options to link with shared libraries
LINK_DYNAMIC="-Wl,-call_shared"

dnl Look for a sed program
dnl
AC_PROG_SED
AS_IF([test "x$SED" == "x"],[AC_MSG_ERROR([Configure requires the program 'sed'.])])
AC_SUBST([SED])

dnl Define some substitution variables for the package version
dnl
PACKAGE_VERSION_MAJOR=`echo $PACKAGE_VERSION | cut -d \. -f 1`
PACKAGE_VERSION_MINOR=`echo $PACKAGE_VERSION | cut -d \. -f 2`
PACKAGE_VERSION_MICRO=`echo $PACKAGE_VERSION | cut -d \. -f 3`
AC_SUBST([PACKAGE_VERSION_MAJOR])
AC_SUBST([PACKAGE_VERSION_MINOR])
AC_SUBST([PACKAGE_VERSION_MICRO])

dnl Set sanitize options
sanitize_cxxflags="-fno-omit-frame-pointer"
sanitize_cflags="-fno-omit-frame-pointer"
sanitize_ldflags=""

dnl Set hardening options
dnl
hardening_cppflags="-D_FORTIFY_SOURCE=2"
hardening_cxxflags="-Wformat -Werror=format-security -fstack-protector-strong"
hardening_cflags="-Wformat -Werror=format-security -fstack-protector-strong"

AS_IF([test "x$have_windows" = "xno"], [
hardening_ldflags="-Wl,-z,relro,-z,now"

hardening_cxxflags="$hardening_cxxflags -fPIE"
hardening_cflags="$hardening_cflags -fPIE"
hardening_ldflags="$hardening_ldflags -fPIE -pie"
])

dnl Set things up for normal, debug, maintainer or private mode
dnl
debug_cxxflags=""
optimize_cxxflags=""
debug_cflags=""
optimize_cflags=""
AS_IF([test "x$enable_private" = "xyes"], [
 AC_DEFINE([HAVE_PRIVATE], 1, [Developers personal settings mode])
])
AS_IF([test "x$enable_maintainer" = "xyes"], [
  AC_DEFINE([HAVE_MAINTAINER], 1, [Warnings are errors])
  enable_debug="yes"
  debug_cxxflags="$debug_cxxflags -Werror"
  debug_cflags="$debug_cflags -Werror"
  sanitize_cxxflags="$sanitize_cxxflags -fsanitize=thread"
  sanitize_cflags="$sanitize_cflags -fsanitize=thread"
  sanitize_ldflags="$sanitize_ldflags -fsanitize=thread"
])
AS_IF([test "x$enable_debug" = "xyes"], [
 debug_cxxflags="-O0 -g3 -Wall"
 debug_cflags="-O0 -g3 -Wall"
 AC_DEFINE([HAVE_DEBUG], 1, [Build with debug information])
 AS_IF([test "x$enable_maintainer" = "xyes"], [
  debug_cflags="$debug_cflags -Werror"
  debug_cxxflags="$debug_cxxflags -Werror"
 ])
])
AS_IF([test "x$debug_cxxflags" = "x"], [
  optimize_cxxflags="-O3 -g0 -Wall"
  optimize_cflags="-O3 -g0 -Wall"
])

dnl Decide to build everything, or just the server application (default = full build)
AS_IF([test "x$enable_extras" != "xyes"], [want_extras="no"])

dnl Decide witch output plugins to include
dnl
AS_IF([test "x${enable_email_plugin}" = "xyes"],[AC_DEFINE([HAVE_EMAIL_PLUGIN], 1, [Compile the email output plugin])])
AS_IF([test "x${enable_mysql_plugin}" = "xyes"],[AC_DEFINE([HAVE_MYSQL_PLUGIN], 1, [Compile the MySQL database output plugin])])
AS_IF([test "x${enable_odbc_plugin}"  = "xyes"],[AC_DEFINE([HAVE_ODBC_PLUGIN], 1, [Compile the ODBC database output plugin])])
AS_IF([test "x${enable_file_plugin}"  = "xyes"],[AC_DEFINE([HAVE_FILE_PLUGIN], 1, [Compile the textfile output plugin])])

dnl Decide to build with or without SSL (default is with)
#AS_IF([test "x$enable_ssl" != "xyes"], [AC_DEFINE([HAVE_NO_SSL], 1, [Compile without SSL support?])])

dnl Decide if we want to run opengalaxy_ca with administrator privileges (Windows)
dnl https://code.msdn.microsoft.com/windowsdesktop/CSUACSelfElevation-644673d3
dnl
dnl This defines the UAC_EXE_LVL substitution variable to 'asInvoker' or 'requireAdministrator'
dnl and is used to initialize the assembly manifest file (uac.xml).
dnl
AS_IF([test "x$have_windows" = "xyes"], [
 AC_MSG_CHECKING([if we want UAC self-elevation])
 AS_IF([test "x$enable_uac" = "xyes"], [
  AC_MSG_RESULT([yes])
  UAC_EXE_LVL="requireAdministrator"
 ], [
  AC_MSG_RESULT([no])
  UAC_EXE_LVL="asInvoker"
 ])
 AC_SUBST([UAC_EXE_LVL])
])

dnl Check for C++11 compiler
AX_CXX_COMPILE_STDCXX_11([], [mandatory])

dnl Check for C99 compiler
AC_PROG_CC_C99
AS_IF([test "x$ac_cv_prog_cc_c99" = "xno"], [
 AC_MSG_ERROR([openGalaxy needs a C compiler in C99 mode!])
])

dnl Checks for header files used by opengalaxy
AC_CHECK_HEADERS([unistd.h ])

# autoscan checks for opengalaxy server
AC_CHECK_HEADERS([fcntl.h stddef.h stdint.h sys/time.h termios.h unistd.h getopt.h])
AC_CHECK_HEADER_STDBOOL
AC_CHECK_FUNCS([getpid])
AC_CHECK_FUNCS([getopt_long], [], [AC_MSG_ERROR([getopt_long() is required but was not found!])])
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit memset strcspn strdup strspn strtol strtoul])

# autoscan checks for opengalaxy ca
AC_PATH_X
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])
AC_TYPE_MODE_T
AC_FUNC_CHOWN
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([atexit memset mkdir strchr strdup strerror strstr strtol strtoul])

# autoscan checks for opengalaxy client
AC_PATH_X
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit memset strdup strstr strtol])


dnl pkg-config
dnl
#AC_PATH_PROG([PKG_CONFIG], [pkg-config])
#AC_SUBST([PKG_CONFIG])

dnl Add rpath's to per-target_LDFLAGS
#AS_IF([test "x$have_windows" != "xyes"], [
# RPATH=`echo "$src_server_opengalaxy_LDFLAGS" | ${SED} "s/-L/-Wl,-rpath,/g"`
# src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${RPATH}"
#])

dnl Test for gperftools
dnl
AS_IF([test "x$enable_gperftools" = "xyes"], [
 AC_MSG_CHECKING([for gperftools])
 AC_PATH_PROG([PKG_CONFIG], [pkg-config])
 AS_IF([test "x$PKG_CONFIG" != "x"], [
  AS_IF([test "x`$PKG_CONFIG libprofiler --exists 2>/dev/null && echo yes || echo no`" = "xyes"], [
   GPERFTOOLS_CXXFLAGS=`$PKG_CONFIG libprofiler --cflags 2>/dev/null`
   GPERFTOOLS_LDFLAGS=`$PKG_CONFIG libprofiler --libs-only-L 2>/dev/null`
   GPERFTOOLS_LIBS=`$PKG_CONFIG libprofiler --libs-only-l 2>/dev/null`
   GPERFTOOLS_RPATH=`echo "$GPERFTOOLS_LDFLAGS" | ${SED} "s/-L/-Wl,-rpath,/g"`
   AC_DEFINE([HAVE_GPERFTOOLS], 1, [Using Google performance tools to profile])
   AC_MSG_RESULT([yes])
  ],[
   AC_MSG_RESULT([no])
   AC_MSG_ERROR([pkg-config could not find gperftools!])
  ])
 ], [
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([pkg-config is needed to look for gperftools!])
 ])
])

dnl Test for POSIX threads support
dnl
AX_PTHREAD([], AC_MSG_ERROR([No POSIX threads available!]))

dnl Test for zlib
dnl
BACKUP_CPPFLAGS=$CPPFLAGS
BACKUP_LDFLAGS=$LDFLAGS
BACKUP_LIBS=$LIBS
CPPFLAGS=""
LDFLAGS=""
LIBS=""
AX_CHECK_ZLIB([], AC_MSG_ERROR([No ZLIB development files found!]))
ZLIB_CFLAGS=$CPPFLAGS
ZLIB_LDFLAGS=$LDFLAGS
ZLIB_LIBS=$LIBS
CPPFLAGS=$BACKUP_CPPFLAGS
LDFLAGS=$BACKUP_LDFLAGS
LIBS=$BACKUP_LIBS

dnl for libwebsockets build
ZLIB_INCLUDE_DIR=$(echo $ZLIB_CFLAGS | awk '{print $1}' | sed s/-I//)
ZLIB_LIBRARY=$(echo $ZLIB_LDFLAGS | awk '{print $1}' | sed s/-L//)
AC_SUBST(ZLIB_INCLUDE_DIR)
AC_SUBST(ZLIB_LIBRARY)


dnl Test for SSL library
dnl
ssl_provider=""
AS_IF([test "x$enable_ssl" = "xyes"], [
 dnl --with-openssl was specified, check for and use OpenSSL
 ssl_provider="OpenSSL"
 AS_IF([test "x$enable_system_openssl" = "xyes"], [
  AS_IF([test "x$have_windows" = "xyes"], [
   backup_libs=$LIBS
   dnl add winsock and gdi32 to LIBS so the openssl build test passes
   LIBS="-lws2_32 -lgdi32"
   AX_CHECK_OPENSSL([], [AC_MSG_ERROR([OpenSSL not found, please specify by using --with-openssl])])
   LIBS=$backup_libs
  ], [
   AX_CHECK_OPENSSL([], [AC_MSG_ERROR([OpenSSL not found, please specify by using --with-openssl])])
  ])
 ])
])
AS_CASE([$ssl_provider], [OpenSSL], [
 AC_DEFINE([HAVE_OPENSSL], 1, [OpenSSL library])
 dnl Windows: Add winsock2 and GDI to openSSL libraries
 AS_IF([test "x$have_windows" = "xyes"], [
  OPENSSL_LIBS="$OPENSSL_LIBS -lws2_32 -lgdi32"
 ])
 AS_IF([test "x$enable_system_openssl" = "xyes"], [
  dnl get the base, include and library ssl directories for the libwebsockets build
  OPENSSL_DIR=$(echo -ne $OPENSSL_LDFLAGS | sed 's/-L//;s/\/lib//')
  AS_IF([test "x$OPENSSL_DIR" = "x"],[
   dnl empty, use system paths
   OPENSSL_ROOT_DIR="/usr"
   OPENSSL_INCLUDE_DIR="/usr/include"
   OPENSSL_LIBRARY_DIR="/usr/lib"
  ],[
   dnl non-standard, use that directory
   OPENSSL_ROOT_DIR="${OPENSSL_DIR}"
   OPENSSL_INCLUDE_DIR="${OPENSSL_DIR}/include"
   OPENSSL_LIBRARY_DIR="${OPENSSL_DIR}/lib"
  ])
 ], [
   dnl use local build (as seen from the libwebsockets/build direcory)
   OPENSSL_ROOT_DIR="../../lib/usr"
   OPENSSL_INCLUDE_DIR="../../lib/usr/include"
   OPENSSL_LIBRARY_DIR="../../lib/usr/lib"
 ])
 AC_SUBST([OPENSSL_ROOT_DIR])
 AC_SUBST([OPENSSL_INCLUDE_DIR])
 AC_SUBST([OPENSSL_LIBRARY_DIR])
])
AM_CONDITIONAL([HAVE_SYSTEM_OPENSSL], [test "x$enable_system_openssl" = "xyes" && test "x$enable_ssl" = "xyes"])


dnl We need libmysqlclient if we use the mysql plugin
dnl
AS_IF([test "x$enable_mysql_plugin" = "xyes"], [
 AS_IF([test "x$have_windows" = "xyes"], [
  dnl
  dnl Windows test for libmysqlclient
  dnl
  AS_IF([test "x$with_mysql" != "x"], [AS_CASE([$with_mysql], [y], [unset with_mysql], [ye], [unset with_mysql], [yes], [unset with_mysql], [n], [unset with_mysql], [no], [unset with_mysql])])
  AS_IF([test "x$with_mysql" = "x"], [
   dnl no directory specified, assume default
   AS_IF([test "x$have_windows64" = "xyes"], [
    PRGFILES=$PROGRAMFILES
   ], [
    dnl Get the $ProgramFiles(x86) environment variable (windows x86_64)
    PRGFILES=`env | sed -n '/\(^ProgramFiles(x86)=\)/p' | sed "s/^ProgramFiles(x86)=//"`
    dnl If not found use the normal $PROGRAMFILES variable
    AS_IF([test "x$PRGFILES" = "x"], [PRGFILES=$PROGRAMFILES])
   ])
   libmysqlclient_dir="${PRGFILES}/MySQL/MySQL Connector C 6.1"
  ], [
   dnl directory was specified
   libmysqlclient_dir="$with_mysql"
  ]) 
  dnl test for files
  have_libmysqlclient="yes"
  AC_MSG_CHECKING([$libmysqlclient_dir/lib/libmysql.dll])
  dnl Autoconf hates spaces in paths, so do our own file tests...
  AS_IF([test -f "$libmysqlclient_dir/lib/libmysql.dll"], [
   AC_MSG_RESULT([yes])
  ], [
   have_libmysqlclient="no"
   AC_MSG_RESULT([no])
  ])
  AC_MSG_CHECKING([$libmysqlclient_dir/include/mysql.h])
  AS_IF([test -f "$libmysqlclient_dir/include/mysql.h"], [
   AC_MSG_RESULT([yes])
  ], [
   have_libmysqlclient="no"
   AC_MSG_RESULT([no])
  ])
  dnl did we find everything?
  AS_IF([test "x${have_libmysqlclient}" = "xno"], [
   # Nothing found. Echo error message.
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([This project requires libmysqlclient to be installed in ${libmysqlclient_dir}])
   AC_MSG_NOTICE([libmysqlclient can be downloaded from http://dev.mysql.com/downloads/connector/c/])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([Please install libmysqlclient (version ${need_libmysqlclient_version} or higher) or use --with-mysql=<dir>])
   AC_MSG_NOTICE([You may also disable the MySQL output plugin with --without-mysql-plugin to remove this dependancy.]) 
   AC_MSG_NOTICE([])
   AC_MSG_ERROR([])
  ])
   LIBMYSQLCLIENT_INCLUDES="-I\"${libmysqlclient_dir}/include\""
   LIBMYSQLCLIENT_LDFLAGS="-L\"${libmysqlclient_dir}/lib\""
   LIBMYSQLCLIENT_LIBS="\"${libmysqlclient_dir}/lib/libmysql.dll\""
 ], [
  dnl
  dnl Linux test for libmysqlclient
  dnl
  AX_LIB_MYSQL([$need_libmysqlclient_version])
  AS_IF([test "$mysql_version_check" != "1"], [
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([This project requires libmysqlclient to be installed])
   AC_MSG_NOTICE([Run 'apt-get install libmysqlclient-dev' or download the sources])
   AC_MSG_NOTICE([from http://dev.mysql.com/downloads/connector/c/])
   AC_MSG_NOTICE([])
   AC_MSG_NOTICE([Please install libmysqlclient (version ${need_libmysqlclient_version} or higher) or use --with-mysql=/full/path/to/mysql_config])
   AC_MSG_NOTICE([You may also disable the MySQL output plugin with --without-mysql-plugin to remove this dependancy.])
   AC_MSG_NOTICE([])
   AC_MSG_ERROR([])
  ])
  LIBMYSQLCLIENT_INCLUDES="`$MYSQL_CONFIG --cflags`"
  LIBMYSQLCLIENT_LDFLAGS="`$MYSQL_CONFIG --libs_r | $SED 's/-l.[[^\ $]]*//g'`"
  LIBMYSQLCLIENT_LIBS="`$MYSQL_CONFIG --libs_r | $SED 's/-L.[[^\ $]]*//g'`"
 ])
])


dnl Test for GTK+ 3.0
dnl
AS_IF([test "x$enable_extras" = "xyes"], [
 PKG_CHECK_MODULES([GTK], [gtk+-3.0], [],[AC_MSG_ERROR("GTK+ 3.x development files are needed to build openGalaxy")])
 dnl ensure that only allowed headers are included
 GTK_CFLAGS+=" -DGTK_DISABLE_SINGLE_INCLUDES"
 dnl ensure that no gtk deprecated symbols are used
 GTK_CFLAGS+=" -DGDK_DISABLE_DEPRECATED"
 GTK_CFLAGS+=" -DGTK_DISABLE_DEPRECATED"
 dnl ensure use of accessors
 GTK_CFLAGS+=" -DGSEAL_ENABLE"
])


dnl Windows: Test for NSIS
dnl
AS_IF([test "x$enable_extras" = "xyes"], [
 AS_IF([test "x$have_windows" = "xyes"], [
  AC_CHECK_PROG([have_nsis], [makensis], ["yes"], ["no"], [], [])
  AS_IF([test "x$have_nsis" = "xno"], [
   AC_MSG_WARN(["Nullsoft Scriptable Install System (NSIS) not found in PATH!"])
   AC_MSG_WARN(["Not building installer image..."])
  ])
 ])
])


dnl Test for xxd (from debian vim-common package)
dnl Used to convert glade files to something we can include in C/C++ files
dnl
AS_IF([test "x$enable_extras" = "xyes"], [
 AC_CHECK_PROG([have_xxd], [xxd], [yes], [no], [], [])
 AS_IF([test "x$have_xxd" == "xno"], [
  AC_MSG_ERROR(["xxd hexdump tool (package: vim-common) not found!"])
 ])
 XXD="xxd"
 AC_SUBST([XXD])
])


dnl Windows: Test for resource compiler
dnl
AS_IF([test "x$have_windows" = "xyes"], [
 AC_CHECK_PROG(have_windres, windres, [yes], [no], [], [])
 AS_IF([test "x$have_windres" = "xno"], [
  AC_MSG_ERROR(["windres resource compiler not found!"])
 ])
 RC="windres"
 AC_SUBST([RC])
])


dnl Windows: Test for 'upx' executeable file compressor
dnl
AS_IF([test "x$have_windows" = "xyes"], [
 AC_CHECK_PROG([have_upx], [upx], ["yes"], ["no"], [], [])
 AS_IF([test "x$have_upx" = "xno"], [
  AC_MSG_WARN(['Ultimate Packer for eXecutables' (UPX) not found, not compressing executables...])
 ])
])


dnl Windows: We also need mkdir -p during the installation phase in Makefile.am
dnl
AS_IF([test "x$have_windows" = "xyes"], [
 AC_PROG_MKDIR_P
 AS_IF([test "x$MKDIR_P" == "x"],[AC_MSG_ERROR([Configure needs to be able to use `mkdir -p`.])])
 AC_SUBST([MKDIR_P])
])


dnl Filter (the superfluous) -lpthread from LIBMYSQLCLIENT_LIBS and GTK_CFLAGS
dnl
LIBMYSQLCLIENT_LIBS=`echo ${LIBMYSQLCLIENT_LIBS} | ${SED} "s/-lpthread//g"`
AS_IF([test "x$have_extras" = "xyes"], [
 GTK_CFLAGS=`echo ${GTK_CFLAGS} | ${SED} "s/-pthread//g"`
])


dnl put all (base) flags together
dnl
CPPFLAGS="$CPPFLAGS $hardening_cppflags"
CXXFLAGS="$CXXFLAGS $sanitize_cxxflags $hardening_cxxflags $debug_cxxflags $optimize_cxxflags"
CFLAGS="$CFLAGS $sanitize_cflags $hardening_cflags $debug_cflags $optimize_cflags"
LDFLAGS="$LDFLAGS $sanitize_ldflags $hardening_ldflags"
AS_IF([test "x$have_windows" == "xyes"], [
 dnl On windows, always compile with -mthreads when using threads
 CXXFLAGS="-mthreads $CXXFLAGS"
 CFLAGS="-mthreads $CFLAGS"
])

DEFAULT_CFLAGS="-I. -Isrc/glade -I${srcdir}/src/common -Ilib/usr/include ${CFLAGS}"
DEFAULT_CXXFLAGS="-I. -Isrc/glade -I${srcdir}/src/common -Ilib/usr/include ${CXXFLAGS}"


dnl
dnl Assemble per-target flags and libs for the openGalaxy support library
dnl
src_libcommon_a_CFLAGS="${DEFAULT_CFLAGS}"
src_libcommon_a_CXXFLAGS="${DEFAULT_CXXFLAGS}"
dnl SSL
AS_IF([test "x$enable_ssl" = "xyes"], [
 AS_IF([test "x$enable_system_openssl" = "yes"], [
  src_libcommon_a_CFLAGS="${src_libcommon_a_CFLAGS} ${OPENSSL_INCLUDES}"
  src_libcommon_a_CXXFLAGS="${src_libcommon_a_CXXFLAGS} ${OPENSSL_INCLUDES}"
 ])
])
dnl zlib
src_libcommon_a_CFLAGS="${src_libcommon_a_CFLAGS} ${ZLIB_CFLAGS}"
src_libcommon_a_CXXFLAGS="${src_libcommon_a_CXXFLAGS} ${ZLIB_CFLAGS}"
dnl GTK+
src_libcommon_a_CFLAGS="${src_libcommon_a_CFLAGS} ${GTK_CFLAGS}"
src_libcommon_a_CXXFLAGS="${src_libcommon_a_CXXFLAGS} ${GTK_CFLAGS}"
AC_SUBST(src_libcommon_a_CFLAGS)
AC_SUBST(src_libcommon_a_CXXFLAGS)


dnl
dnl per target flags for the UI data library
dnl
src_libglade_a_CFLAGS="-I."
AC_SUBST(src_libglade_a_CFLAGS)


dnl
dnl Assemble per-target flags and libs for opengalaxy
dnl
AS_IF([test "x$have_windows" != "xyes"], [
 dnl
 dnl (for Linux)
 dnl
 src_server_opengalaxy_CXXFLAGS="${DEFAULT_CXXFLAGS}"
 src_server_opengalaxy_LDADD="src/libcommon.a ${LIBS}"
 AS_IF([test "x$enable_shared_libwebsockets" = "xyes"],[
  dnl Shared websockets
  src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LINK_DYNAMIC} -Llib/usr/lib -lwebsockets"
 ], [
  dnl Static websockets
  src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LINK_STATIC} -Llib/usr/lib -lwebsockets ${LINK_DYNAMIC}"
 ])
 dnl SSL
 AS_IF([test "x$enable_ssl" = "xyes"], [
  dnl OpenSSL
  AS_IF([test "x$enable_system_openssl" = "yes"], [
   dnl Use system provided OpenSSL
   src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} ${OPENSSL_INCLUDES}"
   src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LINK_DYNAMIC} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}"
  ], [
   dnl Use our local OpenSSL
   src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LINK_DYNAMIC} -lssl -lcrypto -ldl"
  ])
 ])
 dnl pthread
 src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} ${PTHREAD_CFLAGS}"
 src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${PTHREAD_LIBS}"
 dnl MySQL (shared)
 AS_IF([test "x$enable_mysql_plugin" = "xyes"],[
  src_server_opengalaxy_CXXFLAGS="${LIBMYSQLCLIENT_INCLUDES} ${src_server_opengalaxy_CXXFLAGS}"
  src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${LIBMYSQLCLIENT_LDFLAGS}"
  src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LIBMYSQLCLIENT_LIBS}"
 ])
 dnl Zlib (shared)
 src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} ${ZLIB_CFLAGS}"
 src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${ZLIB_LDFLAGS}"
 src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${ZLIB_LIBS}"
 dnl gperftools
 src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} ${GPERFTOOLS_CXXFLAGS}"
 src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${GPERFTOOLS_LDFLAGS}"
 src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${GPERFTOOLS_RPATH} ${GPERFTOOLS_LIBS}"
 dnl add access to private-libwebsockets.h
 src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} -Ilibwebsockets/lib -Ilibwebsockets/build"
 dnl add system library paths last, so that our local libraries are used first
 src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${LDFLAGS}"
], [
 dnl
 dnl (for Windows, MinGW64/MSYS2)
 dnl
 src_server_opengalaxy_CXXFLAGS="-static ${DEFAULT_CXXFLAGS}"
 src_server_opengalaxy_LDADD="--enable-stdcall-fixup src/libcommon.a ${LIBS}"
 # websockets
 AS_IF([test "x$enable_shared_libwebsockets" = "xyes"],[
  dnl Shared websockets
  src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LINK_DYNAMIC} -Llib/usr/lib -lwebsockets_shared.dll ${LINK_STATIC}"
 ], [
  dnl Static websockets
  src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} -Llib/usr/lib -lwebsockets_static"
 ])
 dnl SSL
 AS_IF([test "x$enable_ssl" = "xyes"], [
  dnl OpenSSL
  AS_IF([test "x$enable_system_openssl" = "yes"], [
   dnl Use system provided OpenSSL
   src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} ${OPENSSL_INCLUDES}"
   src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LINK_DYNAMIC} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}"
  ], [
   dnl Use our local OpenSSL
   src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LINK_DYNAMIC} -lssl -lcrypto -lws2_32 -lgdi32"
  ])
 ])
 dnl MySQL
 AS_IF([test "x$enable_mysql_plugin" = "xyes"],[
  src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} ${LIBMYSQLCLIENT_INCLUDES}"
  src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${LIBMYSQLCLIENT_LDFLAGS} --enable-stdcall-fixup"
  src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${LIBMYSQLCLIENT_LIBS}"
 ])
 dnl Zlib
 src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} ${ZLIB_CFLAGS}"
 src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${ZLIB_LDFLAGS}"
 src_server_opengalaxy_LDADD="${src_server_opengalaxy_LDADD} ${ZLIB_LIBS}"
 dnl add access to private-libwebsockets.h
 src_server_opengalaxy_CXXFLAGS="${src_server_opengalaxy_CXXFLAGS} -Ilibwebsockets/lib -Ilibwebsockets/build"
 dnl add system library paths last
 src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${LDFLAGS}"
])

dnl not needed anymore, we link staticly against non-system libraries (wolfssf, websockets, libmysql)
dnl Add rpath's to per-target_LDFLAGS
##AS_IF([test "x$have_windows" != "xyes"], [
## RPATH=`echo "$src_server_opengalaxy_LDFLAGS" | ${SED} "s/-L/-Wl,-rpath,/g"`
## src_server_opengalaxy_LDFLAGS="${src_server_opengalaxy_LDFLAGS} ${RPATH}"
##])

dnl Tidy up for displaying purposes
src_server_opengalaxy_CXXFLAGS=`echo "$src_server_opengalaxy_CXXFLAGS" | $SED 's/  */ /g;s/^ //;s/ $//'`
src_server_opengalaxy_LDFLAGS=`echo "$src_server_opengalaxy_LDFLAGS" | $SED 's/  */ /g;s/^ //;s/ $//'`
src_server_opengalaxy_LDADD=`echo "$src_server_opengalaxy_LDADD" | $SED 's/  */ /g;s/^ //;s/ $//'`

dnl Export flags to automake
AC_SUBST(src_server_opengalaxy_CFLAGS)
AC_SUBST(src_server_opengalaxy_CXXFLAGS)
AC_SUBST(src_server_opengalaxy_LDFLAGS)
AC_SUBST(src_server_opengalaxy_LDADD)


dnl
dnl Assemble per-target flags and libs for opengalaxy_ca
dnl
AS_IF([test "x$enable_extras" = "xyes"], [
 AS_IF([test "x$have_windows" != "xyes"], [
  dnl
  dnl (for Linux)
  dnl
  src_ca_opengalaxy_ca_CFLAGS="${DEFAULT_CFLAGS}"
  src_ca_opengalaxy_ca_LDADD="src/libcommon.a src/libgtkdata.a ${LIBS} -lX11"
  AS_IF([test "x$enable_shared_libwebsockets" = "xyes"],[
   dnl Shared websockets
   src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_DYNAMIC} -Llib/usr/lib -lwebsockets"
  ], [
   dnl Static websockets
   src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_STATIC} -Llib/usr/lib -lwebsockets ${LINK_DYNAMIC}"
  ])
  dnl SSL
  AS_IF([test "x$enable_ssl" = "xyes"], [
   dnl OpenSSL
   AS_IF([test "x$enable_system_openssl" = "yes"], [
    dnl Use system provided OpenSSL
    src_ca_opengalaxy_ca_CXXFLAGS="${src_ca_opengalaxy_ca_CXXFLAGS} ${OPENSSL_INCLUDES}"
    src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_DYNAMIC} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}"
   ], [
    dnl Use our local OpenSSL
    src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_DYNAMIC} -lssl -lcrypto -ldl"
   ])
  ])
  dnl GTK+
  src_ca_opengalaxy_ca_CFLAGS="${src_ca_opengalaxy_ca_CFLAGS} ${GTK_CFLAGS}"
  src_ca_opengalaxy_ca_LDFLAGS="${src_ca_opengalaxy_ca_LDFLAGS} ${GTK_LDFLAGS}"
  src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${GTK_LIBS}"
  dnl Zlib (shared)
  src_ca_opengalaxy_ca_CXXFLAGS="${src_ca_opengalaxy_ca_CXXFLAGS} ${ZLIB_CFLAGS}"
  src_ca_opengalaxy_ca_LDFLAGS="${src_ca_opengalaxy_ca_LDFLAGS} ${ZLIB_LDFLAGS}"
  src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${ZLIB_LIBS}"
  dnl add system library paths last
  src_ca_opengalaxy_ca_LDFLAGS="${src_ca_opengalaxy_ca_LDFLAGS} ${LDFLAGS}"
 ], [
  dnl
  dnl (for MinGW/MSYS)
  dnl
  src_ca_opengalaxy_ca_CFLAGS="-static ${DEFAULT_CFLAGS}"
  src_ca_opengalaxy_ca_LDADD="src/libcommon.a src/libgtkdata.a ${LIBS}"
  # websockets
  AS_IF([test "x$enable_shared_libwebsockets" = "xyes"],[
   dnl Shared websockets
   src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_DYNAMIC} --Llib/usr/lib -lwebsockets_shared.dll ${LINK_STATIC}"
  ], [
   dnl Static websockets
   src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} -Llib/usr/lib -lwebsockets_static"
  ])
  dnl SSL
  AS_IF([test "x$enable_ssl" = "xyes"], [
   dnl OpenSSL
   AS_IF([test "x$enable_system_openssl" = "yes"], [
    dnl Use system provided OpenSSL
    src_ca_opengalaxy_ca_CXXFLAGS="${src_ca_opengalaxy_ca_CXXFLAGS} ${OPENSSL_INCLUDES}"
    src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_DYNAMIC} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}"
   ], [
    dnl Use our local OpenSSL
    src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_DYNAMIC} -lssl -lcrypto -lws2_32 -lgdi32"
   ])
  ])
  dnl Zlib
  src_ca_opengalaxy_ca_CXXFLAGS="${src_ca_opengalaxy_ca_CXXFLAGS} ${ZLIB_CFLAGS}"
  src_ca_opengalaxy_ca_LDFLAGS="${src_ca_opengalaxy_ca_LDFLAGS} ${ZLIB_LDFLAGS}"
  src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${ZLIB_LIBS}"
  dnl GTK+
  src_ca_opengalaxy_ca_CFLAGS="${src_ca_opengalaxy_ca_CFLAGS} ${GTK_CFLAGS}"
  src_ca_opengalaxy_ca_LDFLAGS="${src_ca_opengalaxy_ca_LDFLAGS} ${GTK_LDFLAGS}"
  src_ca_opengalaxy_ca_LDADD="${src_ca_opengalaxy_ca_LDADD} ${LINK_DYNAMIC} ${GTK_LIBS} ${LINK_STATIC}"
  dnl Add system library paths last
  dnl Also Do not use: "-Wl,-subsystem,windows"
  dnl This gives us a console window that we can hide ourselves
  dnl This way we keep a console window from popping up when we use popen()
  src_ca_opengalaxy_ca_LDFLAGS="${src_ca_opengalaxy_ca_LDFLAGS} ${LDFLAGS}"
 ])


 dnl not needed anymore, we link staticly against non-system libraries (wolfssf, websockets, libmysql)
 dnl Add rpath's to per-target_LDFLAGS
# AS_IF([test "x$have_windows" != "xyes"], [
#  RPATH=`echo "$src_ca_opengalaxy_ca_LDFLAGS" | ${SED} "s/-L/-Wl,-rpath,/g"`
#  src_ca_opengalaxy_ca_LDFLAGS="${src_ca_opengalaxy_ca_LDFLAGS} ${RPATH}"
# ])

 dnl Tidy up for displaying purposes
 src_ca_opengalaxy_ca_CFLAGS=`echo "$src_ca_opengalaxy_ca_CFLAGS" | $SED 's/  */ /g;s/^ //;s/ $//'`
 src_ca_opengalaxy_ca_LDFLAGS=`echo "$src_ca_opengalaxy_ca_LDFLAGS" | $SED 's/  */ /g;s/^ //;s/ $//'`
 src_ca_opengalaxy_ca_LDADD=`echo "$src_ca_opengalaxy_ca_LDADD" | $SED 's/  */ /g;s/^ //;s/ $//'`

 dnl Export flags to automake
 AC_SUBST(src_ca_opengalaxy_ca_CFLAGS)
 AC_SUBST(src_ca_opengalaxy_ca_LDFLAGS)
 AC_SUBST(src_ca_opengalaxy_ca_LDADD)
])


dnl
dnl Assemble per-target flags and libs for opengalaxy_client
dnl
AS_IF([test "x$enable_extras" = "xyes"], [
 AS_IF([test "x$have_windows" != "xyes"], [
  dnl
  dnl (for Linux)
  dnl
  src_client_opengalaxy_client_CFLAGS="${DEFAULT_CFLAGS}"
  src_client_opengalaxy_client_LDADD="src/libcommon.a src/libgtkdata.a ${LIBS} -lX11"
  # websockets
  AS_IF([test "x$enable_shared_libwebsockets" = "xyes"],[
   dnl Shared websockets
   src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_DYNAMIC} -lwebsockets"
  ], [
   dnl Static websockets
   src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_STATIC} -lwebsockets ${LINK_DYNAMIC}"
  ])
  dnl SSL
  AS_IF([test "x$enable_ssl" = "xyes"], [
   dnl OpenSSL
   AS_IF([test "x$enable_system_openssl" = "yes"], [
    dnl Use system provided OpenSSL
    src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${OPENSSL_INCLUDES}"
    src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_DYNAMIC} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}"
   ], [
    dnl Use our local OpenSSL
    src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_DYNAMIC} -lssl -lcrypto -ldl"
   ])
  ])
#  dnl MySQL (shared)
#  AS_IF([test "x$enable_mysql_plugin" = "xyes"],[
#   src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${LIBMYSQLCLIENT_INCLUDES}"
#   src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${LIBMYSQLCLIENT_LDFLAGS}"
#   src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LIBMYSQLCLIENT_LIBS}"
#  ])
  dnl GTK+
  src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${GTK_CFLAGS}"
  src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${GTK_LDFLAGS}"
  src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${GTK_LIBS}"
  dnl Zlib (shared)
  src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${ZLIB_CFLAGS}"
  src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${ZLIB_LDFLAGS}"
  src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${ZLIB_LIBS}"
  dnl Add system library paths last
  src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} -Llib/usr/lib ${LDFLAGS}"
 ], [
  dnl
  dnl (for MinGW/MSYS)
  dnl
  src_client_opengalaxy_client_CFLAGS="-static ${DEFAULT_CFLAGS}"
  AS_IF([test "x$enable_debug" != "xyes"], [
    src_client_opengalaxy_client_LDFLAGS="-Wl,-subsystem,windows"
  ])
  src_client_opengalaxy_client_LDADD="src/libcommon.a src/libgtkdata.a ${LIBS}"
  # websockets
  AS_IF([test "x$enable_shared_libwebsockets" = "xyes"],[
   dnl Shared websockets
   src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_DYNAMIC} -Llib/usr/lib -lwebsockets_shared.dll ${LINK_STATIC}"
  ], [
   dnl Static websockets
   src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} -Llib/usr/lib -lwebsockets_static"
  ])
  dnl SSL
  dnl SSL
  AS_IF([test "x$enable_ssl" = "xyes"], [
   dnl OpenSSL
   AS_IF([test "x$enable_system_openssl" = "yes"], [
    dnl Use system provided OpenSSL
    src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${OPENSSL_INCLUDES}"
    src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_DYNAMIC} ${OPENSSL_LDFLAGS} ${OPENSSL_LIBS}"
   ], [
    dnl Use our local OpenSSL
    src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_DYNAMIC} -lssl -lcrypto -lws2_32 -lgdi32"
   ])
  ])
#  dnl MySQL
#  AS_IF([test "x$enable_mysql_plugin" = "xyes"],[
#  src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${LIBMYSQLCLIENT_INCLUDES}"
#   src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${LIBMYSQLCLIENT_LDFLAGS} --enable-stdcall-fixup"
#   src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LIBMYSQLCLIENT_LIBS}"
#  ])
  dnl GTK+
  src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${GTK_CFLAGS}"
  src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${GTK_LDFLAGS}"
  src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${LINK_DYNAMIC} ${GTK_LIBS} ${LINK_STATIC}"
  dnl Zlib
  src_client_opengalaxy_client_CFLAGS="${src_client_opengalaxy_client_CFLAGS} ${ZLIB_CFLAGS}"
  src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${ZLIB_LDFLAGS}"
  src_client_opengalaxy_client_LDADD="${src_client_opengalaxy_client_LDADD} ${ZLIB_LIBS}"
  dnl Add system library paths last
  src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${LDFLAGS}"
 ])

 dnl not needed anymore, we link staticly against non-system libraries (libwebsockets, libmysql)
 dnl Add rpath's to per-target_LDFLAGS
## AS_IF([test "x$have_windows" != "xyes"], [
##  RPATH=`echo "$src_client_opengalaxy_client_LDFLAGS" | ${SED} "s/-L/-Wl,-rpath,/g"`
##  src_client_opengalaxy_client_LDFLAGS="${src_client_opengalaxy_client_LDFLAGS} ${RPATH}"
## ])

 dnl Tidy up for displaying purposes
 src_client_opengalaxy_client_CFLAGS=`echo "$src_client_opengalaxy_client_CFLAGS" | $SED 's/  */ /g;s/^ //;s/ $//'`
 src_client_opengalaxy_client_LDFLAGS=`echo "$src_client_opengalaxy_client_LDFLAGS" | $SED 's/  */ /g;s/^ //;s/ $//'`
 src_client_opengalaxy_client_LDADD=`echo "$src_client_opengalaxy_client_LDADD" | $SED 's/  */ /g;s/^ //;s/ $//'`

 dnl Export flags to automake
 AC_SUBST(src_client_opengalaxy_client_CFLAGS)
 AC_SUBST(src_client_opengalaxy_client_LDFLAGS)
 AC_SUBST(src_client_opengalaxy_client_LDADD)
])


dnl These can be passed to external configure scripts in Makefile.am
EXPORT_CPPFLAGS="$CPPFLAGS"
EXPORT_CFLAGS="$CFLAGS"
EXPORT_CXXFLAGS="$CXXFLAGS"
EXPORT_LDFLAGS="$LDFLAGS"
AC_SUBST(EXPORT_CPPFLAGS)
AC_SUBST(EXPORT_CFLAGS)
AC_SUBST(EXPORT_CXXFLAGS)
AC_SUBST(EXPORT_LDFLAGS)


dnl Export conditionals to Automake
dnl
AM_CONDITIONAL([HAVE_X86_CPU],      [test "x$have_x86_cpu" = "xyes"])
AM_CONDITIONAL([HAVE_AMD64_CPU],    [test "x$have_amd64_cpu" = "xyes"])
AM_CONDITIONAL([HAVE_I386_CPU],     [test "x$have_i386_cpu" = "xyes"])
AM_CONDITIONAL([DEBUG],             [test "x$enable_debug" = "xyes"])
AM_CONDITIONAL([MAINTAINER],        [test "x$enable_maintainer" = "xyes"])
AM_CONDITIONAL([PRIVATE],           [test "x$enable_private" = "xyes"])
AM_CONDITIONAL([HAVE_WINDOWS],      [test "x$have_windows" = "xyes"])
AM_CONDITIONAL([HAVE_DEBIAN],       [test "x$have_debian" = "xyes"])
AM_CONDITIONAL([HAVE_EXTRAS],       [test "x$enable_extras" = "xyes"])
AM_CONDITIONAL([HAVE_EMAIL_PLUGIN], [test "x$enable_email_plugin" = "xyes"])
AM_CONDITIONAL([HAVE_MYSQL_PLUGIN], [test "x$enable_mysql_plugin" = "xyes"])
AM_CONDITIONAL([HAVE_ODBC_PLUGIN],  [test "x$enable_odbc_plugin" = "xyes"])
AM_CONDITIONAL([HAVE_FILE_PLUGIN],  [test "x$enable_file_plugin" = "xyes"])
AM_CONDITIONAL([HAVE_NO_SSL],       [test "x$enable_ssl" != "xyes"])
AM_CONDITIONAL([HAVE_OPENSSL],      [test "x$ssl_provider" = "xOpenSSL"])
AM_CONDITIONAL([HAVE_MYSQL],        [test "x$have_libmysqlclient" = "xyes"])
AM_CONDITIONAL([GTK],               [test -n "$GTK_LIBS"])
AM_CONDITIONAL([HAVE_NSIS],         [test "x$have_nsis" = "xyes"])
AM_CONDITIONAL([HAVE_UPX],          [test "x$have_upx" = "xyes"])
AC_SUBST([libmysqlclient_dir])

dnl Substitution variables to configure the man pages
AS_IF([test "x$have_windows" = "xyes"], [
 dnl Windows
 man_ssmtp_conf="MyDocuments/openGalaxy/ssmtp.conf"
 man_galaxy_conf="MyDocuments/openGalaxy/galaxy.conf"
 man_sql_files="MyDocuments/openGalaxy"
 man_data_dir="MyDocuments/openGalaxy"
 man_ssl_dir="MyDocuments/openGalaxy/ssl"
], [
 dnl Linux
 AS_IF([test "x${prefix}" = "xNONE" ], [
  AS_IF([test "x\${prefix}/etc" = "x${sysconfdir}" ], [
   man_ssmtp_conf="/usr/local/etc/galaxy/ssmtp.conf"
   man_galaxy_conf="/usr/local/etc/galaxy/galaxy.conf"
   man_sql_files="/usr/local/etc/galaxy"
  ], [
   man_ssmtp_conf="${sysconfdir}/galaxy/ssmtp.conf"
   man_galaxy_conf="${sysconfdir}/galaxy/galaxy.conf"
   man_sql_files="${sysconfdir}/galaxy"
  ])

  man_data_dir="/usr/local/share/galaxy"
  man_ssl_dir="/usr/local/share/galaxy/ssl"

 ], [
  AS_IF([test "x\${prefix}/etc" = "x${sysconfdir}" ], [
   man_ssmtp_conf="${prefix}/etc/galaxy/ssmtp.conf"
   man_galaxy_conf="${prefix}/etc/galaxy/galaxy.conf"
   man_sql_files="${prefix}/etc/galaxy"
  ], [
   man_ssmtp_conf="${sysconfdir}/galaxy/ssmtp.conf"
   man_galaxy_conf="${sysconfdir}/galaxy/galaxy.conf"
   man_sql_files="${sysconfdir}/galaxy"
  ])

  man_data_dir="${prefix}/share/galaxy"
  man_ssl_dir="${prefix}/share/galaxy/ssl"

 ])
])
AC_SUBST([man_ssmtp_conf])
AC_SUBST([man_galaxy_conf])
AC_SUBST([man_sql_files])
AC_SUBST([man_data_dir])
AC_SUBST([man_ssl_dir])


dnl Generate files from templates
dnl
AC_CONFIG_FILES([src/glade/placeholder.txt])
AC_CONFIG_FILES([src/www/index.html])
AC_CONFIG_FILES([src/server/galaxy.conf.man])
AC_CONFIG_FILES([src/server/opengalaxy.man])
AC_CONFIG_FILES([src/client/opengalaxy-client.man])
AC_CONFIG_FILES([src/ca/opengalaxy-ca.man])
AS_IF([test "x$have_windows" = "xyes"], [
 AC_CONFIG_FILES([src/server/win-resource.rc])
 AC_CONFIG_FILES([src/client/win-resource.rc])
 AC_CONFIG_FILES([src/ca/win-resource.rc])
 AC_CONFIG_FILES([src/ca/uac.xml])
 AC_CONFIG_FILES([installer.nsi])
], [
 AC_CONFIG_FILES([src/config/ssmtp.conf])
 AC_CONFIG_FILES([src/ca/opengalaxy-ca.desktop])
 AC_CONFIG_FILES([src/server/opengalaxy-server.desktop])
 AC_CONFIG_FILES([src/client/opengalaxy-client.desktop])
])
AC_CONFIG_FILES([src/config/galaxy.conf])
AC_CONFIG_FILES([Makefile])
#AC_CONFIG_FILES([build-debs], [chmod +x ./build-debs])
AC_OUTPUT

dnl print a summary
dnl
AC_MSG_NOTICE([])
AC_MSG_NOTICE([ *** Configuration summary ***])
AC_MSG_NOTICE([])
AS_IF([test "x$enable_extras" = "xyes"], [
 AC_MSG_NOTICE([Build type               : Full, build all applications])
], [
 AC_MSG_NOTICE([Build type               : Compact, build only the server application])
])
 AC_MSG_NOTICE([Target system            : ${target_cpu}])
AS_IF([test "x$enable_ssl" = "xyes"], [
 AS_IF([test "x$enable_system_openssl" = "xyes"], [
  AC_MSG_NOTICE([SSL provider             : ${ssl_provider} @ ${OPENSSL_ROOT_DIR}])
 ], [
  AC_MSG_NOTICE([SSL provider             : Clone from github])
 ])
], [
AC_MSG_NOTICE([SSL provider             : (none)])
])
   AC_MSG_NOTICE([libwebsockets            : Clone from github])
AC_MSG_NOTICE([])
AS_IF([test "x$enable_gperftools" = "xyes"], [
 AC_MSG_NOTICE([Profiling options:])
 AC_MSG_NOTICE([  gperftools             : ${GPERFTOOLS_CXXFLAGS}${GPERFTOOLS_LDFLAGS}${GPERFTOOLS_LIBS}${GPERFTOOLS_RPATH}])
 AC_MSG_NOTICE([])
])
AC_MSG_NOTICE([Output options:])
AC_MSG_NOTICE([  Textfile plugin        : $enable_file_plugin ])
AC_MSG_NOTICE([  Email plugin           : $enable_email_plugin ])
AC_MSG_NOTICE([  MySQL plugin           : $enable_mysql_plugin ])
dnl AC_MSG_NOTICE([  ODBC plugin            : $enable_odbc_plugin ])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([General build options:])
AC_MSG_NOTICE([  C                      : ${debug_cflags}${optimize_cflags}])
AC_MSG_NOTICE([  C++                    : ${debug_cxxflags}${optimize_cxxflags}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Sanitize options:])
AC_MSG_NOTICE([  C                      : ${sanitize_cflags}])
AC_MSG_NOTICE([  C++                    : ${sanitize_cxxflags}])
AC_MSG_NOTICE([  Linker                 : ${sanitize_ldflags}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Hardening options:])
AC_MSG_NOTICE([  CPP                    : ${hardening_cppflags}])
AC_MSG_NOTICE([  C                      : ${hardening_cflags}])
AC_MSG_NOTICE([  C++                    : ${hardening_cxxflags}])
AC_MSG_NOTICE([  Linker                 : ${hardening_ldflags}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Installation directories:])
AC_MSG_NOTICE([  Binaries               : $(eval echo $(eval echo ${bindir}))])
AC_MSG_NOTICE([  Configuration          : $(eval echo $(eval echo ${sysconfdir}/galaxy))])
AC_MSG_NOTICE([  WWW root               : $(eval echo $(eval echo ${datadir}/galaxy/www))])
AC_MSG_NOTICE([  Certificates           : $(eval echo $(eval echo ${datadir}/galaxy/ssl))])
AC_MSG_NOTICE([])

CPPFLAGS=""
CFLAGS=""
CXXFLAGS=""
LDFLAGS=""
LIBS=""

