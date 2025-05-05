AC_PREREQ(2.59)
AC_INIT(amidi2net, 0.1)
AC_PROG_CC
AC_PROG_INSTALL
AM_INIT_AUTOMAKE

PKG_CHECK_MODULES(ALSA, alsa >= 1.2.13)

PKG_CHECK_MODULES(OPENSSL, [openssl], [have_openssl="yes"], [have_openssl="no"])
AM_CONDITIONAL(SUPPORT_AUTH, [test "$have_openssl" = "yes"])
if test "$have_openssl" = "yes"; then
   AC_DEFINE([SUPPORT_AUTH], 1, [Support authentication])
fi

PKG_CHECK_MODULES(AVAHI, [avahi-client], [have_avahi="yes"], [have_avahi="no"])
AM_CONDITIONAL(SUPPORT_MDNS, [test "$have_avahi" = "yes"])
if test "$have_avahi" = "yes"; then
   AC_DEFINE([SUPPORT_MDNS], 1, [Support mDNS])
fi

AC_CONFIG_HEADERS(config.h)

AC_OUTPUT(Makefile)
