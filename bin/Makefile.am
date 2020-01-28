# $Id$

AM_CPPFLAGS = -DKNC_VERSION_STRING=\"1.12\" -I../lib

bin_PROGRAMS = knc

knc_SOURCES = knc.c gssstdio.c
knc_CPPFLAGS = $(AM_CPPFLAGS) $(WFLAGS)
knc_LDFLAGS = ../lib/.libs/libknc.so $(AM_LDFLAGS)

man_MANS = knc.1
