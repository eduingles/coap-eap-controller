AM_CPPFLAGS+= -D CONFIGDIR=\"$(sysconfdir)\" ## Sets the config dir
## wpa_supplicant source directory
WPA_SRC =$(srcdir)/wpa_supplicant/src
# Rafa: Añadido este opción de compilación #
############################################
INCLUDES		      = -I$(WPA_SRC) -I$(WPA_SRC)/utils
AM_CXX=clang++	           
AM_CXXFLAGS=-Wall -g -v -DDEBUG -std=c++11
### user programs ###
bin_PROGRAMS = openpaa mote mote2 

### source declarations ###
openpaa_SOURCES               = mainserver.cpp \
				state_machines/coap_eap_session.c \
 				prf_plus.c \
				panamessages.c \
				lalarm.c \
				panautils.c \
				loadconfig.c \
				aes.c \
				eax.c \
				cantcoap-master/nethelper.c

openpaa_CPPFLAGS 	      = $(AM_CPPFLAGS) 
openpaa_CFLAGS		      = $(AM_CFLAGS) -DISSERVER
openpaa_LDFLAGS		      = $(DBG_LINKOPT)

### library dependencies ###

openpaa_LDADD                     = libeapstack/libeap.a \
				    cantcoap-master/libcantcoap.a
		



### source declarations ###
mote_SOURCES               = mote.cpp \
			     cantcoap-master/nethelper.c \
                             panatiki/eap-peer.c \
                             panatiki/eap-psk.c \
                             panatiki/aes.c \
                             panatiki/eax.c

mote_CPPFLAGS              = $(AM_CPPFLAGS)
mote_CFLAGS                = $(AM_CFLAGS) -DISCLIENT
mote_LDFLAGS               = $(DBG_LINKOPT)
### library dependencies ###

mote_LDADD                     = cantcoap-master/libcantcoap.a
##

### library dependencies ###

mote2_LDADD                     = libeapstack/libeap.a
##

mote2_SOURCES               = mote2.c \
                             cantcoap-master/nethelper.c \
                             _cantcoap.c \
                             panatiki/eap-peer.c \
                             panatiki/eap-psk.c \
                             panatiki/aes.c \
                             panatiki/eax.c 

mote2_CFLAGS                = $(AM_CFLAGS) -DISCLIENT
mote2_LDFLAGS               = $(DBG_LINKOPT)


## Adding PANA header files to distribute using "make dist"
EXTRA_DIST =  *.h state_machines/*.h config.xml

## Extra config files needed
sysconf_DATA = \
		config.xml 

