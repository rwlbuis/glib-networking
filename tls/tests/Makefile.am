include $(top_srcdir)/glib-networking.mk

AM_CPPFLAGS +=					\
	-I$(top_srcdir)/tls			\
	-I$(top_builddir)/tls			\
	-DSRCDIR=\""$(abs_srcdir)"\"		\
	-DTOP_BUILDDIR=\""$(top_builddir)"\"

LDADD  = \
	$(GLIB_LIBS)

test_programs =

if HAVE_GNUTLS
test_programs +=             \
	certificate-gnutls   \
	file-database-gnutls \
	connection-gnutls    \
	$(NULL)

certificate_gnutls_SOURCES = certificate.c
certificate_gnutls_CPPFLAGS = $(AM_CPPFLAGS) $(GNUTLS_CFLAGS) -DBACKEND=\""gnutls"\" -DWITH_BACKEND_GNUTLS
certificate_gnutls_LDADD = $(GLIB_LIBS) $(GNUTLS_LIBS)

connection_gnutls_SOURCES = connection.c mock-interaction.c mock-interaction.h
connection_gnutls_CPPFLAGS = $(AM_CPPFLAGS) $(GNUTLS_CFLAGS) -DBACKEND=\""gnutls"\" -DWITH_BACKEND_GNUTLS
connection_gnutls_LDADD = $(GLIB_LIBS) $(GNUTLS_LIBS)

file_database_gnutls_SOURCES = file-database.c
file_database_gnutls_CPPFLAGS = $(AM_CPPFLAGS) $(GNUTLS_CFLAGS) -DBACKEND=\""gnutls"\" -DWITH_BACKEND_GNUTLS
file_database_gnutls_LDADD = $(GLIB_LIBS) $(GNUTLS_LIBS)

endif

if HAVE_OPENSSL
test_programs +=             \
	certificate-openssl   \
	file-database-openssl \
	connection-openssl    \
	$(NULL)

certificate_openssl_SOURCES = certificate.c
certificate_openssl_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_CFLAGS) -DBACKEND=\""openssl"\" -DWITH_BACKEND_OPENSSL
certificate_openssl_LDADD = $(GLIB_LIBS) $(OPENSSL_LIBS)

connection_openssl_SOURCES = connection.c mock-interaction.c mock-interaction.h
connection_openssl_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_CFLAGS) -DBACKEND=\""openssl"\" -DWITH_BACKEND_OPENSSL
connection_openssl_LDADD = $(GLIB_LIBS) $(OPENSSL_LIBS)

file_database_openssl_SOURCES = file-database.c
file_database_openssl_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_CFLAGS) -DBACKEND=\""openssl"\" -DWITH_BACKEND_OPENSSL
file_database_openssl_LDADD = $(GLIB_LIBS) $(OPENSSL_LIBS)

endif

if HAVE_PKCS11

test_programs +=           \
	pkcs11-util        \
	pkcs11-array       \
	pkcs11-pin         \
	pkcs11-slot

AM_CPPFLAGS +=			\
	$(PKCS11_CFLAGS)

LDADD += $(top_builddir)/tls/pkcs11/libgiopkcs11.la $(PKCS11_LIBS)

pkcs11_slot_SOURCES = pkcs11-slot.c \
	mock-pkcs11.c mock-pkcs11.h \
	mock-interaction.c mock-interaction.h

endif

testfiles_data =				\
	files/ca.pem				\
	files/ca-alternative.pem		\
	files/ca-key.pem			\
	files/ca-roots.pem			\
	files/ca-roots-bad.pem			\
	files/ca-verisign-sha1.pem		\
	files/chain.pem				\
	files/chain-with-verisign-md2.pem	\
	files/client-and-key.pem		\
	files/client-future.pem			\
	files/client-past.pem			\
	files/client.pem			\
	files/intermediate-ca.pem		\
	files/non-ca.pem			\
	files/server-and-key.pem		\
	files/server.der			\
	files/server-intermediate.pem		\
	files/server-intermediate-key.pem	\
	files/server-key.der			\
	files/server-key.pem			\
	files/server.pem			\
	files/server-self.pem			\
	$(NULL)

if ENABLE_INSTALLED_TESTS
testfilesdir = $(installed_testdir)/files
testfiles_DATA = $(testfiles_data)
endif

EXTRA_DIST += $(testfiles_data)
