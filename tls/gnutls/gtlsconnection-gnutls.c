/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2009 Red Hat, Inc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 */

#include "config.h"
#include "glib.h"

#include <errno.h>
#include <stdarg.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gtlsconnection-gnutls.h"
#include "gtlsbackend-gnutls.h"
#include "gtlscertificate-gnutls.h"

#ifdef HAVE_PKCS11
#include <p11-kit/pin.h>
#include "pkcs11/gpkcs11pin.h"
#endif

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <winerror.h>

/* It isn’t clear whether MinGW always defines EMSGSIZE. */
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#endif

#include <glib/gi18n-lib.h>

static ssize_t g_tls_connection_gnutls_push_func (gnutls_transport_ptr_t  transport_data,
						  const void             *buf,
						  size_t                  buflen);
static ssize_t g_tls_connection_gnutls_pull_func (gnutls_transport_ptr_t  transport_data,
						  void                   *buf,
						  size_t                  buflen);

#ifdef HAVE_PKCS11
static P11KitPin*    on_pin_prompt_callback  (const char     *pinfile,
                                              P11KitUri      *pin_uri,
                                              const char     *pin_description,
                                              P11KitPinFlags  pin_flags,
                                              void           *callback_data);
#endif

static void g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface);

static void g_tls_connection_gnutls_init_priorities (void);

G_DEFINE_ABSTRACT_TYPE_WITH_CODE (GTlsConnectionGnutls, g_tls_connection_gnutls, G_TYPE_TLS_CONNECTION_BASE,
				  G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
							 g_tls_connection_gnutls_initable_iface_init);
				  g_tls_connection_gnutls_init_priorities ();
				  )

struct _GTlsConnectionGnutlsPrivate
{
  gnutls_certificate_credentials_t creds;
  gnutls_session_t session;

  gchar *interaction_id;

#ifndef GNUTLS_E_PREMATURE_TERMINATION
  gboolean eof;
#endif

  GTlsCertificate *peer_certificate_tmp;
  GTlsCertificateFlags peer_certificate_errors_tmp;
};

static gint unique_interaction_id = 0;

static void
g_tls_connection_gnutls_init (GTlsConnectionGnutls *gnutls)
{
  gint unique_id;

  gnutls->priv = G_TYPE_INSTANCE_GET_PRIVATE (gnutls, G_TYPE_TLS_CONNECTION_GNUTLS, GTlsConnectionGnutlsPrivate);

  gnutls_certificate_allocate_credentials (&gnutls->priv->creds);
  gnutls_certificate_set_verify_flags (gnutls->priv->creds,
				       GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

  unique_id = g_atomic_int_add (&unique_interaction_id, 1);
  gnutls->priv->interaction_id = g_strdup_printf ("gtls:%d", unique_id);

#ifdef HAVE_PKCS11
  p11_kit_pin_register_callback (gnutls->priv->interaction_id,
                                 on_pin_prompt_callback, gnutls, NULL);
#endif
}

/* First field is "fallback", second is "allow unsafe rehandshaking" */
static gnutls_priority_t priorities[2][2];

#define DEFAULT_BASE_PRIORITY "NORMAL:%COMPAT:%LATEST_RECORD_VERSION"

static void
g_tls_connection_gnutls_init_priorities (void)
{
  const gchar *base_priority;
  gchar *fallback_priority, *unsafe_rehandshake_priority, *fallback_unsafe_rehandshake_priority;
  const guint *protos;
  int ret, i, nprotos, fallback_proto;

  base_priority = g_getenv ("G_TLS_GNUTLS_PRIORITY");
  if (!base_priority)
    base_priority = DEFAULT_BASE_PRIORITY;
  ret = gnutls_priority_init (&priorities[FALSE][FALSE], base_priority, NULL);
  if (ret == GNUTLS_E_INVALID_REQUEST)
    {
      g_warning ("G_TLS_GNUTLS_PRIORITY is invalid; ignoring!");
      base_priority = DEFAULT_BASE_PRIORITY;
      ret = gnutls_priority_init (&priorities[FALSE][FALSE], base_priority, NULL);
      g_warn_if_fail (ret == 0);
    }

  unsafe_rehandshake_priority = g_strdup_printf ("%s:%%UNSAFE_RENEGOTIATION", base_priority);
  ret = gnutls_priority_init (&priorities[FALSE][TRUE], unsafe_rehandshake_priority, NULL);
  g_warn_if_fail (ret == 0);
  g_free (unsafe_rehandshake_priority);

  /* Figure out the lowest SSl/TLS version supported by base_priority */
  nprotos = gnutls_priority_protocol_list (priorities[FALSE][FALSE], &protos);
  fallback_proto = G_MAXUINT;
  for (i = 0; i < nprotos; i++)
    {
      if (protos[i] < fallback_proto)
	fallback_proto = protos[i];
    }
  if (fallback_proto == G_MAXUINT)
    {
      g_warning ("All GNUTLS protocol versions disabled?");
      fallback_priority = g_strdup (base_priority);
    }
  else
    {
      gchar *cleaned_base, *p, *rest;

      /* fallback_priority should be based on base_priority, except
       * that we don't want %LATEST_RECORD_VERSION in it.
       */
      cleaned_base = g_strdup (base_priority);
      p = strstr (cleaned_base, ":%LATEST_RECORD_VERSION");
      if (p)
	{
	  rest = p + strlen (":%LATEST_RECORD_VERSION");
	  memmove (p, rest, strlen (rest) + 1);
	}

      fallback_priority = g_strdup_printf ("%s:%%COMPAT:!VERS-TLS-ALL:+VERS-%s",
					   cleaned_base,
					   gnutls_protocol_get_name (fallback_proto));

      g_free (cleaned_base);
    }
  fallback_unsafe_rehandshake_priority = g_strdup_printf ("%s:%%UNSAFE_RENEGOTIATION",
							  fallback_priority);

  ret = gnutls_priority_init (&priorities[TRUE][FALSE], fallback_priority, NULL);
  g_warn_if_fail (ret == 0);
  ret = gnutls_priority_init (&priorities[TRUE][TRUE], fallback_unsafe_rehandshake_priority, NULL);
  g_warn_if_fail (ret == 0);
  g_free (fallback_priority);
  g_free (fallback_unsafe_rehandshake_priority);
}

static void
g_tls_connection_gnutls_set_handshake_priority (GTlsConnectionGnutls *gnutls)
{
  gboolean fallback, unsafe_rehandshake;

  if (G_IS_TLS_CLIENT_CONNECTION (gnutls))
    fallback = g_tls_client_connection_get_use_ssl3 (G_TLS_CLIENT_CONNECTION (gnutls));
  else
    fallback = FALSE;
  unsafe_rehandshake = (G_TLS_CONNECTION_BASE (gnutls)->rehandshake_mode == G_TLS_REHANDSHAKE_UNSAFELY);
  gnutls_priority_set (gnutls->priv->session,
		       priorities[fallback][unsafe_rehandshake]);
}

static gboolean
g_tls_connection_gnutls_initable_init (GInitable     *initable,
				       GCancellable  *cancellable,
				       GError       **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (initable);
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (initable);
  gboolean client = G_IS_TLS_CLIENT_CONNECTION (gnutls);
  guint flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
  int status;

  g_return_val_if_fail (tls->base_istream != NULL &&
			tls->base_ostream != NULL, FALSE);

  gnutls_init (&gnutls->priv->session, flags);

  status = gnutls_credentials_set (gnutls->priv->session,
				   GNUTLS_CRD_CERTIFICATE,
				   gnutls->priv->creds);
  if (status != 0)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
		   _("Could not create TLS connection: %s"),
		   gnutls_strerror (status));
      return FALSE;
    }

  gnutls_transport_set_push_function (gnutls->priv->session,
				      g_tls_connection_gnutls_push_func);
  gnutls_transport_set_pull_function (gnutls->priv->session,
				      g_tls_connection_gnutls_pull_func);
  gnutls_transport_set_ptr (gnutls->priv->session, gnutls);

  return TRUE;
}

static void
g_tls_connection_gnutls_finalize (GObject *object)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (object);

  if (gnutls->priv->session)
    gnutls_deinit (gnutls->priv->session);
  if (gnutls->priv->creds)
    gnutls_certificate_free_credentials (gnutls->priv->creds);

#ifdef HAVE_PKCS11
  p11_kit_pin_unregister_callback (gnutls->priv->interaction_id,
                                   on_pin_prompt_callback, gnutls);
#endif
  g_free (gnutls->priv->interaction_id);

  g_clear_object (&gnutls->priv->peer_certificate_tmp);

  G_OBJECT_CLASS (g_tls_connection_gnutls_parent_class)->finalize (object);
}

gnutls_certificate_credentials_t
g_tls_connection_gnutls_get_credentials (GTlsConnectionGnutls *gnutls)
{
  return gnutls->priv->creds;
}

gnutls_session_t
g_tls_connection_gnutls_get_session (GTlsConnectionGnutls *gnutls)
{
  return gnutls->priv->session;
}

void
g_tls_connection_gnutls_get_certificate (GTlsConnectionGnutls *gnutls,
                                         gnutls_retr2_st      *st)
{
  GTlsCertificate *cert;

  cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (gnutls));

  st->cert_type = GNUTLS_CRT_X509;
  st->ncerts = 0;

  if (cert)
      g_tls_certificate_gnutls_copy (G_TLS_CERTIFICATE_GNUTLS (cert),
                                     gnutls->priv->interaction_id, st);
}

static GTlsConnectionBaseStatus
end_gnutls_io (GTlsConnectionGnutls  *gnutls,
               GIOCondition           direction,
               int                    ret,
               GError               **error,
               const char            *err_fmt,
               ...) G_GNUC_PRINTF(5, 6);

static GTlsConnectionBaseStatus
end_gnutls_io (GTlsConnectionGnutls  *gnutls,
               GIOCondition           direction,
               int                    ret,
               GError               **error,
               const char            *err_fmt,
               ...)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (gnutls);
  GError *my_error = NULL;
  GTlsConnectionBaseStatus status;

  if (ret == GNUTLS_E_AGAIN ||
      ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
    return G_TLS_CONNECTION_BASE_TRY_AGAIN;

  status = g_tls_connection_base_pop_io (tls, direction, ret >= 0, &my_error);
  if (status == G_TLS_CONNECTION_BASE_OK ||
      status == G_TLS_CONNECTION_BASE_WOULD_BLOCK ||
      status == G_TLS_CONNECTION_BASE_TIMED_OUT)
    {
      if (my_error)
	g_propagate_error (error, my_error);
      return status;
    }

  /* status == G_TLS_CONNECTION_BASE_ERROR */

  if (tls->handshaking && !tls->ever_handshaked)
    {
      if (ret == GNUTLS_E_UNEXPECTED_PACKET_LENGTH ||
	  ret == GNUTLS_E_FATAL_ALERT_RECEIVED ||
	  ret == GNUTLS_E_DECRYPTION_FAILED ||
	  ret == GNUTLS_E_UNSUPPORTED_VERSION_PACKET)
	{
	  g_error_free (my_error);
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
			       _("Peer failed to perform TLS handshake"));
	  return G_TLS_CONNECTION_BASE_ERROR;
	}
    }

  if (ret == GNUTLS_E_REHANDSHAKE)
    {
      if (tls->rehandshake_mode == G_TLS_REHANDSHAKE_NEVER)
	{
	  g_error_free (my_error);
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
			       _("Peer requested illegal TLS rehandshake"));
	  G_TLS_CONNECTION_GNUTLS_GET_CLASS (gnutls)->failed (gnutls);
	  return G_TLS_CONNECTION_BASE_ERROR;
	}

      return G_TLS_CONNECTION_BASE_REHANDSHAKE;
    }
  else if (
#ifdef GNUTLS_E_PREMATURE_TERMINATION
	   ret == GNUTLS_E_PREMATURE_TERMINATION
#else
	   ret == GNUTLS_E_UNEXPECTED_PACKET_LENGTH && gnutls->priv->eof
#endif
	   )
    {
      if (tls->handshaking && !tls->ever_handshaked)
	{
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_NOT_TLS,
			       _("Peer failed to perform TLS handshake"));
	  return GNUTLS_E_PULL_ERROR;
	}
      else if (tls->require_close_notify)
	{
	  g_error_free (my_error);
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_EOF,
			       _("TLS connection closed unexpectedly"));
	  G_TLS_CONNECTION_GNUTLS_GET_CLASS (gnutls)->failed (gnutls);
	  return G_TLS_CONNECTION_BASE_ERROR;
	}
      else
	return G_TLS_CONNECTION_BASE_OK;
    }
  else if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED,
                           _("TLS connection peer did not send a certificate"));
      return status;
    }

  g_propagate_error (error, my_error);
  if (error && !*error)
    {
      va_list ap;

      va_start (ap, err_fmt);
      *error = g_error_new_valist (G_TLS_ERROR, G_TLS_ERROR_MISC, err_fmt, ap);
      va_end (ap);
    }

  return G_TLS_CONNECTION_BASE_ERROR;
}

#define BEGIN_GNUTLS_IO(gnutls, direction, blocking, cancellable)	\
  g_tls_connection_base_push_io (G_TLS_CONNECTION_BASE (gnutls),	\
				 direction, blocking, cancellable);	\
  do {

#define END_GNUTLS_IO(gnutls, direction, ret, status, errmsg, err)	\
    status = end_gnutls_io (gnutls, direction, ret, err, errmsg, gnutls_strerror (ret));	\
  } while (status == G_TLS_CONNECTION_BASE_TRY_AGAIN);

static void
set_gnutls_error (GTlsConnectionGnutls *gnutls,
		  GError               *error)
{
  /* We set EINTR rather than EAGAIN for G_IO_ERROR_WOULD_BLOCK so
   * that GNUTLS_E_AGAIN only gets returned for gnutls-internal
   * reasons, not for actual socket EAGAINs (and we have access
   * to @error at the higher levels, so we can distinguish them
   * that way later).
   */

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    gnutls_transport_set_errno (gnutls->priv->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
    gnutls_transport_set_errno (gnutls->priv->session, EINTR);
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    gnutls_transport_set_errno (gnutls->priv->session, EINTR);
  else
    gnutls_transport_set_errno (gnutls->priv->session, EIO);
}

static ssize_t
g_tls_connection_gnutls_pull_func (gnutls_transport_ptr_t  transport_data,
				   void                   *buf,
				   size_t                  buflen)
{
  GTlsConnectionBase *tls = transport_data;
  GTlsConnectionGnutls *gnutls = transport_data;
  ssize_t ret;

  /* If tls->read_error is non-%NULL when we're called, it means
   * that an error previously occurred, but gnutls decided not to
   * propagate it. So it's correct for us to just clear it. (Usually
   * this means it ignored an EAGAIN after a short read, and now
   * we'll return EAGAIN again, which it will obey this time.)
   */
  g_clear_error (&tls->read_error);

  ret = g_pollable_stream_read (G_INPUT_STREAM (tls->base_istream),
				buf, buflen, tls->read_blocking,
				tls->read_cancellable, &tls->read_error);

  if (ret < 0)
    set_gnutls_error (gnutls, tls->read_error);
#ifndef GNUTLS_E_PREMATURE_TERMINATION
  else if (ret == 0)
    gnutls->priv->eof = TRUE;
#endif

  return ret;
}

static ssize_t
g_tls_connection_gnutls_push_func (gnutls_transport_ptr_t  transport_data,
				   const void             *buf,
				   size_t                  buflen)
{
  GTlsConnectionBase *tls = transport_data;
  GTlsConnectionGnutls *gnutls = transport_data;
  ssize_t ret;

  /* See comment in pull_func. */
  g_clear_error (&tls->write_error);

  ret = g_pollable_stream_write (G_OUTPUT_STREAM (tls->base_ostream),
				 buf, buflen, tls->write_blocking,
				 tls->write_cancellable, &tls->write_error);
  if (ret < 0)
    set_gnutls_error (gnutls, tls->write_error);

  return ret;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_request_rehandshake (GTlsConnectionBase  *tls,
					     GCancellable        *cancellable,
					     GError             **error)
{
  GTlsConnectionGnutls *gnutls;
  GTlsConnectionBaseStatus status;
  int ret;

  /* On a client-side connection, gnutls_handshake() itself will start
   * a rehandshake, so we only need to do something special here for
   * server-side connections.
   */
  if (!G_IS_TLS_SERVER_CONNECTION (tls))
    return G_TLS_CONNECTION_BASE_OK;

  gnutls = G_TLS_CONNECTION_GNUTLS (tls);

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, TRUE, cancellable);
  ret = gnutls_rehandshake (gnutls->priv->session);
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status,
		 _("Error performing TLS handshake: %s"), error);

  return status;
}

static GTlsCertificate *
get_peer_certificate_from_session (GTlsConnectionGnutls *gnutls)
{
  const gnutls_datum_t *certs;
  GTlsCertificateGnutls *chain;
  unsigned int num_certs;

  certs = gnutls_certificate_get_peers (gnutls->priv->session, &num_certs);
  if (!certs || !num_certs)
    return NULL;

  chain = g_tls_certificate_gnutls_build_chain (certs, num_certs, GNUTLS_X509_FMT_DER);
  if (!chain)
    return NULL;

  return G_TLS_CERTIFICATE (chain);
}

static GTlsCertificateFlags
verify_peer_certificate (GTlsConnectionGnutls *gnutls,
			 GTlsCertificate      *peer_certificate)
{
  GTlsConnection *conn = G_TLS_CONNECTION (gnutls);
  GSocketConnectable *peer_identity;
  GTlsDatabase *database;
  GTlsCertificateFlags errors;
  gboolean is_client;

  is_client = G_IS_TLS_CLIENT_CONNECTION (gnutls);
  if (is_client)
    peer_identity = g_tls_client_connection_get_server_identity (G_TLS_CLIENT_CONNECTION (gnutls));
  else
    peer_identity = NULL;

  errors = 0;

  database = g_tls_connection_get_database (conn);
  if (database == NULL)
    {
      errors |= G_TLS_CERTIFICATE_UNKNOWN_CA;
      errors |= g_tls_certificate_verify (peer_certificate, peer_identity, NULL);
    }
  else
    {
      GError *error = NULL;

      errors |= g_tls_database_verify_chain (database, peer_certificate,
					     is_client ?
					     G_TLS_DATABASE_PURPOSE_AUTHENTICATE_SERVER :
					     G_TLS_DATABASE_PURPOSE_AUTHENTICATE_CLIENT,
					     peer_identity,
					     g_tls_connection_get_interaction (conn),
					     G_TLS_DATABASE_VERIFY_NONE,
					     NULL, &error);
      if (error)
	{
	  g_warning ("failure verifying certificate chain: %s",
		     error->message);
	  g_assert (errors != 0);
	  g_clear_error (&error);
	}
    }

  return errors;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_handshake (GTlsConnectionBase  *tls,
				   GCancellable        *cancellable,
				   GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionBaseStatus status;
  int ret;

  g_tls_connection_gnutls_set_handshake_priority (gnutls);

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, TRUE, cancellable);
  ret = gnutls_handshake (gnutls->priv->session);
  if (ret == GNUTLS_E_GOT_APPLICATION_DATA)
    {
      guint8 buf[1024];

      /* Got app data while waiting for rehandshake; buffer it and try again */
      ret = gnutls_record_recv (gnutls->priv->session, buf, sizeof (buf));
      if (ret > -1)
	{
	  if (!tls->app_data_buf)
	    tls->app_data_buf = g_byte_array_new ();
	  g_byte_array_append (tls->app_data_buf, buf, ret);
	  ret = GNUTLS_E_AGAIN;
	}
    }
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status,
		 _("Error performing TLS handshake: %s"), error);

  if (ret == 0 && gnutls_certificate_type_get (gnutls->priv->session) == GNUTLS_CRT_X509)
    {
      gnutls->priv->peer_certificate_tmp = get_peer_certificate_from_session (gnutls);
      if (gnutls->priv->peer_certificate_tmp)
	gnutls->priv->peer_certificate_errors_tmp = verify_peer_certificate (gnutls, gnutls->priv->peer_certificate_tmp);
      else if (G_IS_TLS_CLIENT_CONNECTION (gnutls))
	{
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			       _("Server did not return a valid TLS certificate"));
	}
    }

  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_complete_handshake (GTlsConnectionBase  *tls,
					    GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsCertificate *peer_certificate;
  GTlsCertificateFlags peer_certificate_errors = 0;
  gboolean status = G_TLS_CONNECTION_BASE_OK;

  peer_certificate = gnutls->priv->peer_certificate_tmp;
  gnutls->priv->peer_certificate_tmp = NULL;
  peer_certificate_errors = gnutls->priv->peer_certificate_errors_tmp;
  gnutls->priv->peer_certificate_errors_tmp = 0;

  if (peer_certificate)
    {
      if (!g_tls_connection_base_accept_peer_certificate (tls, peer_certificate,
                                                          peer_certificate_errors))
	{
	  g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
			       _("Unacceptable TLS certificate"));
	  status = G_TLS_CONNECTION_BASE_ERROR;
	}

      g_tls_connection_base_set_peer_certificate (G_TLS_CONNECTION_BASE (gnutls),
						  peer_certificate,
						  peer_certificate_errors);
      g_object_unref (peer_certificate);
    }

  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_read (GTlsConnectionBase    *tls,
			      void                  *buffer,
			      gsize                  count,
			      gboolean               blocking,
			      gssize                *nread,
			      GCancellable          *cancellable,
			      GError               **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN, blocking, cancellable);
  ret = gnutls_record_recv (gnutls->priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_IN, ret, status,
		 _("Error reading data from TLS socket: %s"), error);

  if (ret >= 0)
    *nread = ret;
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_write (GTlsConnectionBase    *tls,
			       const void            *buffer,
			       gsize                  count,
			       gboolean               blocking,
			       gssize                *nwrote,
			       GCancellable          *cancellable,
			       GError               **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionBaseStatus status;
  gssize ret;

  BEGIN_GNUTLS_IO (gnutls, G_IO_OUT, blocking, cancellable);
  ret = gnutls_record_send (gnutls->priv->session, buffer, count);
  END_GNUTLS_IO (gnutls, G_IO_OUT, ret, status,
		 _("Error writing data to TLS socket: %s"), error);

  if (ret >= 0)
    *nwrote = ret;
  return status;
}

static GTlsConnectionBaseStatus
g_tls_connection_gnutls_close (GTlsConnectionBase  *tls,
			       GCancellable        *cancellable,
			       GError             **error)
{
  GTlsConnectionGnutls *gnutls = G_TLS_CONNECTION_GNUTLS (tls);
  GTlsConnectionBaseStatus status;
  int ret;

  BEGIN_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, TRUE, cancellable);
  ret = gnutls_bye (gnutls->priv->session, GNUTLS_SHUT_WR);
  END_GNUTLS_IO (gnutls, G_IO_IN | G_IO_OUT, ret, status,
		 _("Error performing TLS close: %s"), error);

  return status;
}

#ifdef HAVE_PKCS11

static P11KitPin*
on_pin_prompt_callback (const char     *pinfile,
                        P11KitUri      *pin_uri,
                        const char     *pin_description,
                        P11KitPinFlags  pin_flags,
                        void           *callback_data)
{
  GTlsConnectionBase *tls = G_TLS_CONNECTION_BASE (callback_data);
  GTlsInteractionResult result;
  GTlsPasswordFlags flags = 0;
  GTlsPassword *password;
  P11KitPin *pin = NULL;
  GError *error = NULL;

  if (!tls->interaction)
    return NULL;

  if (pin_flags & P11_KIT_PIN_FLAGS_RETRY)
    flags |= G_TLS_PASSWORD_RETRY;
  if (pin_flags & P11_KIT_PIN_FLAGS_MANY_TRIES)
    flags |= G_TLS_PASSWORD_MANY_TRIES;
  if (pin_flags & P11_KIT_PIN_FLAGS_FINAL_TRY)
    flags |= G_TLS_PASSWORD_FINAL_TRY;

  password = g_pkcs11_pin_new (flags, pin_description);

  result = g_tls_interaction_ask_password (tls->interaction, password,
                                           g_cancellable_get_current (), &error);

  switch (result)
    {
    case G_TLS_INTERACTION_FAILED:
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        g_warning ("couldn't ask for password: %s", error->message);
      pin = NULL;
      break;
    case G_TLS_INTERACTION_UNHANDLED:
    default:
      pin = NULL;
      break;
    case G_TLS_INTERACTION_HANDLED:
      pin = g_pkcs11_pin_steal_internal (G_PKCS11_PIN (password));
      break;
    }

  g_object_unref (password);
  return pin;
}

#endif /* HAVE_PKCS11 */

static void
g_tls_connection_gnutls_class_init (GTlsConnectionGnutlsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class = G_TLS_CONNECTION_BASE_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GTlsConnectionGnutlsPrivate));

  gobject_class->finalize     = g_tls_connection_gnutls_finalize;

  base_class->request_rehandshake = g_tls_connection_gnutls_request_rehandshake;
  base_class->handshake           = g_tls_connection_gnutls_handshake;
  base_class->complete_handshake  = g_tls_connection_gnutls_complete_handshake;
  base_class->read_fn             = g_tls_connection_gnutls_read;
  base_class->write_fn            = g_tls_connection_gnutls_write;
  base_class->close_fn            = g_tls_connection_gnutls_close;
}

static void
g_tls_connection_gnutls_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_connection_gnutls_initable_init;
}

gboolean
g_tls_connection_gnutls_request_certificate (GTlsConnectionGnutls  *self,
					     GError               **error)
{
  GTlsInteractionResult res = G_TLS_INTERACTION_UNHANDLED;
  GTlsInteraction *interaction;
  GTlsConnection *conn;
  GTlsConnectionBase *tls;

  g_return_val_if_fail (G_IS_TLS_CONNECTION_GNUTLS (self), FALSE);

  conn = G_TLS_CONNECTION (self);
  tls = G_TLS_CONNECTION_BASE (self);

  interaction = g_tls_connection_get_interaction (conn);
  if (!interaction)
    return FALSE;

  res = g_tls_interaction_invoke_request_certificate (interaction, conn, 0,
						      tls->read_cancellable, error);
  return res != G_TLS_INTERACTION_FAILED;
}
