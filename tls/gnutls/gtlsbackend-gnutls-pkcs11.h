/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Backend, Output and Gnutlsing Library
 *
 * Copyright © 2011 Collabora, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
 *
 * Author: Stef Walter <stef@collabora.co.uk>
 */

#ifndef __G_TLS_BACKEND_GNUTLS_PKCS11_H__
#define __G_TLS_BACKEND_GNUTLS_PKCS11_H__

#include <gio/gio.h>
#include <gnutls/gnutls.h>

#include "gtlsbackend-gnutls.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_BACKEND_GNUTLS_PKCS11            (g_tls_backend_gnutls_pkcs11get_type ())

G_DECLARE_FINAL_TYPE (GTlsBackendGnutlsPkcs11, g_tls_backend_gnutls_pkcs11, G, TLS_BACKEND_GNUTLS_PKCS11, GTlsBackendGnutls)

void         g_tls_backend_gnutls_pkcs11_register           (GIOModule *module);

G_END_DECLS

#endif /* __G_TLS_BACKEND_GNUTLS_H___ */
