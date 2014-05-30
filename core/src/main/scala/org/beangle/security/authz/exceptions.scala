package org.beangle.security.authz

import org.beangle.security.SecurityException

class AuthorizationException(message: String, cause: Throwable) extends SecurityException(message, cause)

class AccessDeniedException(val resource: Any, message: String, cause: Throwable) extends AuthorizationException(message, cause)