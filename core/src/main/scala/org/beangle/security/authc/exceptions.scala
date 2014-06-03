package org.beangle.security.authc

class BadCredentialsException(message: String, token: AuthenticationToken, cause: Throwable)
  extends AuthenticationException(message, token, cause)

@SerialVersionUID(1L)
class UsernameNotFoundException(message: String, token: AuthenticationToken, cause: Throwable = null)
  extends BadCredentialsException(message, token, cause)

class AccountStatusException(message: String, token: AuthenticationToken) extends AuthenticationException(message, token, null)

class LockedException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token)

class DisabledException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token)

class CredentialsExpiredException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token)

class AccountExpiredException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token) 
