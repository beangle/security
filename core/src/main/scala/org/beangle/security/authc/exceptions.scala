package org.beangle.security.authc

class BadCredentialsException(message: String, cause: Throwable) extends AuthenticationException(message, cause)

@SerialVersionUID(1L)
class UsernameNotFoundException(message: String, cause: Throwable = null) extends BadCredentialsException(message, cause)

class AccountStatusException(message: String, user: Any) extends AuthenticationException(message, null) {
  this.extraInfo = user
}

class LockedException(message: String, user: Any) extends AccountStatusException(message, user)

class DisabledException(message: String, user: Any) extends AccountStatusException(message, user)

class CredentialsExpiredException(message: String, user: Any) extends AccountStatusException(message, user)

class AccountExpiredException(message: String, user: Any) extends AccountStatusException(message, user) 
