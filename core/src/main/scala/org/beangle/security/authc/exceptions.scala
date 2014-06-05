package org.beangle.security.authc

import org.beangle.commons.lang.Strings

/**
 * 认证异常
 *
 * @author chaostone
 */
@SerialVersionUID(-3529782031102169004L)
class AuthenticationException(message: String, val principal: Any, cause: Throwable = null) extends SecurityException(message, cause) {

  override def getMessage(): String = {
    val msg = super.getMessage()
    if (null == msg) {
      Strings.concat("security." + Strings.substringBefore(getClass().getSimpleName(), "Exception"))
    } else msg
  }
}

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
