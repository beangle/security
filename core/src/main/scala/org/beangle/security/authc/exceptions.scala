/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.authc

import org.beangle.commons.lang.Strings
import org.beangle.security.SecurityException

/**
  * 认证异常
  *
  * @author chaostone
  */
@SerialVersionUID(-3529782031102169004L)
class AuthenticationException(message: String, val principal: Any, cause: Throwable = null) extends SecurityException(message, cause) {

  override def getMessage: String = {
    val msg = super.getMessage
    if (null == msg) {
      Strings.concat("security." + Strings.substringBefore(getClass.getSimpleName, "Exception"))
    } else msg
  }

  //should display exception to user
  def breakable: Boolean = false
}

class BadCredentialException(message: String, token: AuthenticationToken, cause: Throwable)
  extends AuthenticationException(message, token, cause)

class BadPreauthTokenException(message: String, token: Any, cause: Throwable)
  extends AuthenticationException(message, token, cause) {

  override def breakable: Boolean = true
}

@SerialVersionUID(1L)
class UsernameNotFoundException(message: String, token: AuthenticationToken, cause: Throwable = null)
  extends AuthenticationException(message, token, cause) {
  override def breakable: Boolean = true
}

class AccountStatusException(message: String, token: AuthenticationToken) extends AuthenticationException(message, token, null) {
  override def breakable: Boolean = true
}

class LockedException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token)

class DisabledException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token)

class CredentialExpiredException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token)

class AccountExpiredException(message: String, token: AuthenticationToken) extends AccountStatusException(message, token)
