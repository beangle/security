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
import org.beangle.commons.logging.Logging
import org.beangle.security.realm.Realm

abstract class AbstractAccountRealm extends Realm with Logging {

  protected def determinePrincipal(token: AuthenticationToken): Any = {
    if (token == null) "NONE_PROVIDED" else token.getName
  }

  override def getAccount(token: AuthenticationToken): Account = {
    val principal = determinePrincipal(token)
    if (null == principal || principal.isInstanceOf[String] && Strings.isEmpty(principal.toString)) {
      throw new AuthenticationException("cannot find username for " + token.principal, token)
    }

    if (!token.trusted) {
      if (!credentialCheck(token))
        throw new BadCredentialException("Incorrect credential", token, null)
    }

    loadAccount(principal) match {
      case Some(account) =>
        additionalCheck(token, account)
        val da = new DefaultAccount(account)
        token match {
          case p: PreauthToken => da.addRemoteToken(p.credential)
          case _ =>
        }
        da
      case None =>
        throw new UsernameNotFoundException(s"你的用户名（$token）在本系统无对应账户信息，无法继续使用，请联系系统管理员。", token)
    }
  }

  protected def additionalCheck(token: AuthenticationToken, ac: Account): Unit = {
    if (ac.accountLocked)
      throw new LockedException("AccountStatusChecker.locked", token)
    if (ac.disabled)
      throw new DisabledException("AccountStatusChecker.disabled", token)
    if (ac.accountExpired)
      throw new AccountExpiredException("AccountStatusChecker.expired", token)
    if (ac.credentialExpired)
      throw new CredentialExpiredException("AccountStatusChecker.credentialExpired", token)
  }

  protected def loadAccount(principal: Any): Option[Account]

  protected def credentialCheck(token: AuthenticationToken): Boolean

  def supports(token: AuthenticationToken): Boolean = true

}
