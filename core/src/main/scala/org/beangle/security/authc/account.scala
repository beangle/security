/*
 * Beangle, Agile Development Scaffold and Toolkits.
 *
 * Copyright © 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.authc

import java.io.Externalizable
import java.security.Principal

import org.beangle.commons.lang.Strings
import org.beangle.commons.logging.Logging
import org.beangle.security.realm.Realm

/**
  * Authentication Information
  * @author chaostone
  */
trait Account extends Principal with Externalizable {

  def name: String

  def categoryId:Int

  def description: String

  def remoteToken: Option[String]

  def details: Map[String, Any]

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialExpired: Boolean

  def disabled: Boolean

  def authorities : Array[String]

  def permissions: Array[String]

  def isRemote:Boolean

  override def hashCode: Int = {
    if (null == name) 629 else name.hashCode()
  }

  def getName: String = {
    name
  }

}

trait AccountStore {
  def load(principal: Any): Option[Account]
}

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
      if (!credentialsCheck(token))
        throw new BadCredentialsException("Incorrect credentials", token, null)
    }

    loadAccount(principal) match {
      case Some(account) =>
        additionalCheck(token, account)
        val da = new DefaultAccount(account)
        token match {
          case p: PreauthToken => da.addRemoteToken(p.credentials)
          case _ =>
        }
        da
      case None =>
        throw new UsernameNotFoundException(s"Cannot find account data for $token", token)
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
      throw new CredentialsExpiredException("AccountStatusChecker.credentialExpired", token)
  }

  protected def loadAccount(principal: Any): Option[Account]

  protected def credentialsCheck(token: AuthenticationToken): Boolean

  def supports(token: AuthenticationToken): Boolean = true

}

class DefaultAccountRealm(accountStore: AccountStore, credentialsChecker: CredentialsChecker) extends AbstractAccountRealm {

  def this(accountStore: AccountStore) {
    this(accountStore, null)
  }

  protected override def loadAccount(principal: Any): Option[Account] = {
    accountStore.load(principal)
  }

  protected override def credentialsCheck(token: AuthenticationToken): Boolean = {
    credentialsChecker.check(token.principal, token.credentials)
  }
}
