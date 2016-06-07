/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2016, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.authc

import java.security.Principal

import org.beangle.commons.lang.{ Objects, Strings }
import org.beangle.commons.logging.Logging
import org.beangle.security.authz.AuthorizationInfo
import org.beangle.security.realm.Realm

import DefaultAccount.StatusMask.{ AccountExpired, CredentialExpired, Disabled, Locked }

/**
 * Authentication Information
 * @author chaostone
 */
trait Account extends AuthorizationInfo with Principal with Serializable {

  def principal: Any

  def description: String

  def details: Map[String, Any]

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialExpired: Boolean

  def disabled: Boolean

  override def hashCode: Int = {
    if (null == principal) 629 else principal.hashCode()
  }

  def getName: String = {
    principal.toString
  }
}

object DefaultAccount {
  object StatusMask {
    val Locked = 1
    val Disabled = 2
    val AccountExpired = 4
    val CredentialExpired = 8
  }
}

class DefaultAccount(val principal: Any, val description: String) extends Account {

  var status: Int = _

  var authorities: Any = _

  var permissions: Any = _

  var details: Map[String, Any] = Map.empty

  private def change(value: Boolean, mask: Int): Unit = {
    if (value) status = status | mask
    else {
      if ((status & mask) > 0) status = status ^ mask
    }
  }

  private def get(mask: Int): Boolean = (status & mask) > 0

  def accountExpired: Boolean = get(AccountExpired)

  def accountExpired_=(value: Boolean) = change(value, AccountExpired)

  def accountLocked: Boolean = get(Locked)

  def accountLocked_=(locked: Boolean): Unit = change(locked, Locked)

  def credentialExpired: Boolean = get(CredentialExpired)

  def credentialExpired_=(expired: Boolean): Unit = change(expired, CredentialExpired)

  def disabled: Boolean = get(Disabled)

  def disabled_=(value: Boolean): Unit = change(value, Disabled)

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: DefaultAccount => Objects.equalsBuilder.add(principal, test.principal).isEquals
      case _                    => false
    }
  }

  override def toString(): String = {
    Objects.toStringBuilder(this).add("Principal:", principal)
      .add("AccountExpired: ", accountExpired)
      .add("credentialExpired: ", credentialExpired)
      .add("AccountLocked: ", accountLocked)
      .add("Disabled: ", disabled)
      .add("Authorities: ", authorities)
      .add("Permissions: ", permissions).toString
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
        account
      case None =>
        throw new UsernameNotFoundException(s"Cannot find account data for $token", token)
    }
  }

  protected def additionalCheck(token: AuthenticationToken, ac: Account) {
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
