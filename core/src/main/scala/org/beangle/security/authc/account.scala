package org.beangle.security.authc

import java.security.Principal

import org.beangle.commons.bean.Initializing
import org.beangle.commons.lang.{ Objects, Strings }
import org.beangle.commons.logging.Logging
import org.beangle.security.authz.AuthorizationInfo
import org.beangle.security.realm.Realm

import AccountStatusMask.{ AccountExpired, CredentialExpired, Disabled, Locked }

/**
 * Authentication Information
 * @author chaostone
 */
trait Account extends AuthorizationInfo with Principal with Mergable with Serializable {

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

/**
 * Authentication Info can merge with others
 */
trait Mergable {
  def details_=(data: Map[String, Any])
  def merge(info: Account): this.type
}

object AccountStatusMask {
  val Locked = 1;
  val Disabled = 2
  val AccountExpired = 4
  val CredentialExpired = 8
}

class DefaultAccount(val principal: Any, val description: String) extends Account {

  var status: Int = _

  var authorities: Any = _

  var permissions: Any = _

  var details: Map[String, Any] = Map.empty

  import AccountStatusMask._

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

  override def merge(ac: Account): this.type = {
    if (ac.accountExpired) this.accountExpired = true
    if (ac.accountLocked) this.accountLocked = true
    if (ac.credentialExpired) this.credentialExpired = true
    if (ac.disabled) this.disabled = true
    if (null != ac.authorities) this.authorities = ac.authorities
    if (null != ac.permissions) this.permissions = ac.permissions
    if (!ac.details.isEmpty) this.details ++= ac.details
    this
  }

}

trait AccountStore {
  def load(principal: Any): Option[Account]
}

abstract class AbstractAccountRealm extends Realm with Logging with Initializing {

  var parent: AbstractAccountRealm = _

  override def init(): Unit = {
    var parentRealm = parent
    while (null != parentRealm && parent != null) {
      if (parent == this) parent = null
      else parentRealm = parent.parent
    }
  }
  protected def determinePrincipal(token: AuthenticationToken): Any = {
    if (token == null) "NONE_PROVIDED" else token.getName()
  }

  override def getAccount(token: AuthenticationToken): Account = {
    var merged: Account = if (null != parent) parent.getAccount(token) else null

    val principal = determinePrincipal(token)
    if (null == principal || principal.isInstanceOf[String] && Strings.isEmpty(principal.toString)) {
      throw new AuthenticationException("cannot find username for " + token.principal, token)
    }

    loadAccount(principal) match {
      case Some(account) =>
        if (null == merged) {
          merged = account
          credentialsCheck(token, account)
        } else {
          merged.merge(account)
        }
        additionalCheck(token, merged)
      case None =>
        if (null != merged) throw new UsernameNotFoundException(s"Cannot find account data for $token", null)
    }
    merged
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

  protected def credentialsCheck(token: AuthenticationToken, account: Account): Unit

  def supports(token: AuthenticationToken): Boolean = token.isInstanceOf[UsernamePasswordAuthenticationToken]

}
