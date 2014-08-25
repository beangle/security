package org.beangle.security.authc

import org.beangle.commons.lang.{Objects, Strings}
import org.beangle.commons.logging.Logging
import org.beangle.commons.text.i18n.{NullTextResource, TextResource}
import org.beangle.security.authz.{Authority, AuthorizationInfo}
import org.beangle.security.realm.Realm

trait Account extends AuthenticationInfo with AuthorizationInfo with Mergable with Serializable {

  def id: Any

  def category: Any

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialExpired: Boolean

  def disabled: Boolean
}

object AccountStatusMask {
  val Locked = 1;
  val Disabled = 2
  val AccountExpired = 4
  val CredentialExpired = 8
}

class DefaultAccount(val principal: Any, var id: Any) extends Account with Mergable {

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

  var status: Int = _

  var category: Any = _

  var authorities: Seq[Authority] = List.empty

  var permissions: List[Any] = List.empty

  var details: Map[String, Any] = Map.empty

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: DefaultAccount =>
        Objects.equalsBuilder().add(principal, test.principal).add(id, test.id).isEquals
      case _ => false
    }
  }

  override def toString(): String = {
    Objects.toStringBuilder(this).add("Principal:", principal)
      .add("Id: ", id)
      .add("AccountExpired: ", accountExpired)
      .add("credentialExpired: ", credentialExpired)
      .add("AccountLocked: ", accountLocked)
      .add("Disabled: ", disabled)
      .add("Category: ", category)
      .add("Authorities: ", authorities.mkString(","))
      .add("Permissions: ", permissions.mkString(",")).toString
  }

  override def merge(info: AuthenticationInfo): this.type = {
    info match {
      case ac: Account => {
        if (ac.accountExpired) this.accountExpired = true
        if (ac.accountLocked) this.accountLocked = true
        if (ac.credentialExpired) this.credentialExpired = true
        if (ac.disabled) this.disabled = true
        if (null != ac.id) this.id = ac.id
        if (null != ac.category) this.category = ac.category
        if (!ac.authorities.isEmpty) this.authorities = this.authorities ++ ac.authorities
        if (!ac.permissions.isEmpty) this.permissions ::= ac.permissions
        if (!ac.details.isEmpty) this.details ++= ac.details
      }
    }
    this
  }

}

trait AccountStore {
  def load(principal: Any): Option[Account]
}

abstract class AbstractAccountRealm extends Realm with Logging {

  var parent: AbstractAccountRealm = _

  var tr: TextResource = new NullTextResource()

  protected def determinePrincipal(token: AuthenticationToken): String = {
    if (token == null) "NONE_PROVIDED" else token.getName()
  }

  override def getAuthenticationInfo(token: AuthenticationToken): Account = {
    var merged: Account = if (null != parent) parent.getAuthenticationInfo(token) else null

    val principal = determinePrincipal(token)
    if (Strings.isEmpty(principal)) {
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
      throw new LockedException(tr("AccountStatusChecker.locked", "User account is locked"), token)
    if (ac.disabled)
      throw new DisabledException(tr("AccountStatusChecker.disabled", "User is disabled"), token)
    if (ac.accountExpired)
      throw new AccountExpiredException(tr("AccountStatusChecker.expired", "User account has expired"), token)
    if (ac.credentialExpired)
      throw new CredentialsExpiredException(tr("AccountStatusChecker.credentialExpired", "User credentials have expired"), token)
  }

  protected def loadAccount(principal: Any): Option[Account]

  protected def credentialsCheck(token: AuthenticationToken, account: Account): Unit

  def supports(token: AuthenticationToken): Boolean = token.isInstanceOf[UsernamePasswordAuthenticationToken]

}
