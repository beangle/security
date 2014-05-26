package org.beangle.security.authc

import org.beangle.commons.bean.Initializing
import org.beangle.commons.lang.{ Objects, Strings }
import org.beangle.commons.logging.Logging
import org.beangle.commons.text.i18n.TextResource
import org.beangle.commons.text.i18n.impl.NullTextResource
import org.beangle.security.authz.AuthorizationInfo
import org.beangle.security.realm.Realm

trait Account extends AuthenticationInfo with AuthorizationInfo with Mergable {

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialsExpired: Boolean

  def disabled: Boolean
}

class SimpleAccount(val principal: Any, val credentials: Any) extends Account with Mergable {

  var accountExpired: Boolean = _

  var accountLocked: Boolean = _

  var credentialsExpired: Boolean = _

  var disabled: Boolean = _

  var roles: List[Any] = List.empty

  var permissions: List[Any] = List.empty

  var details: Map[String, Any] = Map.empty

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: SimpleAccount =>
        Objects.equalsBuilder().add(principal, test.principal)
          .add(credentials, test.credentials)
          .add(details, test.details)
          .add(roles, test.roles)
          .add(permissions, test.permissions)
          .isEquals
      case _ => false
    }
  }

  override def toString(): String = {
    Objects.toStringBuilder(this).add("Principal:", principal)
      .add("AccountExpired: ", accountExpired)
      .add("credentialsExpired: ", credentialsExpired)
      .add("AccountLocked: ", accountLocked)
      .add("Disabled: ", disabled)
      .add("Roles: ", roles.mkString(","))
      .add("Permissions: ", permissions.mkString(",")).toString
  }

  override def merge(info: AuthenticationInfo): this.type = {
    info match {
      case ac: Account => {
        if (ac.accountExpired) this.accountExpired = true
        if (ac.accountLocked) this.accountLocked = true
        if (ac.credentialsExpired) this.credentialsExpired = true
        if (ac.disabled) this.disabled = true
        if (!ac.roles.isEmpty) this.roles ::= ac.roles
        if (!ac.permissions.isEmpty) this.permissions ::= ac.permissions
        if (!ac.details.isEmpty) this.details ++= ac.details
      }
    }
    this
  }

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
      val ex = new AuthenticationException("cannot find username for " + token.principal)
      ex.token = token
      throw ex
    }
    val account = loadAccount(token.principal)

    if (null != account) {
      if (null == merged) {
        merged = account
        credentialsCheck(token, account)
      } else merged.merge(account)

      additionalCheck(merged)
    } else {
      if (null != merged) throw new UsernameNotFoundException(s"Cannot find account data for $token", null)
    }
    merged
  }

  protected def additionalCheck(ac: Account) {
    if (ac.accountLocked)
      throw new LockedException(tr("AccountStatusChecker.locked", "User account is locked"), ac)
    if (ac.disabled)
      throw new DisabledException(tr("AccountStatusChecker.disabled", "User is disabled"), ac)
    if (ac.accountExpired)
      throw new AccountExpiredException(tr("AccountStatusChecker.expired", "User account has expired"), ac)
    if (ac.credentialsExpired)
      throw new CredentialsExpiredException(tr("AccountStatusChecker.credentialsExpired", "User credentials have expired"), ac)
  }

  protected def loadAccount(principal: Any): Account

  protected def credentialsCheck(token: AuthenticationToken, account: Account): Unit

  def supports(token: AuthenticationToken): Boolean = token.isInstanceOf[UsernamePasswordAuthenticationToken]

}
