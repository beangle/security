package org.beangle.security.authc

import org.beangle.security.authz.AuthorizationInfo
import org.beangle.commons.lang.Objects
import org.beangle.commons.text.i18n.impl.NullTextResource
import org.beangle.commons.text.i18n.TextResource

trait Account extends AuthenticationInfo with AuthorizationInfo {

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialsExpired: Boolean

  def disabled: Boolean
}

class SimpleAccount(val principal: Any) extends Account with MergableAuthenticationInfo {

  var accountExpired: Boolean = _

  var accountLocked: Boolean = _

  var credentialsExpired: Boolean = _

  var disabled: Boolean = _

  var roles: List[Any] = List.empty

  var permissions: List[Any] = List.empty

  var details: Any = _

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: SimpleAccount =>
        Objects.equalsBuilder().add(principal, test.principal)
          .add(details, test.details)
          .add(roles, test.roles)
          .add(permissions, test.permissions)
          .isEquals
      case _ => false
    }
  }

  override def toString(): String = {
    Objects.toStringBuilder(this).add("principal", principal)
      .add("AccountExpired: ", accountExpired)
      .add("credentialsExpired: ", credentialsExpired)
      .add("AccountLocked: ", accountLocked)
      .add("Disabled: ", disabled)
      .add("Roles: ", roles.mkString(","))
      .add("Permissions: ", permissions.mkString(",")).toString
  }

  override def merge(info: AuthenticationInfo): Unit = {
    info match {
      case ac: Account => {
        if (ac.accountExpired) this.accountExpired = true
        if (ac.accountLocked) this.accountLocked = true
        if (ac.credentialsExpired) this.credentialsExpired = true
        if (ac.disabled) this.disabled = true
        if (!ac.roles.isEmpty) this.roles ::= ac.roles
        if (!ac.permissions.isEmpty) this.permissions ::= ac.permissions
        if (null != ac.details) this.details = ac.details
      }
    }
  }

}

trait AccountChecker {

  def check(account: Account): Unit
}

class AccountStatusChecker extends AccountChecker {

  var tr: TextResource = new NullTextResource()

  def check(ac: Account) {
    if (ac.accountLocked)
      throw new LockedException(tr("AccountStatusChecker.locked", "User account is locked"), ac)
    if (ac.disabled)
      throw new DisabledException(tr("AccountStatusChecker.disabled", "User is disabled"), ac)
    if (ac.accountExpired)
      throw new AccountExpiredException(tr("AccountStatusChecker.expired", "User account has expired"), ac)
    if (ac.credentialsExpired)
      throw new CredentialsExpiredException(tr("AccountStatusChecker.credentialsExpired", "User credentials have expired"), ac)
  }

}
