package org.beangle.security.authc

import org.beangle.security.authz.AuthorizationInfo
import org.beangle.commons.lang.Objects
import org.beangle.commons.text.i18n.impl.NullTextResource
import org.beangle.commons.text.i18n.TextResource

trait Account extends AuthenticationInfo with AuthorizationInfo {

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialsExpired: Boolean

  def enabled: Boolean
}

class SimpleAccount(val principal: Any) extends Account {

  var accountExpired: Boolean = _

  var accountLocked: Boolean = _

  var credentialsExpired: Boolean = _

  var enabled: Boolean = _

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
      .add("enabled", enabled).add("AccountExpired: ", accountExpired)
      .add("credentialsExpired: ", credentialsExpired)
      .add("AccountLocked: ", accountLocked)
      .add("Roles: ", roles.mkString(","))
      .add("Permissions: ", permissions.mkString(",")).toString
  }

}

trait AccountChecker {

  def check(account: Account): Unit
}

class AccountStatusChecker extends AccountChecker {

  var textResource: TextResource = new NullTextResource()

  def check(account: Account) {
    if (account.accountLocked)
      throw new LockedException(textResource.getText("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"), account)
    if (!account.enabled)
      throw new DisabledException(textResource.getText("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"), account)
    if (account.accountExpired)
      throw new AccountExpiredException(textResource.getText("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"), account)
    if (account.credentialsExpired)
      throw new CredentialsExpiredException(textResource.getText("AbstractUserDetailsAuthenticationProvider.credentialsExpired", "User credentials have expired"), account)
  }

}
