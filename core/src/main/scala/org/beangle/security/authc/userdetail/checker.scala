package org.beangle.security.authc.userdetail

import org.beangle.commons.text.i18n.TextResource
import org.beangle.commons.text.i18n.impl.NullTextResource
import org.beangle.security.authc.{AccountExpiredException, CredentialsExpiredException, DisabledException, LockedException}

trait UserDetailChecker {

  def check(toCheck: UserDetail): Unit
}

class AccountStatusChecker extends UserDetailChecker {

  var textResource: TextResource = new NullTextResource()

  def check(user: UserDetail) {
    if (user.accountLocked) {
      throw new LockedException(textResource.getText("AbstractUserDetailsAuthenticationProvider.locked", "User account is locked"), user)
    }
    if (!user.enabled) {
      throw new DisabledException(textResource.getText("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"), user)
    }
    if (user.accountExpired) {
      throw new AccountExpiredException(textResource.getText("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"), user)
    }
    if (user.credentialsExpired) {
      throw new CredentialsExpiredException(textResource.getText("AbstractUserDetailsAuthenticationProvider.credentialsExpired", "User credentials have expired"), user)
    }
  }

}
