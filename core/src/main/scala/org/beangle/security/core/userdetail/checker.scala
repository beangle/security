package org.beangle.security.core.userdetail

import org.beangle.commons.text.i18n.TextResource
import org.beangle.commons.text.i18n.impl.NullTextResource
import org.beangle.security.auth.AccountExpiredException
import org.beangle.security.auth.CredentialsExpiredException
import org.beangle.security.auth.DisabledException
import org.beangle.security.auth.LockedException

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
