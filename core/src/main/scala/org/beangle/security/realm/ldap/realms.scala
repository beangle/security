package org.beangle.security.realm.ldap

import org.beangle.security.authc.{ AbstractAccountRealm, Account, AuthenticationToken, BadCredentialsException }
import org.beangle.security.authc.DefaultAccount

class DefaultLdapRealm(val userStore: LdapUserStore, val passwordValidator: LdapPasswordValidator) extends AbstractAccountRealm {

  protected override def credentialsCheck(token: AuthenticationToken, account: Account): Unit = {
    if (!passwordValidator.verify(account.getName, token.credentials.toString)) throw new BadCredentialsException("Incorrect password", token, null)
  }
  protected override def loadAccount(principal: Any): Option[Account] = userStore.load(principal)
}