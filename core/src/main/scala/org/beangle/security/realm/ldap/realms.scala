package org.beangle.security.realm.ldap

import org.beangle.security.authc.{ AbstractAccountRealm, Account, AuthenticationToken, BadCredentialsException }
import org.beangle.security.authc.DefaultAccount

class DefaultLdapRealm extends AbstractAccountRealm {
  
  var passwordValidator: LdapPasswordValidator = _

  var userStore: LdapUserStore = _

  protected override def credentialsCheck(token: AuthenticationToken, account: Account): Unit = {
    if (!passwordValidator.verify(account.getName, token.credentials.toString)) throw new BadCredentialsException("Incorrect password",token, null)
  }

  protected def loadAccount(principal: Any): Account = {
    val uid = principal.toString
    val dn = userStore.getUserDN(uid)
    if (null != dn) {
      val account = new DefaultAccount(principal, userStore.getPassword(uid))
      account
    } else null
  }
}