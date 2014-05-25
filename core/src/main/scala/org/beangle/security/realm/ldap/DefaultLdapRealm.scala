package org.beangle.security.realm.ldap

import org.beangle.security.authc.{ AbstractAccountRealm, Account, AuthenticationToken, BadCredentialsException }

class DefaultLdapRealm extends AbstractAccountRealm {

  var ldapValidator: LdapValidator = _

  protected def additionalCheck(token: AuthenticationToken, account: Account): Unit = {
    if (!ldapValidator.verifyPassword(account.getName, token.credentials.toString)) throw new BadCredentialsException("Incorrect password", null)
  }
}