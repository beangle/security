package org.beangle.security.realm.ldap

import org.beangle.security.authc.{ Account, AccountStore, DefaultAccount }

import LdapUserService.CommonName

/**
 * @author chaostone
 */
class SimpleLdapUserStore(ldapUserService: LdapUserService) extends AccountStore {
  override def load(principal: Any): Option[Account] = {
    ldapUserService.getUserDN(principal.toString) match {
      case Some(dn) =>
        Some(new DefaultAccount(principal, ldapUserService.getAttributes(dn, CommonName)(CommonName).toString))
      case None => None
    }
  }
}