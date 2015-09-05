package org.beangle.security.realm

import org.beangle.security.authc.AuthenticationException
import org.beangle.security.authc.Account
import org.beangle.security.authc.AuthenticationToken

trait Realm {

  @throws(classOf[AuthenticationException])
  def getAccount(token: AuthenticationToken): Account

  def supports(token: AuthenticationToken): Boolean
}
