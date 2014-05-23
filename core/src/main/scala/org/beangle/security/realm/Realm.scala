package org.beangle.security.realm

import org.beangle.security.authc.AuthenticationToken
import org.beangle.security.authc.AuthenticationInfo

trait Realm {
  /**
   * @throws AuthenticationException
   */
  def getAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo

  def supports(token: Class[_ <: AuthenticationToken]): Boolean
}