package org.beangle.security.realm

import org.beangle.security.authc.{AuthenticationInfo, AuthenticationToken}

trait Realm {
  /**
   * @throws AuthenticationException
   */
  def getAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo

  def supports(token : AuthenticationToken): Boolean
}
