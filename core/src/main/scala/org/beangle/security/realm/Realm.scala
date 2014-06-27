package org.beangle.security.realm

import org.beangle.security.authc.{AuthenticationInfo, AuthenticationToken}
import org.beangle.security.authc.AuthenticationException

trait Realm {
  
  @throws(classOf[AuthenticationException])
  def getAuthenticationInfo(token: AuthenticationToken): AuthenticationInfo

  def supports(token : AuthenticationToken): Boolean
}
