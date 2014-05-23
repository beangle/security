package org.beangle.security.authc

import org.beangle.commons.lang.Objects
import org.beangle.security.authz.Authority
import java.security.Principal

/**
 * Authentication Information
 * @author chaostone
 */
trait AuthenticationInfo extends Principal with Serializable {

  def principal: Any

  def details: Any
  
  def getName = principal.toString

  override def hashCode: Int = if (null == principal) 629 else principal.hashCode()
}

/**
 * Authentication Info can merge with others
 */
trait MergableAuthenticationInfo extends AuthenticationInfo{
  def merge(info:AuthenticationInfo):this.type
}

/**
 * Authentication Token used before authentication
 */
trait AuthenticationToken extends Principal with Serializable {

  def principal: Any

  def credentials: Any

  def details: Any
}

/**
 * Simple Authentication Token 
 */
@SerialVersionUID(3966615358056184985L)
class SimpleAuthenticationToken(val principal: Any, val credentials: Any) extends AuthenticationToken {

  var details: Any = _

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: SimpleAuthenticationToken =>
        Objects.equalsBuilder().add(principal, test.principal)
          .add(credentials, test.credentials).add(details, test.details)
          .isEquals
      case _ => false
    }
  }

  override def hashCode: Int = if (null == principal) 629 else principal.hashCode()

  override def getName: String = {
    this.principal match {
      case jPrincipal: java.security.Principal => jPrincipal.getName
      case null => ""
      case obj: Any => obj.toString
    }
  }
}

object AnonymousToken extends SimpleAuthenticationToken("anonymous","")
