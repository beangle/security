package org.beangle.security.authc

import org.beangle.commons.lang.Objects
import org.beangle.security.authz.Authority
import org.beangle.security.authc.userdetail.UserDetail
import java.security.Principal

/**
 * 认证信息
 *
 * @author chaostone
 */
trait AuthenticationInfo extends Principal with Serializable {

  def principal: Any

  def credentials: Any

  def authorities: List[Authority]

  def details: Any

}

/**
 * Authentication Token used before authentication
 */
trait AuthenticationToken extends Principal with Serializable {

  def principal: Any

  def credentials: Any

  def details: Any
}

@SerialVersionUID(3966615358056184985L)
class AuthenticationTokenBean(val principal: Any, val credentials: Any) extends AuthenticationToken {

  var details: Any = _

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: AuthenticationTokenBean =>
        Objects.equalsBuilder().add(principal, test.principal)
          .add(credentials, test.credentials).add(details, test.details)
          .isEquals
      case _ => false
    }
  }

  override def hashCode: Int = if (null == principal) 629 else principal.hashCode()

  override def getName: String = {
    this.principal match {
      case detail: UserDetail => detail.username
      case jPrincipal: java.security.Principal => jPrincipal.getName
      case null => ""
      case obj: Any => obj.toString
    }
  }
}
@SerialVersionUID(3966615358056184985L)
class AuthenticationInfoBean(val principal: Any, val credentials: Any, val authorities: List[Authority]) extends AuthenticationInfo {

  var details: Any = _

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: AuthenticationInfoBean =>
        Objects.equalsBuilder().add(principal, test.principal)
          .add(credentials, test.credentials).add(details, test.details)
          .add(authorities, test.authorities)
          .isEquals
      case _ => false
    }
  }

  override def hashCode: Int = if (null == principal) 629 else principal.hashCode()

  override def getName: String = {
    this.principal match {
      case detail: UserDetail => detail.username
      case jPrincipal: java.security.Principal => jPrincipal.getName
      case null => ""
      case obj: Any => obj.toString
    }
  }
}

class AnonymousInfo(authorities: List[Authority] = List.empty) extends AuthenticationInfoBean("anonymous", "", authorities) {
  override def equals(obj: Any): Boolean = {
    obj match {
      case test: AnonymousInfo => Objects.equals(principal, test.principal)
      case _ => false
    }
  }
}

object AnonymousToken extends AuthenticationTokenBean("anonymous", "")
