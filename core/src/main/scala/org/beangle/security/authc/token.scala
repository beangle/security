package org.beangle.security.authc

import java.security.Principal

import org.beangle.commons.lang.Objects

object DetailNames {
  val Agent = "agent"
  val Os = "os"
  val Server = "server"
  val Host = "host"
  val Timeout = "timeout"
}
/**
 * Authentication Information
 * @author chaostone
 */
trait AuthenticationInfo extends Principal with Serializable {

  def id: Any

  def principal: Any

  def details: Map[String, Any]

  def getName = principal.toString

  override def hashCode: Int = if (null == principal) 629 else principal.hashCode()
}

/**
 * Authentication Info can merge with others
 */
trait Mergable extends AuthenticationInfo {
  def details_=(data: Map[String, Any])
  def merge(info: AuthenticationInfo): this.type
}

/**
 * Authentication Token used before authentication
 */
trait AuthenticationToken extends Principal with Serializable {

  def principal: Any

  def credentials: Any

  def details: Map[String, Any]

  override def getName: String = {
    this.principal match {
      case jPrincipal: java.security.Principal => jPrincipal.getName
      case null => ""
      case obj: Any => obj.toString
    }
  }

  override def hashCode: Int = if (null == principal) 629 else principal.hashCode()
}

/**
 * Simple Authentication Token
 */
@SerialVersionUID(3966615358056184985L)
class UsernamePasswordAuthenticationToken(val principal: Any, val credentials: Any) extends AuthenticationToken {

  var details: Map[String, Any] = Map.empty

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: UsernamePasswordAuthenticationToken =>
        Objects.equalsBuilder().add(principal, test.principal)
          .add(credentials, test.credentials).add(details, test.details)
          .isEquals
      case _ => false
    }
  }

}

object AnonymousToken extends AuthenticationToken {

  def principal: Any = "anonymous"

  def credentials: Any = ""

  def details: Map[String, Any] = Map.empty

}
