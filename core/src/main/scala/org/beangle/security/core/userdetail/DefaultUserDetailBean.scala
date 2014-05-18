package org.beangle.security.core.userdetail

import java.util.Collection
import org.beangle.commons.lang.Objects
import scala.reflect.{ BeanProperty, BooleanBeanProperty }
import scala.collection.JavaConversions._
import org.beangle.security.core.Authority
import org.beangle.security.core.authority.GrantedAuthority

@SerialVersionUID(1L)
class DefaultUserDetailBean(var username: String, var password: String, var enabled: Boolean, var accountExpired: Boolean, var credentialsExpired: Boolean, var accountLocked: Boolean, var authorities: Seq[_ <: Authority]) extends UserDetail {

  if (((username == null) || "" == username) || (password == null)) {
    throw new IllegalArgumentException("Cannot pass null or empty values to constructor")
  }

  def this(username: String, password: String, authorities: Seq[_ <: Authority]) {
    this(username, password, true, false, false, false, authorities)
  }

  override def equals(rhs: Any): Boolean = {
    if (!(rhs.isInstanceOf[DefaultUserDetailBean]) || (rhs == null)) {
      return false
    }
    val user = rhs.asInstanceOf[DefaultUserDetailBean]
    Objects.equalsBuilder().add(username, user.username).add(password, user.password).add(accountExpired, user.accountLocked).add(accountLocked, user.accountLocked).add(credentialsExpired, user.credentialsExpired).add(enabled, user.enabled).isEquals
  }

  override def hashCode(): Int = {
    if ((null == username)) 629 else username.hashCode
  }

  override def toString(): String = {
    val sb = new StringBuffer()
    sb.append(super.toString).append(": ")
    sb.append("Username: ").append(this.username).append("; ")
    sb.append("Password: [PROTECTED]; ")
    sb.append("Enabled: ").append(this.enabled).append("; ")
    sb.append("AccountExpired: ").append(this.accountExpired).append("; ")
    sb.append("credentialsExpired: ").append(this.credentialsExpired).append("; ")
    sb.append("AccountLocked: ").append(this.accountLocked).append("; ")
    if (!authorities.isEmpty) {
      sb.append("Granted Authorities: ")
      for (authority <- authorities) 
        sb.append(authority.toString).append(", ")
      sb.deleteCharAt(sb.length - 1)
    } else {
      sb.append("Not granted any authorities")
    }
    sb.toString
  }
}
