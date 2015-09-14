package org.beangle.security.session.profile

import org.beangle.commons.lang.Objects
import org.beangle.security.session.Session

/**
 * Session Profile
 */
trait SessionProfile {
  def id: Int
  def capacity: Int
  def maxSession: Int
  def timeout: Short
}

object DefaultSessionProfile extends DefaultSessionProfile(1) {
  this.capacity = Short.MaxValue
  this.maxSession = 2
  this.timeout = Session.DefaultTimeOut
}

class DefaultSessionProfile(val id: Int) extends SessionProfile {
  var capacity: Int = _
  var maxSession: Int = _
  var timeout: Short = _

  override def toString(): String = {
    Objects.toStringBuilder(this).add("id", id)
      .add("capacity", capacity).add("maxSession", maxSession)
      .add("timeout", timeout).toString
  }
}