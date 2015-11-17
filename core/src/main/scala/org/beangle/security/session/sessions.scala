/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.session

import java.io.{ Serializable => jSerializable }
import java.security.Principal
import org.beangle.security.authc.Account
import org.beangle.security.context.SecurityContext

object Session {
  val DefaultTimeOut: Short = 30 * 60

  def user: String = {
    SecurityContext.session.principal.getName
  }

  trait Agent extends Serializable {

    def os: String

    def agent: String

    def ip: String

  }

  trait Status extends Serializable {

    def lastAccessAt: Long
  }

  class Data(val principal: Account, val agent: Agent, val loginAt: Long, val timeout: Short) extends Serializable

  class DefaultAgent(val os: String, val agent: String, val ip: String) extends Agent

  class DefaultStatus(val lastAccessAt: Long) extends Status
}

trait Session {

  def id: String

  def principal: Account

  def agent: Session.Agent

  def status: Session.Status

  def loginAt: Long

  /** the time in seconds that the session may remain idle before expiring.*/
  def timeout: Short

  def onlineTime: Long

  def stop(): Unit

}

class DefaultSession(val id: String, registry: SessionRegistry, val data: Session.Data, val status: Session.Status) extends Session {

  override def principal: Account = {
    data.principal
  }

  override def agent: Session.Agent = {
    data.agent
  }

  override def loginAt: Long = {
    data.loginAt
  }

  override def timeout: Short = {
    data.timeout
  }

  override def stop(): Unit = {
    registry.remove(id)
  }

  override def onlineTime: Long = {
    System.currentTimeMillis() - loginAt
  }

  def clone(newer: Session.Status): Session = {
    new DefaultSession(id, registry, data, newer)
  }
}

trait SessionBuilder {
  def build(key: String, registry: SessionRegistry, auth: Account, agent: Session.Agent, loginAt: Long, timeout: Short): Session
  def build(key: String, registry: SessionRegistry, data: Session.Data, status: Session.Status): Session
  def build(old: Session, status: Session.Status): Session
}

object DefaultSessionBuilder extends SessionBuilder {

  override def build(sessionId: String, registry: SessionRegistry, auth: Account, agent: Session.Agent, loginAt: Long, timeout: Short): Session = {
    new DefaultSession(sessionId, registry, new Session.Data(auth, agent, loginAt, timeout), new Session.DefaultStatus(System.currentTimeMillis))
  }

  override def build(sessionId: String, registry: SessionRegistry, data: Session.Data, status: Session.Status): Session = {
    new DefaultSession(sessionId, registry, data, status)
  }

  def build(old: Session, status: Session.Status): Session = {
    old.asInstanceOf[DefaultSession].clone(status)
  }
}

