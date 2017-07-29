/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
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

import java.time.{ Duration, Instant }

import org.beangle.security.authc.Account
import org.beangle.security.context.SecurityContext

object Session {
  val DefaultTimeOut = Duration.ofSeconds(30 * 60)

  def user: String = {
    SecurityContext.session.principal.getName
  }

  trait Client extends Serializable {
    def ip: String
  }

  trait Status extends Serializable {
    def lastAccessAt: Instant
  }

  class Data(val account: Account, val client: Client, val loginAt: Instant, val timeout: Duration) extends Serializable

  class AgentClient(val agent: String, val ip: String, val os: String) extends Client

  class SsoClient(val token: Any, agent: String, ip: String, os: String) extends AgentClient(agent, ip, os)

  class DefaultStatus(val lastAccessAt: Instant) extends Status
}

trait Session {

  def id: String

  def principal: Account

  def client: Session.Client

  def status: Session.Status

  def loginAt: Instant

  def timeout: Duration

  def stop(): Unit

}

class DefaultSession(val id: String, registry: SessionRegistry, val data: Session.Data, val status: Session.Status) extends Session {

  override def principal: Account = {
    data.account
  }

  override def client: Session.Client = {
    data.client
  }

  override def loginAt: Instant = {
    data.loginAt
  }

  override def timeout: Duration = {
    data.timeout
  }

  override def stop(): Unit = {
    registry.remove(id)
  }

  def onlineTime: Duration = {
    Duration.ofSeconds(Instant.now().getEpochSecond - loginAt.getEpochSecond)
  }

  def clone(newer: Session.Status): Session = {
    new DefaultSession(id, registry, data, newer)
  }
}

trait SessionBuilder {
  def build(key: String, registry: SessionRegistry, auth: Account, agent: Session.Client, loginAt: Instant, timeout: Duration): Session
  def build(key: String, registry: SessionRegistry, data: Session.Data, status: Session.Status): Session
  def build(old: Session, status: Session.Status): Session
}

object DefaultSessionBuilder extends SessionBuilder {

  override def build(sessionId: String, registry: SessionRegistry, auth: Account, agent: Session.Client, loginAt: Instant, timeout: Duration): Session = {
    new DefaultSession(sessionId, registry, new Session.Data(auth, agent, loginAt, timeout), new Session.DefaultStatus(Instant.now))
  }

  override def build(sessionId: String, registry: SessionRegistry, data: Session.Data, status: Session.Status): Session = {
    new DefaultSession(sessionId, registry, data, status)
  }

  def build(old: Session, status: Session.Status): Session = {
    old.asInstanceOf[DefaultSession].clone(status)
  }
}
