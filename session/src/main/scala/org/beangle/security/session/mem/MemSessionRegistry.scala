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
package org.beangle.security.session.mem

import java.{ util => ju }
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.Account
import org.beangle.security.session.{ DefaultSessionBuilder, LoginEvent, LogoutEvent, Session, SessionBuilder }
import org.beangle.security.session.profile.ProfiledSessionRegistry
import org.beangle.security.session.util.UpdateDelayGenerator

/**
 * Hold session in memory
 */
class MemSessionRegistry extends ProfiledSessionRegistry with Logging with EventPublisher {

  protected val principals = new collection.concurrent.TrieMap[Any, collection.mutable.HashSet[String]]

  protected val sessionids = new collection.concurrent.TrieMap[String, Session]

  private val accessDelayMillis = new UpdateDelayGenerator().generateDelayMilliTime()

  var builder: SessionBuilder = DefaultSessionBuilder


  override def getByPrincipal(principal: String): Seq[Session] = {
    principals.get(principal) match {
      case None => List.empty
      case Some(sids) => {
        val list = new collection.mutable.ListBuffer[Session]
        for (sessionid <- sids) list ++= get(sessionid)
        list
      }
    }
  }

  override def get(sessionId: String): Option[Session] = {
    if (null == sessionId) None else sessionids.get(sessionId)
  }

  override def register(sessionId: String, auth: Account, client: Session.Client): Session = {
    val principal = auth.getName
    val existed = get(sessionId) match {
      case Some(existed) => {
        if (existed.principal.getName() != principal) {
          tryAllocate(sessionId, auth)
          remove(sessionId)
        }
      }
      case None => tryAllocate(sessionId, auth)
    }

    val newSession = builder.build(sessionId, this, auth, client, System.currentTimeMillis, getTimeout(auth))
    sessionids.put(sessionId, newSession)
    principals.get(principal) match {
      case None       => principals.put(principal, new collection.mutable.HashSet += sessionId)
      case Some(sids) => sids += sessionId
    }
    publish(new LoginEvent(newSession))
    newSession
  }

  override def remove(sessionId: String): Option[Session] = {
    get(sessionId) match {
      case Some(s) => {
        sessionids.remove(sessionId)
        val principal = s.principal
        logger.debug(s"Remove session $sessionId for $principal")
        val sids = principals.get(principal) foreach { sids =>
          sids.remove(sessionId)
          if (sids.isEmpty) principals.remove(principal)
        }
        release(s)
        publish(new LogoutEvent(s))
        Some(s)
      }
      case None => None
    }
  }

  override def access(sessionId: String, accessAt: Long, accessed: String): Option[Session] = {
    get(sessionId) match {
      case s @ Some(session) =>
        if ((accessAt - session.status.lastAccessAt) > accessDelayMillis) {
          sessionids.put(session.id, builder.build(session, new Session.DefaultStatus(accessAt)))
        }
        s
      case None => None
    }
  }

  protected override def allocate(auth: Account, sessionId: String): Boolean = true
  protected override def release(session: Session): Unit = {}

}