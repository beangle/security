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
package org.beangle.security.session.mem

import java.{ util => ju }

import org.beangle.commons.event.EventPublisher
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.Account
import org.beangle.security.session.{ DefaultSessionBuilder, LoginEvent, LogoutEvent, Session, SessionBuilder, SessionId, SessionKey }
import org.beangle.security.session.profile.ProfiledSessionRegistry

/**
 * Hold session in memory
 */
class MemSessionRegistry extends ProfiledSessionRegistry with Logging with EventPublisher {

  protected val principals = new collection.concurrent.TrieMap[Any, collection.mutable.HashSet[String]]

  protected val sessionids = new collection.concurrent.TrieMap[String, Session]

  var builder: SessionBuilder = new DefaultSessionBuilder

  def isRegisted(principal: String): Boolean = {
    val sids = principals.get(principal)
    (!sids.isEmpty && !sids.get.isEmpty)
  }

  override def get(principal: String, includeExpired: Boolean): Seq[Session] = {
    principals.get(principal) match {
      case None => List.empty
      case Some(sids) => {
        val list = new collection.mutable.ListBuffer[Session]
        for (sessionid <- sids)
          get(SessionId(sessionid)).foreach(info => if (includeExpired || !info.expired) list += info)
        list
      }
    }
  }

  override def getExpired(lastAccessAt: ju.Date): Seq[Session] = {
    val expired = new collection.mutable.ListBuffer[Session]
    sessionids foreach {
      case (id, s) => if (s.expired || s.lastAccessAt.before(lastAccessAt)) expired += s
    }
    expired
  }

  override def get(key: SessionKey): Option[Session] = {
    if (null == key) None
    else sessionids.get(key.sessionId)
  }

  override def register(auth: Account, key: SessionKey): Session = {
    val principal = auth.getName
    val existed = get(key) match {
      case Some(existed) => {
        if (existed.principal.getName() != principal) {
          tryAllocate(key, auth)
          //          existed.remark(" expired with replacement.")
          remove(key)
        }
      }
      case None => tryAllocate(key, auth)
    }

    val newSession = builder.build(key, auth, this, new ju.Date(), getTimeout(auth))
    sessionids.put(key.sessionId, newSession)
    principals.get(principal) match {
      case None       => principals.put(principal, new collection.mutable.HashSet += key.sessionId)
      case Some(sids) => sids += key.sessionId
    }
    publish(new LoginEvent(newSession))
    newSession
  }

  override def remove(key: SessionKey): Option[Session] = {
    get(key) match {
      case Some(s) => {
        sessionids.remove(key.sessionId)
        val principal = s.principal
        logger.debug(s"Remove session $key for $principal")
        val sids = principals.get(principal) foreach { sids =>
          sids.remove(key.sessionId)
          if (sids.isEmpty) principals.remove(principal)
        }
        release(s)
        publish(new LogoutEvent(s))
        Some(s)
      }
      case None => None
    }
  }

  def count(): Int = sessionids.size

  override def stat(): Unit = {}

  protected override def allocate(auth: Account, key: SessionKey): Boolean = true
  /**
   * release slot for user
   */
  protected override def release(session: Session): Unit = {}

}