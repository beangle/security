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
package org.beangle.security.session.profile

import org.beangle.security.authc.Account
import org.beangle.security.session.{ AbstractSessionRegistry, Session }
import org.beangle.commons.event.EventListener
import org.beangle.commons.event.Event

/**
 * @author chaostone
 */
abstract class ProfiledSessionRegistry extends AbstractSessionRegistry with EventListener[ProfileChangeEvent] {

  var profileProvider: ProfileProvider = DefaultProfileProvider

  protected def getMaxSession(auth: Account): Int = {
    profileProvider.getProfile(auth).maxSession
  }

  protected def getTimeout(auth: Account): Short = {
    profileProvider.getProfile(auth).timeout
  }

  protected def getProfileId(auth: Account): Int = {
    profileProvider.getProfile(auth).id
  }

  protected def getProfile(auth: Account): SessionProfile = {
    profileProvider.getProfile(auth)
  }
  /**
   * Handle an application event.
   */
  def onEvent(event: ProfileChangeEvent): Unit = {

  }
  /**
   * Determine whether this listener actually supports the given event type.
   */
  def supportsEventType(eventType: Class[_ <: Event]): Boolean = {
    eventType == classOf[ProfileChangeEvent]
  }

  /**
   * Determine whether this listener actually supports the given source type.
   */
  def supportsSourceType(sourceType: Class[_]): Boolean = {
    true
  }

}