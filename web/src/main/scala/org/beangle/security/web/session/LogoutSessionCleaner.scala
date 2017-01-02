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
package org.beangle.security.web.session

import org.beangle.commons.event.{ Event, EventListener }
import org.beangle.commons.web.session.HttpSessionDestroyedEvent
import org.beangle.security.session.SessionRegistry

class LogoutSessionCleaner(val sessionRegistry: SessionRegistry) extends EventListener[HttpSessionDestroyedEvent] {

  // 当会话消失时，退出用户
  override def onEvent(event: HttpSessionDestroyedEvent): Unit = sessionRegistry.remove(event.session.getId)

  override def supportsEventType(eventType: Class[_ <: Event]): Boolean = classOf[HttpSessionDestroyedEvent].isAssignableFrom(eventType)

  override def supportsSourceType(sourceType: Class[_]): Boolean = true

}
