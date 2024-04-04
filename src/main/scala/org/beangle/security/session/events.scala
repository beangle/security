/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.session

import org.beangle.commons.event.Event

@SerialVersionUID(-6802410177820837015L)
class LoginEvent(src: Session) extends Event(src) {
  def session: Session = source.asInstanceOf[Session]
}

@SerialVersionUID(5562102005395894399L)
class LogoutEvent(src: Session, var reason: String = null) extends Event(src) {

  def session: Session = source.asInstanceOf[Session]
}
