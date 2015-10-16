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
package org.beangle.security.context

import org.beangle.commons.lang.Throwables
import org.beangle.security.session.Session

object SecurityContext {
  val Anonymous = "anonymous"

  /**
   * <ul>
   * <li> threadLocal
   * <li> inheritableThreadLocal
   * <li> global
   * </ul>
   */
  private def buildHolder(strategyName: String): SecurityContextHolder = {
    strategyName match {
      case "threadLocal" => new ThreadLocalHolder(false)
      case "inheritableThreadLocal" => new ThreadLocalHolder(true)
      case "global" => GlobalHolder
      case _ => {
        try {
          val clazz = Class.forName(strategyName).asInstanceOf[Class[SecurityContextHolder]]
          val customStrategy = clazz.getConstructor()
          customStrategy.newInstance(Array()).asInstanceOf[SecurityContextHolder]
        } catch {
          case ex: Exception => throw Throwables.propagate(ex)
        }
      }
    }
  }
  private val holder = buildHolder(System.getProperty("beangle.security.holder", "threadLocal"))

  def session_=(session: Session): Unit = {
    holder.session = session
  }

  def getSession: Option[Session] = {
    if (null == holder.session) None else Some(holder.session)
  }

  def session: Session = {
    if (null == holder.session) throw new SecurityException("Not Login") else holder.session
  }

  def hasValidContext: Boolean = {
    val sess = getSession
    !sess.isEmpty && Anonymous != sess.get.principal
  }

  def principal: Any = getSession match {
    case None => SecurityContext.Anonymous
    case Some(session) => session.principal
  }
}

/**
 * A holder for storing security context information against a thread.
 * <p>
 * The preferred holder is loaded by
 * {@link org.beangle.security.core.context.ContextHolder}.
 * </p>
 *
 */
trait SecurityContextHolder {

  def session: Session

  def session_=(session: Session)
}

/**
 * A <code>static</code> field-based implementation of {@link org.beangle.security.core.context. ContextHolder}.
 */
object GlobalHolder extends SecurityContextHolder {

  var session: Session = _
}

/**
 * A <code>ThreadLocal</code>-based implementation of  {@link org.beangle.security.core.context.ContextHolder}.
 */
class ThreadLocalHolder(inheritable: Boolean) extends SecurityContextHolder {

  private val sessions = if (inheritable) new ThreadLocal[Session] else new InheritableThreadLocal[Session]

  def session: Session = sessions.get

  def session_=(newSession: Session): Unit = sessions.set(newSession)
}