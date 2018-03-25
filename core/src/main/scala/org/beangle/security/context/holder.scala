/*
 * Beangle, Agile Development Scaffold and Toolkits.
 *
 * Copyright © 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.context

import org.beangle.commons.lang.Throwables
import org.beangle.security.session.Session
import org.beangle.security.SecurityException
import org.beangle.commons.security.Request

object SecurityContext {
  val Anonymous = "anonymous"

  private val holder = buildHolder(System.getProperty("beangle.security.holder", "threadLocal"))

  /**
   * <ul>
   * <li> threadLocal
   * <li> inheritableThreadLocal
   * <li> global
   * </ul>
   */
  private def buildHolder(strategyName: String): SecurityContextHolder = {
    strategyName match {
      case "threadLocal"            => new ThreadLocalHolder(false)
      case "inheritableThreadLocal" => new ThreadLocalHolder(true)
      case "global"                 => GlobalHolder
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

  def clear(): Unit = {
    holder.set(null)
  }
  def set(ctx: SecurityContext): Unit = {
    holder.set(ctx)
  }

  def get: SecurityContext = {
    holder.get
  }
}

class SecurityContext(val session: Option[Session], val request: Request, val root: Boolean, val runAs: Option[String]) {

  def isValid: Boolean = {
    session.isDefined
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

  def get: SecurityContext

  def set(context: SecurityContext)
}

/**
 * A <code>static</code> field-based implementation of {@link org.beangle.security.core.context. ContextHolder}.
 */
object GlobalHolder extends SecurityContextHolder {

  var context: SecurityContext = _

  def get: SecurityContext = {
    context
  }
  def set(context: SecurityContext): Unit = {
    this.context = context
  }
}

/**
 * A <code>ThreadLocal</code>-based implementation of  {@link org.beangle.security.core.context.ContextHolder}.
 */
class ThreadLocalHolder(inheritable: Boolean) extends SecurityContextHolder {

  private val context =
    if (inheritable) {
      new ThreadLocal[SecurityContext]
    } else {
      new InheritableThreadLocal[SecurityContext]
    }

  def get: SecurityContext = {
    context.get
  }
  def set(ctx: SecurityContext): Unit = {
    context.set(ctx)
  }
}
