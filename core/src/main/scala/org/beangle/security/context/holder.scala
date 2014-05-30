/*
 * Beangle, Agile Java/Scala Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2013, Beangle Software.
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

/**
 * Associates a given {@link SecurityContext} with the current execution thread.
 * <p>
 * This object provides a series of methods that delegate to an instance of
 * {@link org.beangle.security.core.context.SecurityContextHolder} . The purpose of the
 * class is to provide a convenient way to specify the holder that should be used for a given JVM.
 * This is a JVM-wide setting.
 * </p>
 *
 * <p>
 * It can set the system property keyed on {@link #SYSTEM_PROPERTY} to specify the desired holder name <code>String</code>.
 * </p>
 *
 * @author chaostone
 */
object ContextHolder {

  private val holder = buildHolder(System.getProperty("beangle.security.holder", "threadLocal"))

  def context_=(context: SecurityContext) {
    holder.context = context
  }

  def context: Option[SecurityContext] = if (null == holder.context) None else Some(holder.context)

  /**
   * <ul>
   * <li> threadLocal
   * <li> inheritableThreadLocal
   * <li> global
   * </ul>
   */
  def buildHolder(strategyName: String): ContextHolder = {
    strategyName match {
      case "threadLocal" => new ThreadLocalHolder(false)
      case "inheritableThreadLocal" => new ThreadLocalHolder(true)
      case "global" => GlobalHolder
      case _ => {
        try {
          val clazz = Class.forName(strategyName).asInstanceOf[Class[ContextHolder]]
          val customStrategy = clazz.getConstructor()
          customStrategy.newInstance(Array()).asInstanceOf[ContextHolder]
        } catch {
          case ex: Exception => throw Throwables.propagate(ex)
        }
      }
    }
  }

  def hasValidContext: Boolean = !context.isEmpty && SecurityContext.Anonymous != context.get.principal

  def principal: Any = context match {
    case None => SecurityContext.Anonymous
    case Some(context) => context.principal
  }
}

/**
 * A holder for storing security context information against a thread.
 * <p>
 * The preferred holder is loaded by
 * {@link org.beangle.security.core.context.SecurityContextHolder}.
 * </p>
 *
 * @author chaostone
 * @version $Id: SecurityContextHolderStrategy.java 2142 2007-09-21 18:18:21Z $
 */
trait ContextHolder {

  def context: SecurityContext

  def context_=(context: SecurityContext)
}

/**
 * A <code>static</code> field-based implementation of
 * {@link org.beangle.security.core.context.SecurityContextHolder}.
 * <p>
 * This means that all instances in the JVM share the same <code>SecurityContext</code>. This is
 * generally useful with rich clients, such as Swing.
 * </p>
 *
 * @author chaostone
 */
object GlobalHolder extends ContextHolder {

  var context: SecurityContext = _
}

/**
 * A <code>ThreadLocal</code>-based implementation of
 * {@link org.beangle.security.core.context.SecurityContextHolder}.
 *
 * @author chaostone
 * @see java.lang.ThreadLocal
 */
class ThreadLocalHolder(inheritable: Boolean) extends ContextHolder {

  private val contexts = if (inheritable) new ThreadLocal[SecurityContext] else new InheritableThreadLocal[SecurityContext]

  def context: SecurityContext = contexts.get

  def context_=(newContext: SecurityContext) {
    contexts.set(newContext)
  }
}