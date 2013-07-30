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
package org.beangle.security.core

import java.security.Principal;
import java.util.Collection;

/**
 * 认证信息
 * 
 * @author chaostone
 */
trait Authentication extends Principal with Serializable {

  def principal:AnyRef

  def credentials:AnyRef

  def authorites:Iterable[Authority]

  def details:AnyRef

  def authenticated:Boolean

  def authenticated_= (authenticated:Boolean)
}
