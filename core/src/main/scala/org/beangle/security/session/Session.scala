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
package org.beangle.security.session

import java.security.Principal
import java.time.Instant

object Session {

  class Agent(val name: String, val ip: String, val os: String) extends Serializable

}

trait Session extends java.io.Externalizable {

  def id: String

  def principal: Principal

  def loginAt: Instant

  def agent: Session.Agent

  def ttiSeconds: Int

  def ttiSeconds_=(seconds: Int): Unit

  def lastAccessAt: Instant

  /** 访问session
   *
   * @return 据上一次的间隔秒数，-1 表示已经过期
   **/
  def access(accessAt: Instant): Long

  def expired: Boolean
}

/** 会话配置
 *
 * @param ttiSeconds      tti时间以秒计
 * @param concurrent      多重会话数上限
 * @param checkConcurrent 是否检查多重会话
 * @param checkCapacity   是否检查系统会话上限
 */
case class SessionProfile(ttiSeconds: Int, concurrent: Int, capacity: Int, checkConcurrent: Boolean, checkCapacity: Boolean)

trait SessionBuilder {
  def build(id: String, principal: Principal, loginAt: Instant, agent: Session.Agent, ttiSeconds: Int): Session
}
