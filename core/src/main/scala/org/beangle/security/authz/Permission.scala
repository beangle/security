package org.beangle.security.authz

import java.security.Principal
import java.util.Date

trait Permission extends Serializable with Cloneable {
  def resource: Resource
  def principal: Principal
  def actions: String
  def restrictions: String
  def beginAt: Date
  def endAt: Date
}