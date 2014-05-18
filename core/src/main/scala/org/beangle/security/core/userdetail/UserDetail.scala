
package org.beangle.security.core.userdetail

import java.io.Serializable
import java.util.Collection
import org.beangle.security.core.Authority

trait UserDetail extends Serializable {

  def username: String

  def password: String

  def authorities: Seq[_ <: Authority]

  def accountExpired: Boolean

  def accountLocked: Boolean

  def credentialsExpired: Boolean

  def enabled: Boolean
}
