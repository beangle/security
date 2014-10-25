package org.beangle.security.blueprint.domain

import java.security.Principal

import org.beangle.commons.lang.Strings
import org.beangle.data.model.{ Coded, Enabled, Entity, Hierarchical, SlowId, IntIdEntity, LongIdEntity, Named, TemporalAt, TemporalOn, Updated }
import org.beangle.security.authz.Authority

object Property {
  val All = "*"
}

trait Field extends IntIdEntity with Named with SlowId {
  def title: String
  def source: String
  def multiple: Boolean
  def required: Boolean
  def typeName: String
  def keyName: String
  def properties: String
}

trait Profile {

  def properties: collection.mutable.Map[Field, String]

  def setProperty(field: Field, value: String): Unit = {
    val property = getProperty(field)
    if (Strings.isNotBlank(value))
      properties.put(field, value)
    else properties -= field
  }

  def getProperty(field: Field): Option[String] = {
    properties.get(field)
  }

  def getProperty(name: String): Option[String] = {
    properties.keys.find(k => k.name == name) match {
      case Some(p) => properties.get(p)
      case None => None
    }
  }

  def matches(other: Profile): Boolean = {
    if (other.properties.isEmpty) return true
    other.properties exists {
      case (field, target) =>
        val source = getProperty(field).getOrElse("")
        (source != Property.All) && ((target == Property.All) || (Strings.split(target, ",").toSet -- Strings.split(source, ",")).isEmpty)
    }
  }
}
trait UserCategory extends IntIdEntity with Named with SlowId {

}

trait User extends LongIdEntity with Coded with Named with Updated with TemporalOn with Enabled with Principal {

  def email: String

  def credential: String

  def members: Seq[Member]

  def roles: Seq[Role]

  def authorities: Seq[Authority]

  def creator: Option[User]

  def accountExpired: Boolean

  def credentialExpired: Boolean

  def category: UserCategory

  def locked: Boolean
}

trait UserProfile extends LongIdEntity with Profile {
  def user: User
}

object Member {
  object Ship extends Enumeration(1) {
    type Ship = Value
    val IsMember = Value("Member")
    val IsGranter = Value("Granter")
    val IsManager = Value("Manager")
  }
}

trait Member extends LongIdEntity {

  def user: User

  def role: Role

  def member: Boolean

  def granter: Boolean

  def manager: Boolean
}

trait Role extends Entity[Integer] with Named with Updated with Enabled with Hierarchical[Role] with Profile with Principal with SlowId {

  def members: Seq[Member]

  def creator: Option[User]

  def remark: String
}

object Resource {
  /** 资源的所有部分 */
  final val AllParts = "*";

  /** 允许所有操作 */
  final val AllActions = "*";
}

trait Resource extends IntIdEntity with Named with Enabled with SlowId {
  def title: String
  def actions: String
  def remark: String
}

trait Permission extends IntIdEntity with Cloneable with TemporalAt with SlowId {
  def resource: Resource
  def principal: Principal
  def actions: String
  def restrictions: String
  def remark: String
}
