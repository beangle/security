package org.beangle.security.blueprint.service

import org.beangle.security.blueprint.Profile
import org.beangle.security.blueprint.FuncResource
import org.beangle.security.blueprint.Role
import org.beangle.security.blueprint.Field
import org.beangle.security.blueprint.User

trait UserService {

  def get(code: String): Option[User]

  def get(id: Long): Option[User]

  def getUsers(id: Long*): Seq[User]

  def isRoot(user: User): Boolean
}

trait RoleService {

  def get(id: Int): Role

  def create(creator: User, role: Role): Unit

  def isManagedBy(manager: User, role: Role): Boolean

  def orphans: Seq[Role]
}

trait ProfileService {

  def getProfiles(user: User, resource: FuncResource): Seq[Profile]

  def getFieldValues(field: Field, keys: Any*): Seq[Any]

  def getField(fieldName: String): Field

  def get(id: Long): Profile

}
