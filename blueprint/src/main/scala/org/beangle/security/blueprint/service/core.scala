package org.beangle.security.blueprint.service

import org.beangle.security.blueprint.Profile
import org.beangle.security.blueprint.FuncResource
import org.beangle.security.blueprint.Role
import org.beangle.security.blueprint.Field
import org.beangle.security.blueprint.User

trait UserService {

  def get(code: String): Option[User]

  def get(id: java.lang.Long): User

  def getUsers(id: java.lang.Long*): Seq[User]

  def isRoot(user: User): Boolean
}

trait RoleService {

  def get(id: Integer): Role

}

trait ProfileService {

  def getProfiles(user: User, resource: FuncResource): Seq[Profile]

  def getFieldValues(field: Field, keys: Any*): Seq[Any]

  def getField(fieldName: String): Field

  def get(id: java.lang.Long): Profile

}
