package org.beangle.security.blueprint.service

import org.beangle.security.blueprint.{Menu, MenuProfile, Profile, Role, User}

trait MenuService {

  def getMenus(profile: MenuProfile, role: Role, active: Option[Boolean]): Seq[Menu]

  def getMenus(profile: MenuProfile, user: User, profiles: Seq[Profile]): Seq[Menu]

  def getProfile(role: Role, profileId: Integer): MenuProfile

  def getProfiles(user: User): Seq[MenuProfile]

  def getProfiles(role: Role): Seq[MenuProfile]
}