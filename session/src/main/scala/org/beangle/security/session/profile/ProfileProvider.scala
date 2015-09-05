package org.beangle.security.session.profile

import org.beangle.security.authc.Account

/**
 * @author chaostone
 */
trait ProfileProvider {

  def getProfile(auth: Account): SessionProfile

  def getProfiles(): Iterable[SessionProfile]
}

object DefaultProfileProvider extends ProfileProvider {

  private val defaultProfile = DefaultSessionProfile

  def getProfile(auth: Account): SessionProfile = {
    defaultProfile
  }
  
  def getProfiles(): Iterable[SessionProfile] = {
    List(defaultProfile)
  }
}