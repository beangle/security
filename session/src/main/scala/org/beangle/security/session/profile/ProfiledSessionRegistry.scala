package org.beangle.security.session.profile

import org.beangle.security.authc.Account
import org.beangle.security.session.{ AbstractSessionRegistry, Session }
import org.beangle.commons.event.EventListener
import org.beangle.commons.event.Event

/**
 * @author chaostone
 */
abstract class ProfiledSessionRegistry extends AbstractSessionRegistry with EventListener[ProfileChangeEvent] {

  var profileProvider: ProfileProvider = DefaultProfileProvider

  protected def getMaxSession(auth: Account): Int = {
    profileProvider.getProfile(auth).maxSession
  }

  protected def getTimeout(auth: Account): Short = {
    profileProvider.getProfile(auth).timeout
  }

  protected def getProfileId(auth: Account): Number = {
    profileProvider.getProfile(auth).id
  }

  protected def getProfile(auth: Account): SessionProfile = {
    profileProvider.getProfile(auth)
  }
  /**
   * Handle an application event.
   */
  def onEvent(event: ProfileChangeEvent): Unit = {

  }
  /**
   * Determine whether this listener actually supports the given event type.
   */
  def supportsEventType(eventType: Class[_ <: Event]): Boolean = {
    eventType == classOf[ProfileChangeEvent]
  }

  /**
   * Determine whether this listener actually supports the given source type.
   */
  def supportsSourceType(sourceType: Class[_]): Boolean = {
    true
  }

}