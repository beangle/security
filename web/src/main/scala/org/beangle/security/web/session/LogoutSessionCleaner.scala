package org.beangle.security.web.session

import org.beangle.commons.event.{ Event, EventListener }
import org.beangle.commons.web.session.HttpSessionDestroyedEvent
import org.beangle.security.session.SessionRegistry
import org.beangle.security.session.SessionId

class LogoutSessionCleaner(val sessionRegistry: SessionRegistry) extends EventListener[HttpSessionDestroyedEvent] {

  // 当会话消失时，退出用户
  override def onEvent(event: HttpSessionDestroyedEvent): Unit = sessionRegistry.remove(SessionId(event.session.getId))

  override def supportsEventType(eventType: Class[_ <: Event]): Boolean = classOf[HttpSessionDestroyedEvent].isAssignableFrom(eventType)

  override def supportsSourceType(sourceType: Class[_]): Boolean = true

}
