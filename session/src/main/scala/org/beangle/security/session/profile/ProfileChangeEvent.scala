package org.beangle.security.session.profile

import org.beangle.commons.event.Event

/**
 * @author chaostone
 */
class ProfileChangeEvent(val profile:SessionProfile) extends Event(profile){
  
}