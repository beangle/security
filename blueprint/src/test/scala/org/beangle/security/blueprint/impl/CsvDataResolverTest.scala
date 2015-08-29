package org.beangle.security.blueprint.impl

import org.junit.runner.RunWith
import org.scalatest.{ FunSpec, Matchers }
import org.beangle.commons.lang.reflect.BeanManifest
import org.beangle.security.blueprint.domain.RoleBean
import org.beangle.security.blueprint.domain.DimensionBean
import org.beangle.security.blueprint.domain.RoleBean
import org.beangle.security.blueprint.service.impl.CsvDataResolver
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class CsvDataResolverTest extends FunSpec with Matchers {

  val field = new DimensionBean()
  field.id = 1
  field.name = "role"
  field.source = "oql:from Role"
  field.typeName = classOf[RoleBean].getName
  field.keyName = "id"
  field.properties = "name"

  describe("CsvDataResolver") {
    it("marshal") {
      val text = CsvDataResolver.marshal(field, List(new RoleBean(1, "role1"), new RoleBean(2, "role2")))
      assert(text == "id;name,1;role1,2;role2")

    }
    it("unmarshal") {
      val rs: Seq[RoleBean] = CsvDataResolver.unmarshal(field, "id;name,1;role1,2;role2")
      val methods = classOf[RoleBean].getDeclaredMethods 
      var i=0;
      while(i<methods.length){
        val method=methods(i);
        i+=1
        if(method.getName().toLowerCase().contains("id")){
          val gpt =method.getGenericParameterTypes()
          val rt = method.getGenericReturnType();
          if(gpt.length>0)println(gpt(0),rt) else println(rt)
        }
      }
      val manifest = BeanManifest.get(classOf[RoleBean])
      assert(manifest.getPropertyType("id") == Some(classOf[Integer]))
      val objs = List(new RoleBean(1, "role1"), new RoleBean(2, "role2"))
      assert(rs.toList.head == objs.head)
    }
  }
}