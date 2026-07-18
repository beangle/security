/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.context

import org.beangle.security.authc.Profile
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

class RunAsTest extends AnyFunSpec, Matchers {

  describe("RunAs") {
    it("parseJson with empty properties array") {
      val json = """{"profiles":[{"name":"本专科","id":"5","properties":[]}],"name":"241290536"}"""
      val runAs = RunAs.parseJson(json)
      runAs shouldBe defined
      runAs.get.name should be("241290536")
      runAs.get.profiles should be(Seq(Profile(5L, "本专科", Map.empty)))
    }

    it("parseJson with properties object") {
      val json = """{"name":"241290536","profiles":[{"id":"5","name":"本专科","properties":{"campus":"1","grade":"2024"}}]}"""
      val runAs = RunAs.parseJson(json)
      runAs shouldBe defined
      runAs.get.name should be("241290536")
      runAs.get.profiles should be(Seq(Profile(5L, "本专科", Map("campus" -> "1", "grade" -> "2024"))))
    }

    it("parseJson without profiles") {
      val json = """{"name":"241290536"}"""
      val runAs = RunAs.parseJson(json)
      runAs shouldBe Some(RunAs("241290536", Seq.empty))
    }

    it("parseJson returns None when name missing") {
      val json = """{"profiles":[{"name":"本专科","id":"5","properties":[]}]}"""
      RunAs.parseJson(json) shouldBe None
    }

    it("parseJson returns None for invalid json") {
      RunAs.parseJson("not-a-json") shouldBe None
    }

    it("find profile by id after parse") {
      val json = """{"profiles":[{"name":"本专科","id":"5","properties":[]},{"name":"研究生","id":"8","properties":{"dept":"cs"}}],"name":"241290536"}"""
      val runAs = RunAs.parseJson(json).get
      runAs.profiles.find(_.id == 5L) shouldBe Some(Profile(5L, "本专科", Map.empty))
      runAs.profiles.find(_.id == 8L) shouldBe Some(Profile(8L, "研究生", Map("dept" -> "cs")))
      runAs.profiles.find(_.id == 9L) shouldBe None
    }
  }
}
