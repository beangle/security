import sbt._
import Keys._

object BuildSettings {
  val buildOrganization = "org.beangle.security"
  val buildVersion = "4.0.1-SNAPSHOT"
  val buildScalaVersion = "2.10.2"

  val buildSettings = Defaults.defaultSettings ++ Seq(
    organization := buildOrganization,
    version := buildVersion,
    scalaVersion := buildScalaVersion,
    shellPrompt := ShellPrompt.buildShellPrompt,
    crossPaths := false)
}

object ShellPrompt {

  object devnull extends ProcessLogger {
    def info(s: => String) {}

    def error(s: => String) {}

    def buffer[T](f: => T): T = f
  }

  def currBranch = (
    ("git status -sb" lines_! devnull headOption)
    getOrElse "-" stripPrefix "## ")

  val buildShellPrompt = {
    (state: State) =>
      {
        val currProject = Project.extract(state).currentProject.id
        "%s:%s:%s> ".format(
          currProject, currBranch, BuildSettings.buildVersion)
      }
  }
}

object Dependencies {
  val slf4jVer = "1.6.6"
  val mockitoVer = "1.9.5"
  val logbackVer = "1.0.7"
  val scalatestVer = "2.0.M5b"
  val springVer = "3.2.3.RELEASE"
  val commonsVer ="4.0.1-SNAPSHOT"

  val slf4j = "org.slf4j" % "slf4j-api" % slf4jVer
  val scalatest = "org.scalatest" % "scalatest_2.10" % scalatestVer % "test"
  val mockito = "org.mockito" % "mockito-core" % mockitoVer % "test"

  val logbackClassic = "ch.qos.logback" % "logback-classic" % logbackVer % "test"
  val logbackCore = "ch.qos.logback" % "logback-core" % logbackVer % "test"

  val validation = "javax.validation" % "validation-api" % "1.0.0.GA"
  val beangle_core = "org.beangle.commons" % "beangle-commons-core" % commonsVer
}

object Resolvers {
  val m2repo = "Local Maven2 Repo" at "file://" + Path.userHome + "/.m2/repository"
}

object BeangleBuild extends Build {

  import Dependencies._
  import BuildSettings._
  import Resolvers._

  val commonDeps = Seq(slf4j, logbackClassic, logbackCore, scalatest, beangle_core)

  lazy val security = Project("beangle-security", file("."), settings = buildSettings) aggregate (security_core)

  lazy val security_core = Project(
    "beangle-security-core",
    file("core"),
    settings = buildSettings ++ Seq(libraryDependencies ++= commonDeps) ++ Seq(resolvers += m2repo))
}
