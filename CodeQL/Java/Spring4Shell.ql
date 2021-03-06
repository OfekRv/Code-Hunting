import semmle.code.java.frameworks.spring.SpringController
import semmle.code.xml.MavenPom

predicate isVulnerableSpringVersion(Dependency d) {
    d.getGroup().getTextValue() = "org.springframework"
    and not(d.getVersionString() = "5.2.20") 
    and not(isAboveVersion(d, "5.3.18"))
}

predicate isPOJOParametrizedEndpoint(SpringRequestMappingMethod endpoint, Class c) {
    endpoint.getARequestParameter().getType().getName() = c.getName()
    and c.fromSource() 
}

bindingset[version]
predicate isAboveVersion(Dependency d, string version) {
    isAboveVersionInPosition(d, version, 0)
    and isAboveVersionInPosition(d, version, 1)
    and isAboveVersionInPosition(d, version, 2)
}

bindingset[version]
predicate isAboveVersionInPosition(Dependency d, string version, int position) {
    d.getVersionString().splitAt(".", position).toInt() > version.splitAt(".", position).toInt()
}

from SpringRequestMappingMethod endpoint, Class c, Dependency d
where isVulnerableSpringVersion(d) 
and isPOJOParametrizedEndpoint(endpoint, c)
select endpoint