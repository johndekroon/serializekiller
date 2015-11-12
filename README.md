#SerializeKiller
After the article published about the serilization vulnerability we needed to scan all of our servers to verify if it's vulnerable. So we wrote this script, and decided to share it. This script enables you to scan a lot of servers in a short time for the infamous Java serialization vulnerability. It currently detects WebLogic, WebSphere, Jenkins and partly OpenNMS.

##What is the vulnerability?
It is bad. The bug enables attackers to take over the the server, even without credentials. If you use Websphere, Weblogic, JBoss, Jenkins or OpenNMS you are probably vulnerable.

You can read more about the bug here: http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/

##How do I use it?
You need to install Python, Curl and NMAP first. With that installed it's pretty ease, just:
./serializekiller.py targetfile.txt

##Is it dangerous to use?

No, it shouldn't do any damage, no exploit code is used. If you have doubts, keep in mind that being vulnerable is much worse ;)

##How fast is it?

We scanned over a 1000 servers in less than 2 minutes.

##I want to contribute

Please send your pull request.
