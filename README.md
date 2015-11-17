#SerializeKiller
After the article published about the deserilization vulnerability we needed to scan all of our servers to verify if it's vulnerable. So we wrote this script, and decided to share it. This script enables you to scan a lot of servers in a short time for the infamous Java deserialization vulnerability. It currently detects WebLogic, WebSphere and Jenkins.

##What is the vulnerability?
It is bad. The bug enables attackers to take over the the server, even without credentials. If you use Websphere, Weblogic, JBoss, Jenkins or OpenNMS you are probably vulnerable.

You can read more about the bug here: http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/

##How do I use it?
You need to install Python 2, Curl and NMAP first. Also Python needs the requests library. With that installed it's pretty ease, just:
`./serializekiller.py targets.txt`
or
`./serializekiller.py --url example.com`

**Note:** on my Mac I had to call the script with: `python2.7 serializekiller.py targets.txt`. It *might* be specific for my installation. On Linux we experienced no problems.

##Is it dangerous to use?

No, it shouldn't do any damage, no exploit code is used. If you have doubts, keep in mind that being vulnerable is much worse ;)

##How fast is it?

We scanned over a 1000 servers in less than 2 minutes.

##Help, we are vulnerable!
My colleague hacker Sijmen Ruwhof made a nice write-up what to do next. You can find it [here](http://sijmen.ruwhof.net/weblog/683-scanning-an-enterprise-organisation-for-the-critical-java-deserialization-vulnerability)

##I want to contribute

Please send your pull request.
