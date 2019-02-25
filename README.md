# SerializeKiller
After the article published about the deserialization vulnerability we needed to scan all of our servers to verify if it's vulnerable. So we wrote this script, and decided to share it. This script enables you to scan a lot of servers in a short time for the famous Java deserialization vulnerability. It currently detects WebLogic, WebSphere, JBOSS and Jenkins.

Edit: changed "infamous" to "famous" since this script made it somehow to Mr. Robot S03E07. 

## What is the vulnerability?
It is bad. The bug enables attackers to take over the the server, even without credentials. If you use Websphere, Weblogic, JBoss, Jenkins or OpenNMS you are probably vulnerable.

You can read more about the bug here: http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/

## How do I use it?
You need to install Python 2, Curl and NMAP first. Also Python needs the requests library. With that installed it's pretty ease, just:
`./serializekiller.py targets.txt`
or
`./serializekiller.py --url example.com`

In the scanfile you can put IP adresses and hosts. It's also possible to scan specific ports. Please see the scanfile. 

**Note:** on my Mac I had to call the script with: `python2.7 serializekiller.py targets.txt`. It *might* be specific for my installation. On Linux we experienced no problems.

## Is it dangerous to use?

No, it shouldn't do any damage, no exploit code is used. If you have doubts, keep in mind that being vulnerable is much worse ;)

## How fast is it?

We scanned over a 1000 servers in less than 2 minutes.
Edit: We noticed that in some cases it can be slower. 

## Help, we are vulnerable!
My colleague hacker Sijmen Ruwhof made a nice write-up what to do next. You can find it [here](http://sijmen.ruwhof.net/weblog/683-scanning-an-enterprise-organisation-for-the-critical-java-deserialization-vulnerability)

## Pfeew! We are not vulnerable!
Congratz! But keep in mind that this script only scans some default ports. 
*E.g. If you have a vulnerable Jenkins server on port 80, the SerializeKiller won't find it.*
If you want to scan non-default ports, you can specify those ports in the targets file.

## I've patched (some) of my servers. Will SerializeKiller detect that?
Yes. And No. We couldn't find a way to verify a patched WebSphere server (OK, we could run the exploit, but thats not desirable).
AFAIK it will detect a patched Jenkins, Jboss and Weblogic.
*We decided to mark vulnerable WebSphere servers as possibly vulnerable, because we can't verify the patch.*

## I want to contribute
Please send your pull request.

### Known issues
- After specifing a port, it could take a long time to finish the scan. This is not a bug, it just takes a while.
- Some SSL libs doesn't have the method create_default_context. As a result, it wont scan JBOSS and Jenkins proper.
