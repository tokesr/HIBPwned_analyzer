**HIBPwned_analyzer** is a Cortex analyzer to find account breaches, account pastes, and site breaches by using the haveibeenpwned.com API.
Be aware this is not the official HIBP analyzer for Cortex. I added two additional queries to that one because these are also frequently used by analysts (these or similar functionalities on other sites).

The analyzer comes in three different flavors:
1. AccountBreach: Provides information about account breaches. If a breach happened and it is stored on haveibeenpwned.com the analyzer will return with true (report will contain the details) and false if the account hasn't been breached.
1. AccountPaste: Provides information about pastes of an account. If any paste were found the value is going to be true.
1. SiteBreach: Provides information about a site breach.
1. (The fourth service of haveibeenpwned.com is to look for leaked passwords based on hashes. This functionality is not implemented in the analyzer because based on my experience analysts are not really using it)


# Configuration settings:
1. unverified: Set it to true if you want to get unverified breaches as well.
1. truncate: Set to true if you do not want to see every information.
1. api_key: API key is mandatory to use HIBP's API/
1. retries: Amount of retries after unsuccessful attempts if the status code is 429 or 503.
1. user_agent: User-agent is mandatory to use HIBP API. You can use the default one or define one for yourself.


# Installation
You can install the analyzers (different flavors) by copying the content of HIBPwned folder into your analyzer folder on the Cortex server. You can install (copy) all of the flavors or only the ones you really need.

After copying the file you have to install the python modules from the requirements.txt file.

This is the recommended code for installation

```bash
for I in $(find Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip2 install -r $I; done && \
for I in $(find Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip3 install -r $I || true; done
```

The report templates can be installed on theHive GUI by drag-n-drop-ing the zip files from thehive-templates folder one-by-one.
