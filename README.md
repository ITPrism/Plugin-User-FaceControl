User - Face Control
==========================
( Version 1.2 )
- - -

This is Joomla! plugin that provides additional protection on the front-end of the website, during the process of login.

Features
* Create a list with IP addresses from which you will be able to login on font-end.
* Sends email to the administrator when someone login on the front-end.
* Detects brute force attack and blocks the IP address of the attacker.
* Sends e-mail to the administrator when brute force attack be detected.

Changelog
---------

###v1.2
* Fixed the method _onUserAuthorisation_.
* Removed the method _onUserBeforeAuthenticate_.


###v1.1
* Added option for number of allowed login failures. If there are more than these login attempts, the system will treat it as an attack.
* Moved the functionality that sends mail to the administrator from onUserBeforeAuthenticate to onUserLoginFailure.