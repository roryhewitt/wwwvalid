# IBM i Web Access User Validator

The Web Access User Validator (WWWVALID) is an IBM i service program which can be added to any existing CGI program, to AUTOMATICALLY provide the following:

## User profile/password (credential) validation
Automatically checks passed credentials for either system validity (a system user profile) or against a defined list of userid/password combinations (whcih can be be entirely separate from system profiles). User defined credentials can use format and characters which are not allowed in normal IBM i profiles. These credentials will 'map' to an internal IBM i profile, thus providing a layer of abstraction from the outside world.

## Application-specific sign-on pages
Different applications on the IBM i can have their own sign-on (logon) pages, using application-specific images, CSS, JS etc.

## Sign-on control

## Application timeout processing (per-page and per-session)
You can define application timeouts, either on a per-session basis (an entire end-to-end session from initial logon to logout) or on a per-page basis (to automatically log users out after a period of inactivity, or to ensure that they complete the processing within an application screen within a certain time).

## Session-specific cookies
Complete end-to-end secure session management.

## Profile swapping
The option to swap to run under the user profile used to sign-on, so the underlying CGI program can run with advanced authorities.

All these additional options can be added to your existing CGI programs with only a few lines of code, and with **no changes** to your HTTP server configuration.

Features
* Automatic security processing for your IBM i CGI applications
* Application-specific signon page
* Application timeout processing (per-page and per-transaction)
* Profile swapping

![Object List](https://github.com/roryhewitt/wwwvalid/blob/main/Object%20List.png?raw=true)

![Information Screen](https://github.com/roryhewitt/wwwvalid/blob/main/Information%20Screen.png?raw=true)

![Default Logon Screen](https://github.com/roryhewitt/wwwvalid/blob/main/Logon%20Screen.png?raw=true)
