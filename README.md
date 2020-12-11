# IBM i Web Access User Validator

The Web Access User Validator (WWWVALID) is an IBM i service program which can be added to any existing IBM i CGI programs, to AUTOMATICALLY provide the following:

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

# Why should I use the Web Access User Validator?
Currently, if you want application security for your IBM i CGI applications, you have a number of very limited options that you can use to control who can call your CGI programs:

1. Use the `UserID %%CLIENT%%` Apache configuration directive

2. Specific hand-written security added to your CGI programs

In the first case, the user is presented with a sign-on pop-up, where they must enter a valid IBM i user profile and password, which are validated by the system. Whilst this functionality works in many cases, it has a number of drawbacks:
  - The validation pop-up is just that – a basic (ugly!) pop-up – it's not a true sign-on page, which might have a corporate look-and-feel, with a company logo, links, images etc.
 - The user must enter an *actual IBM i user profile and password*. This is fine for intranet use, but if you want to make your CGI application available on the internet, you're probably not going to want either to create individual user profiles for each possible user or to use a single user profile for all possible users.
  - The HTTP server will actually swap to use that user profile when running the CGI program. This might be what you want, but it might not, and you don't get the choice.

In the second case, you have to write your own credential validation processing. Obviously you can do this and add whatever additional processing you want, but it can be a lot of work for you. Additionally, the CGI program normally then has access to the password and user profile used to sign on, so you need to be sure that the CGI program is entirely secure.

However, if you use the **Web Access User Validator**, you can have the best of both worlds - an application-specific sign-on page, which automatically includes timeout processing for your CGI programs, without either the requirement either to substantially change any of your existing CGI programs or to write your own transaction and credential validation processing. Additionally, the user profile and password used to sign on are stored in an encrypted format and are 'insulated' from your CGI program, which can only access the user profile using a specific procedure and cannot access the password in any way.

# How do I use the Web Access User Validator?
After installing the **Web Access User Validator**, just add a call to the `www_validate()` procedure as the first bit of processing in your existing CGI program(s), as the following example shows:
```
www_sessionid = www_validate();
if www_sessionid = *blanks;
  return;
endif;
...your existing CGI program code...
```

That's all there is to it!

Simply by adding these four lines of code, when the CGI program is first called from the browser, a sign-on page is displayed, where the user must enter a valid IBM i user profile and password. If the credentials are invalid (for instance, if the password is incorrect), the sign-on page is redisplayed with an appropriate error message, and the user must re-enter their credentials. If the credentials are valid, the CGI program continues its processing just as if you had not added the call to www_validate. On subsequent calls to the CGI program, the sign-on page is not displayed.

However, you may want to add more functionality - perhaps you want to ensure that the session times-out after a few minutes. To do this, simply pass a parameter to www_validate, like this:
```
www_sessionid = www_validate('-sessiontimeout 300');
if www_sessionid = *blanks;
  return;
endif;
...your existing CGI program code...
```
This time, in addition to the above processing, every time your CGI program is called, `www_validate()` will check how long it was since the user initially signed on. If it is more than the specified time (300 seconds in the above example), the sign-on page is redisplayed with a "Session has expired" error message. If the user signs on correctly again, a new session ID is generated by `www_validate()`.

There are lots more options available, including separate credential and timeout options (all documented in the PDF).

# Installation

**Web Access User Validator** comes with full installation instructions, as well as a number of simple test harness programs you can use to try out the different options.

# Previous versions

Previously, the **Web Access User Validator** was available on SourceForge as compiled objects. However, it is now available as source files, so you can compile the code yourself.

This is an example of the simple debug page which you can use to test out the functionality
![Information Screen](https://github.com/roryhewitt/wwwvalid/blob/main/Information%20Screen.png?raw=true)

This is the default HTML logon page which comes out of the box - you can change it to your heart's content.
![Default Logon Screen](https://github.com/roryhewitt/wwwvalid/blob/main/Logon%20Screen.png?raw=true)
