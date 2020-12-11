# IBM i Web Access User Validator

The Web Access User Validator (WWWVALID) is an IBM i service program which can be added to any existing CGI program, to AUTOMATICALLY provide the following:

User profile/password (credential) validation, application-specific sign-on pages, user-defined credential validation, allowing you to define your own userid's and sign-on control, application timeout processing (per-page and per-session), session-specific cookies, to ensure complete end-to-end session management and the option to swap to run under the user profile used to sign-on, so the CGI program can run with advanced authorities.

These additional options can be added to your existing CGI programs with only a few lines of code, and with no changes to HTTP server configuration.

Features
* Automatic security processing for your IBM i CGI applications
* Application-specific signon page
* Application timeout processing (per-page and per-transaction)
* Profile swapping
