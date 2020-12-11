     H COPYRIGHT('Copyright (c) 2012 Rory Hewitt. All rights reserved.')
     /*                                                                    +
      *                                                                    +
      * Copyright (c) 2012 Rory Hewitt. All rights reserved.               +
      *                                                                    +
      * Redistribution and use in source and binary forms, with or without +
      * modification, are permitted provided that the following conditions +
      * are met:                                                           +
      * 1. Redistributions of source code must retain the above copyright  +
      *    notice, this list of conditions and the following disclaimer.   +
      * 2. Redistributions in binary form must reproduce the above         +
      *    copyright notice, this list of conditions and the following     +
      *    disclaimer in the documentation and/or other materials provided +
      *    with the distribution.                                          +
      *                                                                    +
      * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ''AS IS'' +
      * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED  +
      * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A    +
      * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR   +
      * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,    +
      * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT   +
      * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF   +
      * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    +
      * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT        +
      * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  +
      * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE    +
      * POSSIBILITY OF SUCH DAMAGE.                                        +
      *                                                                    +
      */
      *D:
      *D: This is an example exit program, which would be called from the
      *D: www_validate() procedure if the '-exitpgm' flag is specified in
      *D: the parameter to www_validate() as follows:
      *D:
      *D:    '... -exitpgm wwwvalid/wwwvalidep ...'
      *D:
      *D: You can copy this example exit program to create your own exit
      *D: programs. When creating your own exit program, use the exact
      *D: same interface as shown in the 'Program interface' section
      *D: below, except that you should change the value of the EXTPGM
      *D: keyword to be the name of your exit program.
      *D:
      *D: In this example exit program, there are examples of the kind of
      *D: validation an exit program could perform, as follows:
      *D:
      *D: 1. Two specific userid/passwd combinations are checked to see if
      *D:    they are valid. As you can see, the values passed to this
      *D:    program from www_validate() are not changed in any way,
      *D:    except that leading and trailing blanks are removed.
      *D:    Embedded blanks are allowed, as are all special characters.
      *D:    A maximum length of 128 is allowed for both the userid and
      *D:    passwd field.
      *D:
      *D:    In this example, the userid/passwd combinations are hard-coded
      *D:    into the program, which you would probably never do.
      *D:
      *D:    In a real-life example, you might give each of your customers
      *D:    their own unique userid/passwd combination, which you hold in
      *D:    a database file, thus allowing you to selectively revoke a
      *D:    customer's access to your application. In such a case, this
      *D:    program could access that file to check the credentials.
      *D:
      *D:    If the credentials are valid, this program returns a 'dummy'
      *D:    user profile of '*CUSTOMER', which the CGI program can
      *D:    retrieve by calling the www_getusrprf() procedure. It could
      *D:    use this to determine which web pages should be displayed,
      *D:    without needing to cater for all possible userid's.
      *D:
      *D:    Of course, you could return any value in the RtnUsrPrf field -
      *D:    whatever value is returned will be available to your CGI
      *D:    program using the www_getusrprf() procedure.
      *D:
      *D: 2. If the user signs on with a helpdesk-related userid, then
      *D:    perform basic validation and return the user profile.
      *D:
      *D: 3. If the userid begins with 'RMH', then this program returns a
      *D:    value of EXITPGM_SYSTEM_VALIDATION in the 'valid' parameter,
      *D:    so www_validate() will subsequently validate the credentials
      *D:    as an IBM i user profile
      *D:
      *D: 4. Any other values are invalid, and a value is specified for
      *D:    the errmsg parameter - this will be shown when www_validate()
      *D:    redisplays the sign-on page.
      *D:
      *=============================================================================================
      * Copybooks
      *---------------------------------------------------------------------------------------------

      /copy qsrc,wwwvalid_p

      *---------------------------------------------------------------------------------------------
      * Program interface
      *---------------------------------------------------------------------------------------------

     D main            PR                  EXTPGM('WWWVALIDEP')
     D   userid                     128A   Const
     D   passwd                     128A   Const
     D   valid                       10I 0
     D   errmsg                     100A         Varying
     D   rtnusrprf                   10A

     D main            PI
     D   userid                     128A   Const
     D   passwd                     128A   Const
     D   valid                       10I 0
     D   errmsg                     100A         Varying
     D   rtnusrprf                   10A

      *---------------------------------------------------------------------------------------------
      * Global variables
      *---------------------------------------------------------------------------------------------

     D LOWER           C                   'abcdefghijklmnopqrstuvwxyz'
     D UPPER           C                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

      *=============================================================================================
      * MAINLINE
      *=============================================================================================
      /free

        // Initialize the output parameters
        valid = EXITPGM_INVALID_CREDENTIALS;
        clear errmsg;
        clear rtnusrprf;

        // Check credentials
        select;

          // Two specific userid's are checked for validity - could be
          // replaced with a check on a database file of 'external' user
          // names or equivalent functionality.
          when ( userid = 'Johnny43'        and passwd = 'TooC00l!#'    ) or
               ( userid = 'Casey Jones Jr.' and passwd = 'Ziggy Marley' );
            valid = EXITPGM_VALID_CREDENTIALS;
            rtnusrprf = '*CUSTOMER';

          // If a user signs on as e.g. 'helpdesk41' and with a password
          // of 'hlppwd4141', then they are a valid helpdesk user. Set the
          // return user profile to be the name they signed on with, but
          // converted to upper-case.
          when %xlate( LOWER :
                       UPPER :
                       %subst( userid : 1 : 8 ) )  = 'HELPDESK' and
               %subst( userid : 9 : 2 ) <> *blanks and
               %xlate( LOWER :
                       UPPER :
                       %subst( passwd : 1 : 6 ) )  = 'HLPPWD' and
               %subst( passwd : 7 : 4 ) = %subst( userid : 9 : 2 ) +
                                          %subst( userid : 9 : 2 );
            valid = EXITPGM_VALID_CREDENTIALS;
            rtnusrprf = %xlate( LOWER : UPPER : userid );

          // In this example, any userid which begins with the letters
          // 'RMH' should be validated as a system user profile.
          when %subst( userid : 1 : 3 ) = 'RMH' and passwd <> *blanks;
            valid = EXITPGM_SYSTEM_VALIDATION;

          // All other values are invalid
          other;
            valid = EXITPGM_INVALID_CREDENTIALS;
            errmsg = 'Invalid credentials supplied.';

        endsl;

        return;

        // *PSSR error-handling subroutine
        begsr *pssr;
          valid = EXITPGM_INVALID_CREDENTIALS;
          errmsg = 'Error in credential validation program.';
          return;
        endsr;

      /end-free
