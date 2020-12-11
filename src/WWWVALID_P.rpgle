      /IF DEFINED(WWWVALID_P)
      /EOF
      /ENDIF
      /DEFINE WWWVALID_P
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

      *=============================================================================================
      * Global template variables and constants
      *=============================================================================================

     D wwwvalid_name   C                   'WWWVALID'
     D wwwvalid_text   C                   'Web Access User Validator'

     D www_sessionid_t...
     D                 S             16A   Based(TEMPLATE)

      *=============================================================================================
      * www_validate(): Validate browser access for user
      *=============================================================================================

     D www_validate    PR                  Like(www_sessionid_t)
     D                                     Extproc('www_validate')
     D   parms                     1024A   Const Options(*Nopass)
     D

     D CREATE_SESSION_COOKIE...
     D                 C                   'session'
     D CREATE_PAGE_COOKIE...
     D                 C                   'page'

      *=============================================================================================
      * www_endsession(): Delete the session record
      *=============================================================================================

     D www_endsession  PR            10I 0 Extproc('www_endsession')
     D   pSessionId                        Const Like(www_sessionid_t)

      *=============================================================================================
      * www_getusrprf(): Retrieve the user profile for the session
      *=============================================================================================

     D www_getusrprf   PR            10A   Extproc('www_getusrprf')
     D   pSessionId                        Const Like(www_sessionid_t)

      *=============================================================================================
      * www_swapusrprf(): Swap to the specified user profile
      *=============================================================================================

     D www_swapusrprf  PR            10I 0 Extproc('www_swapusrprf')
     D   pSessionId                        Const Like(www_sessionid_t)

      *=============================================================================================
      * www_resetusrprf(): Swap back to the original user profile
      *=============================================================================================

     D www_resetusrprf...
     D                 PR            10I 0 Extproc('www_resetusrprf')
     D   pSessionId                        Const Like(www_sessionid_t)

      *=============================================================================================
      * Exit program prototype
      *=============================================================================================

     **WWWVALIDEP      PR                  ExtPgm('WWWVALIDEP')
     **  userid                     128A   Const
     **  passwd                     128A   Const
     **  valid                       10I 0
     **  errmsg                     100A         Varying
     **  rtnusrprf                   10A

     D EXITPGM_INVALID_CREDENTIALS...
     D                 C                   0
     D EXITPGM_VALID_CREDENTIALS...
     D                 C                   1
     D EXITPGM_SYSTEM_VALIDATION...
     D                 C                   2

