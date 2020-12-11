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
      *=============================================================================================
      * Copybooks
      *---------------------------------------------------------------------------------------------

      /copy qsrc,wwwvalid_p

      *---------------------------------------------------------------------------------------------
      * Program Status Data Structure (PSDS)
      *---------------------------------------------------------------------------------------------

      * PgmSDS - Program Status Data-Structure
     D PgmSDS         SDS                  Qualified
     D  MainProc                     10A
     D  Status                        5S 0
     D  PrvSts                        5S 0
     D  Stmt                          8A
     D  Routine                       8A
     D  Parms                         3S 0
     D  ExcpMsg                       7A
     D   ExcpMsgPfx                   3A   Overlay(ExcpMsg)
     D   ExcpMsgNbr                   4A   Overlay(ExcpMsg:*Next)
     D                                4A
     D  WorkArea                     30A
     D  PgmLib                       10A
     D  ExcpData                     80A
     D  ExcpID                        4A
     D  FileErr                      10A
     D                                6A
     D  Date                          8A
     D  Century                       2A
     D  FileErr2                      8A
     D  FileSts                      35A
     D  QualJob                      26A
     D    JobName                    10A   Overlay(QualJob)
     D    JobUser                    10A   Overlay(QualJob:*Next)
     D    JobNbr                      6A   Overlay(QualJob:*Next)
     D      JobNbrN                   6S 0 Overlay(JobNbr)
     D  JobDate                       6S 0
     D    JobDateC                    6A   Overlay(JobDate)
     D      JobDateMM                 2A   Overlay(JobDateC)
     D      JobDateDD                 2A   Overlay(JobDateC:*Next)
     D      JobDateYY                 2A   Overlay(JobDateC:*Next)
     D  RunDate                       6S 0
     D    RunDateC                    6A   Overlay(RunDate)
     D      RunDateMM                 2A   Overlay(RunDateC)
     D      RunDateDD                 2A   Overlay(RunDateC:*Next)
     D      RunDateYY                 2A   Overlay(RunDateC:*Next)
     D  RunTime                       6S 0
     D    RunTimeC                    6A   Overlay(RunTime)
     D      RunTimeHH                 2A   Overlay(RunTimeC)
     D      RunTimeMN                 2A   Overlay(RunTimeC:*Next)
     D      RunTimeSS                 2A   Overlay(RunTimeC:*Next)
     D  CmpDate                       6S 0
     D    CmpDateC                    6A   Overlay(CmpDate)
     D      CmpDateMM                 2A   Overlay(CmpDateC)
     D      CmpDateDD                 2A   Overlay(CmpDateC:*Next)
     D      CmpDateYY                 2A   Overlay(CmpDateC:*Next)
     D  CmpTime                       6S 0
     D    CmpTimeC                    6A   Overlay(CmpTime)
     D      CmpTimeHH                 2A   Overlay(CmpTimeC)
     D      CmpTimeMN                 2A   Overlay(CmpTimeC:*Next)
     D      CmpTimeSS                 2A   Overlay(CmpTimeC:*Next)
     D  CmpLvl                        4A
     D  SrcfName                     10A
     D  SrcfLib                      10A
     D  SrcfMbr                      10A
     D  OwnPgm                       10A
     D  OwnMod                       10A
     D                               76A
     D  SrcID                         5I 0
     D  SrcID2                        5I 0
     D  UsrPrf                       10A
     D                               62A

      *---------------------------------------------------------------------------------------------
      * External procedure prototypes and related variables
      *---------------------------------------------------------------------------------------------

      * write: Write to a file
     D write           PR            10I 0 ExtProc('write')
     D  handle                       10I 0 Value
     D  buffer                         *   Value
     D  bytes                        10U 0 Value

      * read: Read from a file
     D read            pr            10i 0 extproc('read')
     D  handle                       10i 0 Value
     D  buffer                         *   Value
     D  bytes                        10u 0 Value

      * Constants
     D STDIN           C                   0
     D STDOUT          C                   1

     D Qp0zInitEnv     PR            10I 0 Extproc('Qp0zInitEnv')
     D environ         S               *   Import('environ')
     D envvarptr       S               *   Dim(4096) Based(environ)

      * getenv: Get the value of an environment variable
     D getenv          pr              *   extproc('getenv')
     D   envvar                        *   value options(*string)

     D atoi            PR            10I 0 Extproc('atoi')
     D                                 *   Value Options(*String)

     D cvthc           PR                  Extproc('cvthc')
     D   Tgt_Char                      *   Value
     D   Src_Hex                       *   Value
     D   Tgt_Len                     10I 0 Value

      *---------------------------------------------------------------------------------------------
      * Subprocedure prototypes
      *---------------------------------------------------------------------------------------------

      * rtvenvvar(): Retrieve an environment variable
     D rtvenvvar       PR         65535A   Varying Extproc('rtvenvvar')
     D   envvar                      50A   Const Varying

      * getcgival(): Get a variable's value from a CGI string
     D getcgival       PR          1024A   Varying Extproc('getcgival')
     D   var                         50A   Const Varying
     D   string                    5000A   Const Varying

      * writeOutput(): Write a line to STDOUT
     D writeOutput     PR            10I 0 Extproc('writeOutput')
     D   pBuffer                           Const Like(Buffer)

      *---------------------------------------------------------------------------------------------
      * Global variables
      *---------------------------------------------------------------------------------------------

     D rc              S             10I 0
     D x               S             10I 0
     D Buffer          S          65535A   Varying
     D HTML1           S            100A   Dim(10) Ctdata
     D HTML2           S            100A   Dim(6) Ctdata
     D EOL             C                   x'25'
     D start_ts        S               Z
     D secs            S             10I 0
     D rcvvar          S          65535A
     D rcvlen          S             10I 0

      * WWWVALID-related variables
     D www_sessionid   S                   Inz Like(www_sessionid_t)
     D www_sessionidX  S             32A
     D www_usrprf      S             10A   Inz

      *=============================================================================================
      * MAINLINE
      *=============================================================================================
      /free

        start_ts = %timestamp();

        // Call www_validate to start session
        www_sessionid = www_validate('-pagetimeout 30 ' +
                                     '-sessiontimeout 300');
        if www_sessionid = *blanks;
          return;
        endif;

        // Output the HTTP headers and the first bit of the HTML
        for x = 1 to %elem( HTML1 );
          rc = writeOutput( %trimr( HTML1(x) ) + EOL );
        endfor;

        // Check if the user pressed the 'Log off' button
        rcvlen = atoi( rtvenvvar( 'CONTENT_LENGTH' ) );
        if rcvlen > 0;
          rcvlen = read( STDIN : %addr( rcvvar ) : %len( rcvvar ) );
          if rcvlen = -1;
            exsr *pssr;
          endif;
          rcvvar = %subst( rcvvar : 1 : rcvlen );
          if getcgival( 'logoff' : rcvvar ) <> *blanks;
            rc = www_endsession( www_sessionid );
            rc = writeOutput( 'Session has ended. Goobye.' + EOL );
            return;
          endif;
        endif;

        // Output the HTTP server job information
        rc = writeOutput( '<h2>HTTP Server Instance</h2>' + EOL );
        Buffer = 'HTTP Server Job:' + ' ' +
                 %trimr( PgmSDS.JobNbr  ) + '/' +
                 %trimr( PgmSDS.JobUser ) + '/' +
                 %trimr( PgmSDS.JobName );
        rc = writeOutput( Buffer + EOL );
        // Output a blank line
        rc = writeOutput( EOL );

        // Output the program information
        rc = writeOutput( '<h2>Program Information</h2>' + EOL );
        Buffer = 'CGI Program:' + ' ' +
                 %trimr( PgmSDS.PgmLib  ) + '/' +
                 %trimr( PgmSDS.MainProc );
        rc = writeOutput( Buffer + EOL );
        // Output a blank line
        rc = writeOutput( EOL );

        // Output the www_validate session ID and user id
        rc = writeOutput( '<h2>WWWVALID Information</h2>' + EOL );
        cvthc( %addr( www_sessionidX ) : %addr( www_sessionid ) : 32 );
        rc = writeOutput( 'Session ID: x''' + www_sessionidX + '''' + EOL );
        www_usrprf = www_getusrprf( www_sessionid );
        rc = writeOutput( 'Signed on as: ' +  www_usrprf + EOL );
        // Output a blank line
        rc = writeOutput( EOL );

        // Display all the environment variables
        rc = writeOutput( '<h2>Environment variables</h2>' + EOL );
        // Initialize the environ pointer
        if Qp0zInitEnv() <> 0 or environ = *null;
          exsr *pssr;
        endif;
        for x = 1 to %elem( envvarptr );
          if envvarptr(x) = *null;
            leave;
          endif;
          rc = writeOutput( %str( envvarptr(x) ) + EOL );
        endfor;
        // Output a blank line
        rc = writeOutput( EOL );

        // Write out how long the transaction took
        secs = %diff(%timestamp():start_ts:*mseconds);
        Buffer = 'Transaction took ' + %char(secs) + ' microseconds.';
        rc = writeOutput( Buffer + EOL );

        // Write out the final lines
        for x = 1 to %elem( HTML2 );
          rc = writeOutput( HTML2(x) + EOL );
        endfor;

        return;

        begsr *pssr;
          return;
        endsr;

      /end-free
      *=============================================================================================
      * rtvenvvar(): Retrieves an environment variable.
      *=============================================================================================
     P rtvenvvar       B
     D                 PI         65535A   Varying
     D   envvar                      50A   Const Varying
      *---------------------------------------------------------------------------------------------
     D envvalptr       S               *   Inz
     D rtnval          S          65535A   Varying
      *---------------------------------------------------------------------------------------------
      /free

        envvalptr = getenv( envvar );
        if envvalptr <> *null;
          rtnval = %str( envvalptr );
        else;
          clear rtnval;
        endif;

        return rtnval;

      /end-free
     P                 E
      *=============================================================================================
      * getcgival(): Retrieves a CGI variable from a CGI string.
      *=============================================================================================
     P getcgival       B
     D                 PI          1024A   Varying
     D   var                         50A   Const Varying
     D   string                    5000A   Const Varying
      *---------------------------------------------------------------------------------------------
     D val             S           1024A   Varying
     D p1              S             10I 0
     D p2              S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        p1 = %scan( var + '=' : string );
        if p1 > 0;
          p1 += %len( var ) + 1;
          p2 = %scan( '&' : string : p1 );
          if p2 >= p1;
            val = %subst( string : p1 : p2 - p1 );
          else;
            val = %subst( string : p1 );
            if %subst( val : %len( val ) : 1 ) = *blanks;
              val = %trimr( val );
            endif;
          endif;
        else;
          exsr *pssr;
        endif;

        return val;

        begsr *pssr;
          clear val;
          return val;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * writeOutput(): Write a line to STDOUT
      *
      *   Accepts:
      *     pBuffer      (I) Buffer to write
      *   Returns:
      *     boolean      (O) 0 if all data written
      *
      *=============================================================================================
     P writeOutput     B
     D                 PI            10I 0
     D   pBuffer                  65535A   Const Varying
      *---------------------------------------------------------------------------------------------
     D Buffer          S          65535A   Static
     D bytes           S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        %subst( Buffer : 1 : %len( pBuffer ) ) = pBuffer;
        bytes = write( STDOUT : %addr( Buffer ) : %len( pBuffer ) );

        return ( bytes - %len( pBuffer ) );

        // *PSSR: Error-handling subroutine
        begsr *pssr;
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
** CTDATA HTML1
content-type: text/html

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <title>Web Access User Validator Test Harness WWWVALIDT2</title>
  </head>
  <body>
    <pre>
** CTDATA HTML2
    </pre>
    <form name="signon" method="post" action="">
      <input type="submit" name="logoff" value="Log off">
    </form>
  </body>
</html>
