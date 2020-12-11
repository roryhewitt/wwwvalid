     H DEBUG(*YES) NOMAIN
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
      *
      *D:
      *D: This module is bound into the WWWVALID service program and
      *D: contains a number of procedures that can be called from your
      *D: CGI programs to add security and timeout functionality.
      *D:
      *D: See the Web Access User Validator User Guide for full details.
      *D:
      *D: Note: To make compilation as simple as possible, this module
      *D:       contains a number of prototypes to external procedures
      *D:       and programs which would normally be included in
      *D:       separate copybooks. Feel free to copy those prototypes
      *D:       into copybooks and reference those copybooks here.
      *D:
      *D:       Additionally, this module contains a number of procedures
      *D:       which would normally be compiled into their own module(s)
      *D:       and possibly bound into separate service programs.
      *D:       Examples are the 'writeOutput' procedure and the
      *D:       encryption procedures. If you wish, you may strip these
      *D:       procedures from this module and copy them into their own
      *D:       module(s) and then compile and bind that module into the
      *D:       WWWVALID service program. Note that, because of library
      *D:       list issues, it is generally advisable NOT to link to
      *D:       other service programs in CGI-related programs or objects
      *D:       unless you explicitly library-qualify them.
      *D:
      *=============================================================================================
      * Program identification (DO NOT CHANGE THESE VALUES)
      *---------------------------------------------------------------------------------------------

     D ThisProgram     C                   'WWWVALID'
     D ThisVersion     C                   '1.0'
     D ThisDataLevel   C                   10

      *---------------------------------------------------------------------------------------------
      * Copybooks
      *---------------------------------------------------------------------------------------------

      /copy qsrc,wwwvalid_p                       Web Access User Validator Prototypes

      *---------------------------------------------------------------------------------------------
      * External program/procedure prototypes
      *---------------------------------------------------------------------------------------------

      * QSYRLSPH - Release Profile Handle
     D qsyrlsph        pr                  Extpgm('QSYRLSPH')
     D   PrfHandle                         Const Like(PrfHandle_t)
     D   ApiError                                Likeds(QUSEC_T)

      * QSYGETPH - Get Profile Handle
     D qsygetph        pr                  extpgm('QSYGETPH')
     D   UsrPrf                      10A   Const
     D   Password                   512A   Const
     D   PrfHandle                               Like(PrfHandle_t)
     D   ApiError                                Likeds(QUSEC_T)
     D   PwdLen                      10I 0 Const Options(*nopass)
     D   PwdCCSID                    10I 0 Const Options(*nopass)

      * QWTSETP - Set User Profile API
     D qwtsetp         PR                  Extpgm('QWTSETP')
     D   PrfHandle                         Const Like(PrfHandle_t)
     D   ApiError                                Likeds(QUSEC_T)
     D                                           Options(*Nopass)

     D PrfHandle_t     S             12A   Based(TEMPLATE)

      * QMHRMVPM - Remove Program Messages API
     D qmhrmvpm        PR                  Extpgm('QMHRMVPM')
     D   CSE                       4096A   Const
     D   CSC                         10I 0 Const
     D   MsgKey                       4A   Const
     D   MsgsToRemove                10A   Const
     D   ApiError                                Like(QUSEC_T)
     D   CSELen                      10I 0 Const Options(*Nopass)
     D   qCSE                        20A   Const Options(*Nopass)
     D   RmvUnhdlExcp                10A   Const Options(*Nopass)
     D   CSEDtaTyp                   10A   Const Options(*Nopass)

      * QMHRTVM - Retrieve Message API
     D qmhrtvm         PR                  Extpgm('QMHRTVM')
     D   MsgInf                   65535A         Options(*Varsize)
     D   MsgInfLen                   10I 0 Const
     D   Format                       8A   Const
     D   Msgid                        7A   Const
     D   qMsgf                       20A   Const
     D   RplDta                   65535A   Const Options(*Varsize)
     D   RplDtaLen                   10I 0 Const
     D   RplSubVar                   10A   Const
     D   RtnFmtCtlChr                10A   Const
     D   ApiError                                Like(QUSEC_T)
     D   RtvOpt                      10A   Const Options(*Nopass)
     D   CvtToCCSID                  10I 0 Const Options(*Nopass)
     D   RplDtaCCSID                 10I 0 Const Options(*Nopass)

      * getenv: Get the value of an environment variable
     D getenv          pr              *   extproc('getenv')
     D   envvar                        *   value options(*string)

      * open: Open a file
     D open            PR            10I 0 ExtProc('open')
     D  filename                       *   Value options(*string)
     D  openflags                    10I 0 Value
     D  mode                         10U 0 Value options(*nopass)
     D  codepage                     10U 0 Value options(*nopass)
     D  creatcnvid                   10U 0 Value options(*nopass)

      * close: Close a file
     D close           PR            10I 0 ExtProc('close')
     D  handle                       10I 0 Value

      * read: Read from a file
     D read            pr            10i 0 extproc('read')
     D  handle                       10i 0 Value
     D  buffer                         *   Value
     D  bytes                        10u 0 Value

      * write: Write to a file
     D write           PR            10I 0 ExtProc('write')
     D  handle                       10I 0 Value
     D  buffer                         *   Value
     D  bytes                        10U 0 Value

      * Constants
     D STDIN           C                   0
     D STDOUT          C                   1

      * QUSCRTUS - Create User Space
     D quscrtus        PR                  Extpgm('QUSCRTUS')
     D  qUsrSpc                            Const Likeds(qObj_t)
     D  ExtAtr                             Const Like(ValidName_t)
     D  InitSize                     10i 0 Const
     D  InitVal                       1a   Const
     D  PubAut                       10A   Const
     D  Text                         50a   Const
     D  Replace                      10a   Const
     D  ApiError                                 Likeds(QUSEC_T)
     D  Domain                       10    Const Options(*nopass)

      * QUSPTRUS - Get Pointer to User Space
     D qusptrus        PR                  Extpgm('QUSPTRUS')
     D   qUsrSpc                           Const Likeds(qObj_t)
     D   UsrSpcPtr                     *
     D   ApiError                          likeds(QUSEC_T) options(*nopass)

      * QDCXLATE - Translate String
     D qdcxlate        PR                  Extpgm('QDCXLATE')
     D   datalen                      5P 0 Const
     D   data                     65535A         Options(*Varsize)
     D   SBCStable                   10A   Const
      * Optional parms
     D   SBCStablelib                10A   Const Options(*Nopass)
     D   outdata                  65535A         Options(*Varsize:*Nopass)
     D   outbufflen                   5P 0 Const Options(*Nopass)
     D   outdatalen                   5P 0 Const Options(*Nopass)
     D   DBCSlang                    10A   Const Options(*Nopass)
     D   SISOChars                    1A   Const Options(*Nopass)
     D   ConvertType                 10A   Const Options(*Nopass)

      * QWCRSVAL - Retrieve System Value
     D qwcrsval        PR                  Extpgm('QWCRSVAL')
     D   RcvVar                   65535A         Options(*Varsize)
     D   RcvVarLen                   10I 0 Const
     D   NbrSysVal                   10I 0 Const
     D   SysValArr                  100A   Const
     D   ApiError                                Like(QUSEC_T)

     D SysValArr       DS                  Qualified
     D   SysVal                      10A   Dim(10)

     D sysvaldta_t     DS         65535    Qualified
     D   NbrValRtn                   10I 0
     D   SysValOSArr                 10I 0 Dim(10)

     D SysVal_t        DS         65535    Qualified Based(TEMPLATE)
     D   Name                        10A
     D   DtaTyp                       1A
     D   InfSts                       1A
     D   DtaLen                      10I 0

      * locksl2 - Lock Space Location
     D locksl2         PR                  Extproc('_LOCKSL2')
     D   lock_request                  *   Const

      * unlocksl1 - Unlock Space Location
     D unlocksl1       PR                  Extproc('_UNLOCKSL1')
     D   location                      *   Const
     D   lock_request                 3I 0 Const

     D LOCKSL_EXCLRD   C                   16

      * Qc3EncryptData - Encrypt Data
     D Qc3EncryptData  PR                  Extproc('Qc3EncryptData')
     D   ClearData                65535A   Const Options(*Varsize)
     D   ClearDataLen                10I 0 Const
     D   Format                       8A   Const
     D   AlgDesc                  65535A   Const Options(*Varsize)
     D   AlgFormat                    8A   Const
     D   KeyDesc                  65535A   Const Options(*Varsize)
     D   KeyFormat                    8A   Const
     D   CryptProv                    1A   const
     D   CryptDevice                 10A   Const
     D   EncData                  65535A         Options(*Varsize)
     D   EncDataSize                 10I 0 Const
     D   EncDataLen                  10I 0
     D   ApiError                          Likeds(QUSEC_t)

      * Qc3DecryptData - Decrypt Data
     D Qc3DecryptData  PR                  Extproc('Qc3DecryptData')
     D   ClearData                65535A   Const Options(*Varsize)
     D   ClearDataLen                10I 0 Const
     D   AlgDesc                  65535A   Const Options(*Varsize)
     D   AlgFormat                    8A   Const
     D   KeyDesc                  65535A   Const Options(*Varsize)
     D   KeyFormat                    8A   Const
     D   CryptProv                    1A   const
     D   CryptDevice                 10A   Const
     D   EncData                  65535A         Options(*Varsize)
     D   EncDataSize                 10I 0 Const
     D   EncDataLen                  10I 0
     D   ApiError                          Likeds(QUSEC_t)

     D ALGD0300_t      DS                  Qualified Based(TEMPLATE)
     D   Algorithm                   10I 0

     D KEYD0200_t      DS                  Qualified Based(TEMPLATE)
     D   KeyType                     10I 0
     D   KeyLen                      10I 0
     D   KeyFmt                       1A
     D                                5I 0
     D                                3I 0
     D   Key                        256A

     D CRYPT_SRV_ANY   C                   '0'
     D STREAM_CIPHER_RC4...
     D                 C                   30
     D KEY_TYPE_RC4    C                   30
     D ENCRYPT_DATA    C                   '*ENCRYPT'
     D DECRYPT_DATA    C                   '*DECRYPT'

      * printf - Output to job log
     D printf          PR            10I 0 ExtProc('Qp0zLprintf')
     D  message                        *   Value Options(*String)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)
     D                                 *   Value Options(*String:*Nopass)

      * atoi - Convert alpha to integer
     D atoi            PR            10I 0 Extproc('atoi')
     D                                 *   Value Options(*String)

      * cvtch - Convert character to hex
     D cvtch           PR                  Extproc('cvtch')
     D   target                        *   Value
     D   source                        *   Value
     D   sourcelen                   10i 0 Value

      * cvthc - Convert hex to character
     D cvthc           PR                  Extproc('cvthc')
     D   Tgt_Char                      *   Value
     D   Src_Hex                       *   Value
     D   Tgt_Len                     10I 0 Value

      *---------------------------------------------------------------------------------------------
      * Internal procedure prototypes
      *---------------------------------------------------------------------------------------------

      * setUsrSpcPtr(): Set the pointer to the control user space
     D setUsrSpcPtr    PR            10I 0 Extproc('setUsrSpcPtr')

      * lockslw(): Lock Space Location with Wait
     D lockslw         PR              N   Extproc('lockslw')
     D   ptr                           *   Const
     D   lockstate                    3U 0 Const
     D   waittime                    10I 0 Const Options(*Nopass)

      * unlockslw(): Unlock Space Location with Wait
     D unlockslw       PR              N   Extproc('unlockslw')
     D   ptr                           *   Const
     D   lockstate                    3U 0 Const

      * buildSignonPage(): Build the signon page
     D buildSignonPage...
     D                 PR            10I 0 Extproc('buildSignonPage')

      * buildErrorPage(): Build the error page
     D buildErrorPage  PR            10I 0 Extproc('buildErrorPage')

      * validateCredentials(): Validate the signon credentials
     D validateCredentials...
     D                 PR            10I 0 Extproc('validateCredentials')

      * writeCookie(): Write out the cookie value to the browser
     D writeCookie     PR            10I 0 Extproc('writeCookie')
     D   pCookie                           Like(gCookie) Const

      * getCookie: Get the cookie value from the browser
     D getCookie       PR                  Like(gCookie)
     D                                     Extproc('getCookie')

      * setCookie: Set the new cookie value
     D setCookie       PR                  Like(gCookie)
     D                                     Extproc('setCookie')
     D   pTimestamp                    Z   Const

      * setCtlRcd: Set a control record in the user space
     D setCtlRcd       PR            10I 0
     D                                     Extproc('setCtlRcd')
     D   pCookie                                 Like(gCookie)
     D   pCtlRcd                           Const Likeds(ctlrcd_t)

      * getCtlRcd: Get a control record from the user space
     D getCtlRcd       PR            10I 0
     D                                     Extproc('getCtlRcd')
     D   pCookie                           Const Like(gCookie)
     D   pCtlRcd                                 Likeds(ctlrcd_t)

      * swapUsrPrf: Swap the user profile
     D swapUsrPrf      PR            10I 0
     D                                     Extproc('swapUsrPrf')
     D   pSessionIdx                 10I 0 Const
     D   pSwapType                   10I 0 Const

      * writeOutput(): Write a line to standard output
     D writeOutput     PR            10I 0 Extproc('writeOutput')
     D   pBuffer                           Const Like(Buffer_t)

      * getErrMsg(): Retrieve an error message by index number
     D getErrMsg       PR           100A   Varying Extproc('getErrMsg')
     D   pMsgf                       10A   Const
     D   pErrMsgIdx                  10I 0 Const

      * rtvenvvar(): Retrieve an environment variable
     D rtvenvvar       PR         65535A   Varying Extproc('rtvenvvar')
     D   envvar                      50A   Const Varying

      * getcgival(): Get a variable's value from a CGI string
     D getcgival       PR          1024A   Varying Extproc('getcgival')
     D   var                         50A   Const Varying
     D   string                    5000A   Const Varying

      * cvtcgistr(): Convert a CGI string to readable format
     D cvtcgistr       PR          8192A   Varying Extproc('cvtcgistr')
     D   cgistr                    8192A   Varying Const

      * splitString(): Parse a string into its constituent words
     D splitString     PR            10I 0 Extproc('splitString')
     D   string                   65535A   Const Varying Options(*Varsize)
     D   wordarray                               Likeds(wordarray_t)

      * cryptRC4(): Encrypt/decrypt a string with the RC4 algorithm
     D cryptRC4        PR         65535A   Varying Extproc('cryptRC4')
     D   Data                     65535A   Const Varying Options(*Varsize)
     D   Password                   256A   Const Varying Options(*Varsize)
     D   Action                      10A   Const
     D   ApiError                          Likeds(QUSEC_T) Options(*Nopass)

      *---------------------------------------------------------------------------------------------
      * Compile-time arrays
      *---------------------------------------------------------------------------------------------

     D extarrds        DS
     D   errmsgarr                         dim(11) ctdata
     D     errmsgid                   7A   overlay(errmsgarr)
     D                                1    overlay(errmsgarr:*next)
     D     errmsgtxt                 92A   overlay(errmsgarr:*next)

      *---------------------------------------------------------------------------------------------
      * Global variables
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

      * Standard definitions and constants
     D LOWER           C                   'abcdefghijklmnopqrstuvwxyz'
     D UPPER           C                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
     D DIGITS          C                   '1234567890'
     D EOL             C                   x'25'
     D rc              S             10I 0
     D ValidName_t     S             10A   Based(TEMPLATE)
     D ObjString_t     S             21A   Based(TEMPLATE)
     D qObj_t          DS                  Qualified Based(TEMPLATE)
     D   Obj                               Like(ValidName_t)
     D   Lib                               Like(ValidName_t)
     D Timestamp_Char_t...
     D                 DS                   Qualified Based(TEMPLATE)
     D   C1                           1A
     D     C1_S                       1S 0  Overlay(C1)
     D   C2                           1A
     D     C2_S                       1S 0  Overlay(C2)
     D   Y1                           1A
     D     Y1_S                       1S 0  Overlay(Y1)
     D   Y2                           1A
     D     Y2_S                       1S 0  Overlay(Y2)
     D                                1A
     D   M1                           1A
     D     M1_S                       1S 0  Overlay(M1)
     D   M2                           1A
     D     M2_S                       1S 0  Overlay(M2)
     D                                1A
     D   D1                           1A
     D     D1_S                       1S 0  Overlay(D1)
     D   D2                           1A
     D       D2_S                     1S 0  Overlay(D2)
     D                                1A
     D   H1                           1A
     D     H1_S                       1S 0  Overlay(H1)
     D   H2                           1A
     D     H2_S                       1S 0  Overlay(H2)
     D                                1A
     D   N1                           1A
     D     N1_S                       1S 0  Overlay(N1)
     D   N2                           1A
     D     N2_S                       1S 0  Overlay(N2)
     D                                1A
     D   S1                           1A
     D     S1_S                       1S 0  Overlay(S1)
     D   S2                           1A
     D     S2_S                       1S 0  Overlay(S2)
     D                                1A
     D   MS1                          1A
     D     MS1_S                      1S 0  Overlay(MS1)
     D   MS2                          1A
     D     MS2_S                      1S 0  Overlay(MS2)
     D   MS3                          1A
     D     MS3_S                      1S 0  Overlay(MS3)
     D   MS4                          1A
     D     MS4_S                      1S 0  Overlay(MS4)
     D   MS5                          1A
     D     MS5_S                      1S 0  Overlay(MS5)
     D   MS6                          1A
     D     MS6_S                      1S 0  Overlay(MS6)

     D qusec_t         DS                  Inz Qualified
     D  ErrBytesProv                 10I 0 Inz(%size(qusec_t))
     D  ErrBytesAvail                10I 0
     D  ErrMsgID                      7A
     D                                1
     D  ErrMsgDta                   512A

     D wordarray_t     DS                  Qualified Based(TEMPLATE)
     D   nbrelm                      10I 0
     D   word                       128A   Varying Dim(128)

      * Control user space
     D ctlrcdarrsize   S             10I 0
     D UsrSpcPtr       S               *
     D                 DS                  based(UsrSpcPtr)
     D usrspchdr
     D   ctlrcdmax                   10I 0 overlay(usrspchdr)
     D   passwdlvl                   10I 0 overlay(usrspchdr:*next)
     D    passwdlvl_c                 4A   overlay(passwdlvl)
     D   passwdlen                   10I 0 overlay(usrspchdr:*next)
     D   datalevel                   10I 0 overlay(usrspchdr:*next)
     D ctlrcdarr                           dim(32767)
     D   cookieval                   64A   overlay(ctlrcdarr)
     D   ctlrcdval                         overlay(ctlrcdarr:*next)
     D                                     like(ctlrcd_t)
     D     ssnidval                        overlay(ctlrcdval)
     D                                     like(www_sessionid_t)

     D ctlrcd_t        DS                  Qualified Based(TEMPLATE)
     D   sessionid                         like(www_sessionid_t)
     D   usrprf                     128A
     D   passwd                     128A
     D   swapped                       N
     D   sysusrprf                     N
     D   init                          Z
     D   last                          Z
     D   pagetimeout                 10I 0
     D   sesstimeout                 10I 0
     D   cookieopt                   10I 0
     D   status                      10I 0
     D   msgf                        10A

     D cStatus_Active  C                   1
     D cStatus_Ended   C                   2
     D cStatus_Timed   C                   3
     D cStatus_Signon  C                   4

     D gCtlRcd         DS                  Likeds(ctlrcd_t)
     D Key             S             64A

      * Exit program definition
     D www_exitpgm_qn  S             21A
     D www_exitpgm     PR                  ExtPgm(www_exitpgm_qn)
     D   userid                     128A   Const
     D   passwd                     128A   Const
     D   valid                       10I 0
     D   errmsg                     100A         Varying
     D   rtnusrprf                   10A

     D gCookie         S             64A
     D gSessionId      S                   Like(www_sessionid_t)
     D Buffer_t        S          65535A   Varying
     D PrfHandle       S                   Like(PrfHandle_t)
     D gErrMsg         S            100A   Varying
     D gPath_Signon    S            256A   Varying
     D gPath_Error     S            256A   Varying

     D cContType_html  C                   'Content-Type: text/html'
     D cCookieName     C                   'WWWVALID-COOKIE'
     D cSignon         C                   '*SIGNON'
     D cError          C                   '*ERROR'
     D cEnded          C                   '*ENDED'
     D cSessionCookie  C                   'SESSION'
     D cPageCookie     C                   'PAGE'
     D cUsrprf_Field   C                   'www_validate-userid'
     D cPasswd_Field   C                   'www_validate-passwd'
     D cErrMsg_Var     C                   'www_validate-errmsg'
     D cPTimeout_Var   C                   'www_validate-pagetimeout'
     D cSTimeout_Var   C                   'www_validate-sessiontimeout'
     D cSwapToNew      C                   0
     D cSwapToOrig     C                   1

      *=============================================================================================
      * EXPORTED PROCEDURES
      *=============================================================================================
      * www_validate(): Validate browser access for user.
      *
      *   Accepts:
      *     parms        (I) Parameter string
      *   Returns:
      *     sessionid    (O) Session identifier
      *
      *=============================================================================================
     P www_validate    B                   Export
     D                 PI                  like(www_sessionid_t)
     D   parms                     1024A   Const Options(*Nopass)
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(QUSEC_T) Inz(*Likeds)
     D wordarray       DS                  Likeds(wordarray_t)
     D kwdvar          S                   Like(wordarray_t.word)
     D kwdval          S                   Like(wordarray_t.word)
     D w               S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        // Initialize global variables
        clear gCtlRcd;
        clear gErrMsg;

        // Check if the user space must be initialized. If there is an
        // error, then the user space doesn't exist, so create it.
        monitor;
          if ctlrcdmax = 0;
            exsr getParms;
            if setUsrSpcPtr() <> 0;
              exsr *pssr;
            endif;
          endif;
        on-error;
          // Remove error message from job log and create user
          // space or reset pointer to it.
          reset QUSEC;
          qmhrmvpm( '*' : 0 : *blanks : '*ALL' : QUSEC );
          exsr getParms;
          if setUsrSpcPtr() <> 0;
            exsr *pssr;
          endif;
        endmon;

        // Retrieve the current cookie value from the browser
        gCookie = getCookie();

        if gCookie = *blanks;
          // No cookie found, so retrieve parameter values
          // and build the signon page to send to the browser
          exsr getParms;
          gCtlRcd.status = cStatus_Signon;
          if setCtlRcd( gCookie : gCtlRcd ) <> 0;
            exsr *pssr;
          endif;
          rc = buildSignonPage();
        else;
          // Retrieve control record for cookie
          if getCtlRcd( gCookie : gCtlRcd ) <> 0;
            exsr *pssr;
          endif;
          select;
            // If last page sent to browser was signon page,
            // retrieve user-entered values and validate them
            when gCtlRcd.status = cStatus_Signon;
              rc = validateCredentials();
            // Session has ended/expired, so redisplay signon page
            when gCtlRcd.status <> cStatus_Active;
              exsr getParms;
              rc = setCtlRcd( gCookie : gCtlRcd );
              rc = buildSignonPage();
            other;
              // Update control record as required
              rc = setCtlRcd( gCookie : gCtlRcd );
              rc = writeCookie( gCookie );
          endsl;
        endif;

        exsr return;

                              // ============ //
                              // SUBROUTINES  //
                              // ============ //

        // getParms: Retrieve the parameter values
        begsr getParms;
          // Set default values;
          gCtlRcd.pagetimeout = 0;
          gCtlRcd.sesstimeout = 0;
          gPath_Signon = '/wwwvalid/login.html';
          gPath_Error  = '/wwwvalid/error.html';
          gCtlRcd.CookieOpt = 0;
          clear www_exitpgm_qn;
          gCtlRcd.Msgf = wwwvalid_name;
          if %parms > 0 and parms <> *blanks;
            // Split the parameter into its keyword/value pairs
            if splitString( parms : wordarray ) <> 0;
              printf( 'WWWVALID: Error in splitString().' + EOL );
              exsr *pssr;
            endif;
            // Process each keyword/value pair
            for w = 1 to wordarray.nbrelm by 2;
              kwdvar = %xlate( UPPER : LOWER : wordarray.word(w) );
              kwdval = wordarray.word(w+1);
              // Check for matching var/val
              if kwdval = *blanks or %subst( kwdval : 1 : 1 ) = '-';
                printf( 'WWWVALID: Invalid parameter: %s' + EOL : kwdval );
                exsr *pssr;
              endif;
              select;
                when kwdvar = '-pagetimeout';
                  gCtlRcd.pagetimeout = atoi( kwdval );
                when kwdvar = '-sessiontimeout';
                  gCtlRcd.sesstimeout = atoi( kwdval );
                when kwdvar = '-signonpage';
                  gPath_Signon = kwdval;
                when kwdvar = '-errorpage';
                  gPath_Error = kwdval;
                when kwdvar = '-cookieoption';
                  select;
                    when %xlate( LOWER : UPPER : kwdval ) = cSessionCookie;
                      gCtlRcd.CookieOpt = 0;
                    when %xlate( LOWER : UPPER : kwdval ) = cPageCookie;
                      gCtlRcd.CookieOpt = 1;
                    other;
                      printf( 'Invalid value for -cookieoption' + EOL );
                  endsl;
                when kwdvar = '-exitpgm';
                  www_exitpgm_qn = %xlate( LOWER : UPPER : kwdval );
                when kwdvar = '-msgf';
                  gCtlRcd.Msgf = %xlate( LOWER : UPPER : kwdval );
                other;
                  printf( 'WWWVALID: Unknown keyword: %s'+ EOL : kwdvar );
              endsl;
            endfor;
          endif;
        endsr;

        // return: Return session ID to caller
        begsr return;
          return gSessionId;
        endsr;

        // *pssr: Error-handling subroutine
        begsr *pssr;
          printf( 'WWWVALID: Error in www_validate().' + EOL );
          if gErrMsg = *blanks;
            gErrMsg = getErrMsg( gCtlRcd.msgf : 1);
          endif;
          rc = buildErrorPage();
          clear gSessionId;
          exsr return;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * www_endsession(): Delete the session record
      *
      *   Accepts:
      *     pSessionId   (I) Session identifier
      *   Returns:
      *     rtnval       (O) 0 if successful, -1 if unsuccessful
      *
      *=============================================================================================
     P www_endsession  B                   Export
     D                 PI            10I 0
     D pSessionId                          Const like(www_sessionid_t)
      *---------------------------------------------------------------------------------------------
     D ctlrcd          DS                  Likeds(ctlrcd_t)
     D rtnval          S             10I 0 Inz
     D i               S             10I 0 Inz
      *---------------------------------------------------------------------------------------------
      /free

        i = %lookup( pSessionID : ssnidval : 1 : ctlrcdmax );
        if i > 0;
          ctlrcd = ctlrcdval(i);
          ctlrcd.status = cStatus_Ended;
          ctlrcd.usrprf = *blanks;
          ctlrcd.passwd = *blanks;
          ctlrcdval(i) = ctlrcd;
        endif;

        exsr return;

        begsr return;
          return rtnval;
        endsr;

        begsr *pssr;
          printf( 'WWWVALID: Error in www_endsession().' + EOL );
          rtnval = -1;
          exsr return;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * www_getusrprf(): Retrieve the user profile for the session
      *
      *   Accepts:
      *     pSessionId   (I) Session identifier
      *   Returns:
      *     usrprf       (O) User profile associated with session
      *
      *=============================================================================================
     P www_getusrprf   B                   Export
     D                 PI            10A
     D pSessionId                          Const like(www_sessionid_t)
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(QUSEC_T) Inz(*Likeds)
     D i               S             10I 0 Inz
     D ctlrcd          DS                  Likeds(ctlrcd_t)
     D wUsrPrf         S                   Like(ctlrcd.usrprf) Inz
      *---------------------------------------------------------------------------------------------
      /free

        // Search for the existing session in the control array
        i = %lookup( pSessionId : ssnidval : 1 : ctlrcdmax );
        if i > 0;
          ctlrcd = ctlrcdval(i);
          if ctlrcd.usrprf <> *blanks;
            // Decrypt the user profile into a temporary variable
            reset QUSEC;
            wUsrPrf = cryptRC4( ctlrcd.usrprf : Key :
                                DECRYPT_DATA : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
          endif;
        endif;

        return wUsrPrf;

        begsr *pssr;
          printf( 'WWWVALID: Error in www_getusrprf().' + EOL );
          return wUsrPrf;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * www_swapusrprf(): Swap to the specified user profile.
      *
      *   Accepts:
      *     pSessionId   (I) Session identifier
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P www_swapusrprf  B                   Export
     D                 PI            10I 0
     D   pSessionId                        Const like(www_sessionid_t)
      *---------------------------------------------------------------------------------------------
     D i               S             10I 0 Inz
      *---------------------------------------------------------------------------------------------
      /free

        // Search for the existing session in the control array
        i = %lookup( pSessionId : ssnidval : 1 : ctlrcdmax );
        if i > 0;
          rc = swapUsrPrf( i : cSwapToNew );
        else;
          exsr *pssr;
        endif;

        return rc;

        begsr *pssr;
          printf( 'WWWVALID: Error in www_swapusrprf().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * www_resetusrprf(): Swap back to the original user profile.
      *
      *   Accepts:
      *     pSessionId   (I) Session identifier
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P www_resetusrprf...
     P                 B                   Export
     D                 PI            10I 0
     D   pSessionId                        Const like(www_sessionid_t)
      *---------------------------------------------------------------------------------------------
     D i               S             10I 0 Inz
      *---------------------------------------------------------------------------------------------
      /free

        // Search for the existing session in the control array
        i = %lookup( pSessionId : ssnidval : 1 : ctlrcdmax );
        if i > 0;
          rc = swapUsrPrf( i : cSwapToOrig );
        else;
          exsr *pssr;
        endif;

        return rc;

        begsr *pssr;
          printf( 'WWWVALID: Error in www_resetusrprf().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * INTERNAL SUBPROCEDURES
      *=============================================================================================
      * setUsrSpcPtr(): Set the pointer to the user space
      *
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P setUsrSpcPtr    B
     D                 PI            10I 0
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(QUSEC_t) Inz(*Likeds)
     D qUsrSpc         DS                  Likeds(qObj_t)
     D sysvaldta       DS                  Likeds(sysvaldta_t)
     D sysval          DS                  Likeds(sysval_t) Based(sysvalptr)
     D x               S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        printf( 'WWWVALID: Program %s, version %s' + EOL :
                ThisProgram : ThisVersion );
        printf( 'WWWVALID: Initializing user space...' + EOL );

        // Retrieve the pointer to the control user space. If it
        // doesn't yet exist, create it and initialize it.
        qUsrSpc.Obj = wwwvalid_name;
        qUsrSpc.Lib = PgmSds.PgmLib;
        reset QUSEC;
        qusptrus( qUsrSpc : UsrSpcPtr : QUSEC );
        if QUSEC.ErrBytesAvail > 0;
          if QUSEC.ErrMsgID = 'CPF9801';
            ctlrcdarrsize = %size( usrspchdr ) + %size( ctlrcdarr:*all );
            reset QUSEC;
            quscrtus( qUsrSpc : *blanks : ctlrcdarrsize :
                      x'40' : '*CHANGE' : wwwvalid_text : '*YES' : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
            qusptrus( qUsrSpc : UsrSpcPtr : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
          else;
            exsr *pssr;
          endif;
          // Lock the user space to stop anyone else from
          // accessing it while we are initializing it.
          if not lockslw( UsrSpcPtr : LOCKSL_EXCLRD : 10 );
            exsr *pssr;
          endif;
          ctlrcdmax = 0;
          datalevel = ThisDataLevel;
          // Retrieve the QPWDLVL system value
          SysValArr.SysVal(1) = 'QPWDLVL';
          reset qusec;
          qwcrsval( sysvaldta : %size(sysvaldta) : 1 : SysValArr : qusec );
          if QUSEC.ErrBytesAvail > 0 or sysvaldta.NbrValRtn <> 1;
            exsr *pssr;
          endif;
          sysvalptr = %addr( sysvaldta ) + sysvaldta.SysValOSArr(1);
          passwdlvl_c = %subst( sysval : 17 : sysval.DtaLen );
          // Passwords at level 0 or 1 are 10-byte upper-case.
          // Passwords at level 2 or 3 are 128-byte mixed-case.
          if passwdlvl = 2 or passwdlvl = 3;
            passwdlen = 128;
          else;
            passwdlen = 10;
          endif;
          // Unlock the user space
          unlockslw( UsrSpcPtr : LOCKSL_EXCLRD );
        endif;

        // Build Key as 4 sets of the RHS of the user space pointer (as
        // a combined 64-byte character string). This ensures that it is
        // unique and will change if the user space is deleted.
        for x = 1 to 4;
          cvthc( %addr( Key ) + ( ( x - 1 ) * 16 ) :
                 %addr( UsrSpcPtr ) + 8 :
                 16 );
        endfor;

        return 0;

        begsr *pssr;
          unlockslw( UsrSpcPtr : LOCKSL_EXCLRD );
          printf( 'WWWVALID: Error in setUsrSpcPtr().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * lockslw(): Lock Space Location with Wait
      *
      * Returns TRUE if lock obtained within specified wait time, otherwise
      * returns FALSE.
      *=============================================================================================
     P lockslw         B
     D                 PI              N
     D   location                      *   Const
     D   lockstate                    3U 0 Const
     D   waittime                    10I 0 Const Options(*Nopass)
      *---------------------------------------------------------------------------------------------
     D qusec           DS                  Likeds(qusec_t) Inz(*Likeds)

      * Definition of parameter passed to _LOCKSL2, with hard-coded values
      * for 'number of lock requests' and 'offset to lock state' to specify
      * only a single lock request. Other fields defaulted to common values.
     D lockrqs         DS                  Qualified
     D   nbr_rqs                     10I 0 Inz(1)
     D   lockstate_os                 5I 0 Inz(48)
     D   wait_time                   20U 0 Inz
     D   lock_opt                     3A   Inz(x'400000')
     D   new_evt_mask                 5U 0 Inz
     D   prv_evt_mask                 5U 0 Inz
     D                               11A   Inz(*allx'00')
     D   location                      *   Inz
     D   lockstate                    3U 0 Inz

      * One second time interval, as an MI Standard Time Format value
     D MI_one_second   C                   4096000000
      *---------------------------------------------------------------------------------------------
      /free

        // If a positive value is specified for waittime, use it,
        // otherwise use default value of 0 (job default wait time).
        if %parms > 2 and waittime > 0;
          lockrqs.wait_time = ( waittime * MI_one_second );
        endif;
        lockrqs.location = location;
        lockrqs.lockstate = lockstate + 1;

        locksl2( %addr( lockrqs ) );

        return *on;

        // *PSSR error-handling subroutine. Remove error message from
        // job log and return FALSE.
        begsr *pssr;
          reset qusec;
          qmhrmvpm( '*' : 0 : *blanks : '*ALL' : qusec );
          return *off;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * unlockslw(): Unlock Space Location with Wait
      *
      * Returns TRUE if lock released, otherwise returns FALSE. No actual
      * wait time processing - function name simply mirrors 'lockslw' name.
      *=============================================================================================
     P unlockslw       B
     D                 PI              N
     D   location                      *   Const
     D   lockstate                    3U 0 Const
      *---------------------------------------------------------------------------------------------
     D qusec           DS                  Likeds(qusec_t) Inz(*Likeds)
      *---------------------------------------------------------------------------------------------
      /free

        unlocksl1( location : lockstate );

        return *on;

        // *PSSR error-handling subroutine. Remove error message from
        // job log and return FALSE.
        begsr *pssr;
          reset qusec;
          qmhrmvpm( '*' : 0 : *blanks : '*ALL' : qusec );
          return *off;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      *=============================================================================================
      * buildSignonPage(): Build a signon page
      *
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P buildSignonPage...
     P                 B
     D                 PI            10I 0
      *---------------------------------------------------------------------------------------------
     D fd              S             10I 0
     D openflags       S             10I 0
     D mode            S             10U 0
     D codepage        S             10U 0
     D i               S             10I 0 Inz
     D p               S             10I 0 Inz
     D wBuffer         S                   Like(Buffer_t)
     D bytes           S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        // Write out the cookie string
        rc = writeCookie( gCookie );

        // Write out basic HTTP headers
        if writeOutput( cContType_html + EOL + EOL ) < 0;
          exsr *pssr;
        endif;

        // If a user-defined signon page was specified, load it
        clear wBuffer;
        openflags = 16777217;  // O_RDONLY + O_TEXTDATA
        mode      = 256;       // S_IRUSR
        codepage  = 0;         // *JOB CCSID
        fd = open( gPath_Signon : openflags : mode : codepage : 0 );
        if fd > 0;
          %len( wBuffer ) = %size( wBuffer ) - 2;
          %len( wBuffer ) =
                  read( fd : %addr( wBuffer ) + 2 : %len( wBuffer ) );
        endif;

        // Replace error message with contents of gErrMsg variable
        p = %scan( cErrMsg_Var : wBuffer );
        if p > 0;
          wBuffer = %replace( gErrMsg : wBuffer : p : %len(cErrMsg_Var) );
        endif;

        // Replace page timeout variable with current expiration value
        p = %scan( cPTimeout_Var : wBuffer );
        if p > 0;
          wBuffer = %replace( %char( gCtlRcd.pagetimeout ) :
                              wBuffer : p : %len(cPTimeout_Var) );
        endif;

        // Replace session timeout variable with current expiration value
        p = %scan( cSTimeout_Var : wBuffer );
        if p > 0;
          wBuffer = %replace( %char( gCtlRcd.sesstimeout ) :
                              wBuffer : p : %len(cSTimeout_Var) );
        endif;

        // Write out signon page
        if writeOutput( wBuffer ) < 0;
          exsr *pssr;
        endif;

        clear gSessionId;

        return 0;

        begsr *pssr;
          printf( 'WWWVALID: Error in buildSignonPage().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * buildErrorPage(): Build an error page
      *
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P buildErrorPage  B
     D                 PI            10I 0
      *---------------------------------------------------------------------------------------------
     D fd              S             10I 0
     D openflags       S             10I 0
     D mode            S             10U 0
     D codepage        S             10U 0
     D i               S             10I 0 Inz
     D p               S             10I 0 Inz
     D wBuffer         S                   Like(Buffer_t)
     D bytes           S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        // Write out basic HTTP headers
        if writeOutput( cContType_html + EOL + EOL ) < 0;
          exsr *pssr;
        endif;

        // If a user-defined error page was specified, load it
        clear wBuffer;
        openflags = 16777217;  // O_RDONLY + O_TEXTDATA
        mode      = 256;       // S_IRUSR
        codepage  = 0;         // *JOB CCSID
        fd = open( gPath_Error : openflags : mode : codepage : 0 );
        if fd > 0;
          %len( wBuffer ) = %size( wBuffer ) - 2;
          %len( wBuffer ) =
                  read( fd : %addr( wBuffer ) + 2 : %len( wBuffer ) );
        endif;

        // Replace error message with contents of gErrMsg variable
        p = %scan( cErrMsg_Var : wBuffer );
        if p > 0;
          wBuffer = %replace( gErrMsg : wBuffer : p : %len(cErrMsg_Var) );
        endif;

        // Write out error page
        if writeOutput( wBuffer ) < 0;
          exsr *pssr;
        endif;

        clear gSessionId;

        return 0;

        begsr *pssr;
          printf( 'WWWVALID: Error in buildErrorPage().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * validateCredentials(): Validate the signon credentials.
      *
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P validateCredentials...
     P                 B
     D                 PI            10I 0
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(QUSEC_t) Inz(*Likeds)
     D IsValid         S               N
     D rcvvar          S           1024A
     D rcvlen          S             10I 0
     D wUsrPrf         S            128A
     D wPasswd         S            128A
     D rtnUsrPrf       S             10A
     D wValidSts       S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        IsValid = *off;

        // Read in the form data and parse out the USRPRF and PASSWD
        rcvlen = read( STDIN : %addr( rcvvar ) : %len( rcvvar ) );
        if rcvlen = -1;
          exsr *pssr;
        endif;
        rcvvar = %subst( rcvvar : 1 : rcvlen );
        rcvvar = cvtcgistr( rcvvar );
        wUsrPrf = getcgival( cUsrprf_Field : rcvvar );
        wPasswd = getcgival( cPasswd_Field : rcvvar );

        // If necessary, call the user exit program to validate.
        if www_exitpgm_qn <> *blanks;
          gCtlRcd.sysusrprf = *off;
          callp(e) www_exitpgm( wUsrPrf :
                                wPasswd :
                                wValidSts :
                                gErrMsg :
                                rtnUsrPrf );
          select;
            // Credentials are valid, so no further validation
            // is necessary.
            when wValidSts = EXITPGM_VALID_CREDENTIALS;
              IsValid = *on;
              if rtnUsrPrf <> *blanks;
                wUsrPrf = rtnUsrPrf;
                wPasswd = *blanks;
              endif;
            // Credentials are NOT valid, so build a sign-on page
            // and quit.
            when %error or wValidSts = EXITPGM_INVALID_CREDENTIALS;
              if gErrMsg = *blanks;
                gErrMsg = getErrMsg( gCtlRcd.msgf : 6 );
              endif;
              rc = buildSignonPage();
              return 0;
            // Credentials are for a *USRPRF, so perform system validation
            when wValidSts = EXITPGM_SYSTEM_VALIDATION;
              IsValid = *off;
          endsl;
        endif;

        // Perform system validation to check that the user profile
        // and password are valid IBM i credentials.
        if IsValid = *off;
          gCtlRcd.sysusrprf = *on;
          // Convert user profile upper-case
          wUsrPrf = %xlate( LOWER : UPPER : wUsrPrf );
          select;
            // No user id supplied
            when wUsrPrf = *blanks;
              gErrMsg = getErrMsg( gCtlRcd.msgf : 4 );
            // No password supplied
            when wPasswd = *blanks;
              gErrMsg = getErrMsg( gCtlRcd.msgf : 5 );
            // Different user signing on to timed-out page
            when gCtlRcd.usrprf <> *blanks and
                 gCtlRcd.usrprf <> wUsrPrf;
              gErrMsg = getErrMsg( gCtlRcd.msgf : 9 );
            // Check if the user/password combination is valid
            other;
              // Convert password to upper-case if necessary
              if passwdlen = 10;
                wPasswd = %xlate( LOWER : UPPER : wPasswd );
              endif;
              // Validate user profile/password combination
              reset QUSEC;
              qsygetph( wUsrPrf : wPasswd : PrfHandle :
                        QUSEC : passwdlen : 0 );
              if QUSEC.ErrBytesAvail > 0;
                gErrMsg = getErrMsg( gCtlRcd.msgf : 6 );
              else;
                IsValid = *on;
                reset QUSEC;
                qsyrlsph( PrfHandle : QUSEC );
                clear PrfHandle;
              endif;
          endsl;
        endif;

        // If the userid/passwd are valid, update the control record
        if IsValid;
          gCtlRcd.UsrPrf = wUsrPrf;
          gCtlRcd.Passwd = wPasswd;
          gCtlRcd.status = cStatus_Active;
          rc = setCtlRcd( gCookie : gCtlRcd );
          // Write out a redirect record, to convert this POST
          // response into a GET response, and thus avoid the
          // CGI program from being able to access the password.
          if writeOutput( 'Status: 302 Found' + EOL +
                          'Location: ' + rtvenvvar( 'REQUEST_URI' ) +
                          EOL ) < 0;
            exsr *pssr;
          endif;
          // Write out the cookie string
          rc = writeCookie( gCookie );
          rc = writeOutput( EOL + EOL );
          clear gSessionId;
        else;
          rc = buildSignonPage();
        endif;

        return 0;

        begsr *pssr;
          printf( 'WWWVALID: Error in validateCredentials().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * writeCookie(): Write out the cookie value
      *
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P writeCookie     B
     D                 PI            10I 0
     D   pCookie                           Like(gCookie) Const
      *---------------------------------------------------------------------------------------------
     D rc              S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        if pCookie = *blanks;
          rc = writeOutput( 'Set-Cookie: ' +
                            cCookieName + '=;' + EOL );
        else;
          rc = writeOutput( 'Set-Cookie: ' +
                            cCookieName + '=' +
                            gCookie + '; HttpOnly' + EOL );
        endif;

        return rc;

        begsr *pssr;
          printf( 'WWWVALID: Error in writeCookie().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * getCookie: Get the cookie value from the browser
      *
      *   Returns:
      *     cookie       (O) Cookie value retrieved from envvar
      *
      *=============================================================================================
     P getCookie       B
     D                 PI                  Like(gCookie)
      *---------------------------------------------------------------------------------------------
     D cookieinfo      S          65535A
     D s1              S             10I 0
     D s2              S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        cookieinfo = rtvenvvar( 'HTTP_COOKIE' );
        s1 = %scan( cCookieName + '=' : cookieinfo );
        if s1 > 0;
          s2 = %scan( ';' : cookieinfo : s1 + 1 );
          if s2 = 0;
            s2 = %scan( ' ' : cookieinfo : s1 + 1 );
          endif;
          if s2 > s1;
            s1 += %len( cCookieName + '=' );
            return %subst( cookieinfo : s1 : s2 - s1 );
          endif;
        endif;

        return *blanks;

        begsr *pssr;
          printf( 'WWWVALID: Error in getCookie().' + EOL );
          return *blanks;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * setCookie(): Set the new cookie value and return it
      *
      *   Accepts:
      *     pTimestamp   (I) timestamp to use to build cookie
      *
      *   Returns:
      *     cookie       (O) New cookie value
      *
      *=============================================================================================
     P setCookie       B
     D                 PI                  Like(gCookie)
     D   pTimestamp                    Z   Const
      *---------------------------------------------------------------------------------------------
     D cookie          S                   Like(gCookie) Inz
     D TS              DS                  Likeds(Timestamp_Char_t)
     D JN              DS                  Qualified
     D   c1                           1A
     D   c2                           1A
     D   c3                           1A
     D   c4                           1A
     D   c5                           1A
     D   c6                           1A
     D Chars           S             10A
     D char16          S             16A
     D char            S              1A   Based(CharPtr)
     D x               S             10I 0
     D y               S              1A
     D z               S             10I 0
     D i               S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        // Put the job number into an array
        JN = PgmSDS.JobNbr;
        // Load timestamp into TS structure
        TS = %char( pTimestamp );

        // Create cookie from 4 concatenated 16-character strings (which
        // are individually randomized and then globally randomized).
        for x = 1 to 4;

          // Determine the salt
          select;
            when x = 1;
              y = TS.MS3;
            when x = 2;
              y = TS.MS2;
            when x = 3;
              y = TS.MS4;
            when x = 4;
              y = TS.MS1;
          endsl;

          // Build a 16-character string which is a combination of
          // characters from the job number and characters from the
          // timestamp.
          select;
            when y = '0';
              // Job number is in order 362415 in positions 2,4,7,11,12,16
              char16 = TS.S1 + JN.c3 + TS.Y2 + JN.c6 + TS.C2 + TS.N1 +
                       JN.c2 + TS.N2 + TS.S1 + TS.N2 + JN.c4 + JN.c1 +
                       TS.C1 + TS.H2 + TS.S2 + JN.c5;
            when y = '1';
              // Job number is in order 531642 in positions 1,4,6,8,12,15
              char16 = JN.c5 + TS.S1 + TS.N1 + JN.c3 + TS.M2 + JN.c1 +
                       TS.C2 + JN.c6 + TS.S1 + TS.N2 + TS.S2 + JN.c4 +
                       TS.S2 + TS.H2 + JN.c2 + TS.Y1;
            when y = '2';
              // Job number is in order 342165 in positions 2,5,11,12,14,17
              char16 = TS.N2 + JN.c3 + TS.S1 + TS.N1 + JN.c4 + TS.Y2 +
                       TS.C1 + TS.S2 + TS.S1 + TS.M1 + JN.c2 + JN.c1 +
                       TS.C2 + JN.c6 + TS.S2 + JN.c5;
            when y = '3';
              // Job number is in order 123456 in positions 3,4,8,10,13,16
              char16 = TS.S2 + TS.C2 + JN.c1 + JN.c2 + TS.C1 + TS.N1 +
                       TS.M2 + JN.c3 + TS.S1 + JN.c4 + TS.D1 + TS.S2 +
                       JN.c5 + TS.N2 + TS.Y2 + JN.c6;
            when y = '4';
              // Job number is in order 461325 in positions 2,5,10,12,14,15
              char16 = TS.D1 + JN.c4 + TS.M2 + TS.Y1 + JN.c6 + TS.D1 +
                       TS.S1 + TS.C1 + TS.S1 + JN.c1 + TS.D2 + JN.c3 +
                       TS.N2 + JN.c2 + JN.c5 + TS.Y2;
            when y = '5';
              // Job number is in order 164523 in positions 1,2,7,10,11,16
              char16 = JN.c1 + JN.c6 + TS.N1 + TS.M1 + TS.N1 + TS.N2 +
                       JN.c4 + TS.S2 + TS.S1 + JN.c5 + JN.c2 + TS.Y1 +
                       TS.Y2 + TS.S1 + TS.D1 + JN.c3;
            when y = '6';
              // Job number is in order 436125 in positions 3,5,11,12,14,16
              char16 = TS.C1 + TS.S1 + JN.c4 + TS.Y1 + JN.c3 + TS.N2 +
                       TS.D2 + TS.M2 + TS.S1 + TS.Y2 + JN.c6 + JN.c1 +
                       TS.H2 + JN.c2 + TS.D1 + JN.c5;
            when y = '7';
              // Job number is in order 531642 in positions 1,4,6,8,12,15
              char16 = JN.c5 + TS.S2 + TS.Y1 + JN.c3 + TS.M2 + JN.c1 +
                       TS.Y2 + JN.c6 + TS.S1 + TS.M1 + TS.S2 + JN.c4 +
                       TS.C1 + TS.H2 + JN.c2 + TS.Y1;
            when y = '8';
              // Job number is in order 342165 in positions 2,5,11,12,14,17
              char16 = TS.N1 + JN.c3 + TS.Y2 + TS.N1 + JN.c4 + TS.Y2 +
                       TS.C1 + TS.Y1 + TS.S1 + TS.C2 + JN.c2 + JN.c1 +
                       TS.C2 + JN.c6 + TS.S2 + JN.c5;
            when y = '9';
              // Job number is in order 123456 in positions 3,4,8,10,13,16
              char16 = TS.S1 + TS.N2 + JN.c1 + JN.c2 + TS.C2 + TS.M1 +
                       TS.M2 + JN.c3 + TS.S1 + JN.c4 + TS.D1 + TS.S2 +
                       JN.c5 + TS.N2 + TS.Y2 + JN.c6;
            other;
              exsr *pssr;
          endsl;

          // Convert/randomize
          i = %int(TS.MS1);
          if i = 0;
            i = 1;
          endif;
          for z = 1 to %len( char16 );
            charptr = %addr( char16 ) + z - 1;
            Chars = %subst( Key : i : 10 );
            Char = %xlate( DIGITS : Chars : Char );
            i = i + 2;
            if i > 52;
              i = 1;
            endif;
          endfor;

          // Append 16-character to form full cookie value
          %subst( cookie : ( x * 16 ) - 15 : 16 ) = char16;

        endfor;

        // Final conversion/randomizing process
        for z = 1 to %len( cookie );
          charptr = %addr( cookie ) + z - 1;
          Chars = %subst( Key : i : 10 );
          Char = %xlate( DIGITS : Chars : Char );
          i = i + 2;
          if i > 52;
            i = 1;
          endif;
        endfor;

        // Return cookie value
        return cookie;

        begsr *pssr;
          printf( 'WWWVALID: Error in setCookie().' + EOL );
          return *blanks;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * getCtlRcd: Get a control record
      *
      *   Accepts:
      *     pCookie      (I) Current cookie value
      *     pCtlRcd      (B) Control record
      *   Returns:
      *     int(10)      (O) 0 if successful, otherwise -1
      *
      *=============================================================================================
     P getCtlRcd       B
     D                 PI            10I 0
     D   pCookie                           Const Like(gCookie)
     D   pCtlRcd                                 Likeds(ctlrcd_t)
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(QUSEC_T) Inz(*Likeds)
     D i               S             10I 0
     D curts           S               Z
     D rtnval          S             10I 0 Inz
      *---------------------------------------------------------------------------------------------
      /free

        // Check for data level incompatibility
        if datalevel <> ThisDataLevel;
          gErrMsg = getErrMsg( gCtlRcd.msgf : 11 );
          exsr *pssr;
        endif;

        // Check if a record exists for the cookie
        i = %lookup( pCookie : cookieval : 1 : ctlrcdmax );
        if i = 0;
          gErrMsg = getErrMsg( gCtlRcd.msgf : 10 );
          exsr return;
        endif;

        // Update parameter with decrypted user profile
        pCtlRcd = ctlrcdval(i);
        if pCtlRcd.UsrPrf <> *blanks;
          reset QUSEC;
          pCtlRcd.UsrPrf = cryptRC4( pCtlRcd.UsrPrf : Key :
                                     DECRYPT_DATA : QUSEC );
          if QUSEC.ErrBytesAvail > 0;
            exsr *pssr;
          endif;
        endif;

        // Check if the session has already ended, and redisplay sign-on
        if pCtlRcd.status = cStatus_Ended;
          gErrMsg = getErrMsg( pCtlRcd.msgf : 7 );
          exsr return;
        endif;

        // Check if an active session has expired, and redisplay sign-on
        if pCtlRcd.status = cStatus_Active;
          curts = %timestamp();
          select;
            // Check for session timeout
            when pCtlRcd.sesstimeout > 0 and
                 %diff(curts:pCtlRcd.init:*seconds) > pCtlRcd.sesstimeout;
              pCtlRcd.status = cStatus_Ended;
              pCtlRcd.usrprf = *blanks;
              pCtlRcd.passwd = *blanks;
              gErrMsg = getErrMsg( pCtlRcd.msgf : 3 );
              ctlrcdval(i) = pCtlRcd; // Update control record
            // Check for page timeout
            when pCtlRcd.pagetimeout > 0 and
                 %diff(curts:pCtlRcd.last:*seconds) > pCtlRcd.pagetimeout;
              pCtlRcd.status = cStatus_Timed;
              gErrMsg = getErrMsg( pCtlRcd.msgf : 8 );
          endsl;
        endif;

        exsr return;

        // return: Return to the calling procedure
        begsr return;
          return rtnval;
        endsr;

        // *PSSR: Error-handling subroutine
        begsr *pssr;
          if gErrMsg = *blanks;
            gErrMsg = getErrMsg( gCtlRcd.msgf : 10 );
          endif;
          printf( 'WWWVALID: Error in getCtlRcd().' + EOL );
          rtnval = -1;
          exsr return;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * setCtlRcd: Set a control record.
      *
      *   Accepts:
      *     pCookie      (B) Current cookie value
      *     pCtlRcd      (I) Control record
      *   Returns:
      *     int(10)      (O) 0 if success, otherwise -1
      *
      *=============================================================================================
     P setCtlRcd       B
     D                 PI            10I 0
     D   pCookie                                 Like(gCookie)
     D   pCtlRcd                           Const Likeds(ctlrcd_t)
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(QUSEC_t) Inz(*Likeds)
     D rtnval          S             10I 0
     D ctlrcd          DS                  Likeds(ctlrcd_t)
     D wCookie         S                   Like(gCookie)
     D wSessionId      S                   like(www_sessionid_t)
     D curts           S               Z
     D i               S             10I 0
     D j               S             10I 0
     D TS              DS                  Likeds(Timestamp_Char_t)
      *---------------------------------------------------------------------------------------------
      /free

        rtnval = 0;
        clear wCookie;
        curts = %timestamp();

        // Acquire lock on control user space data
        if not lockslw( UsrSpcPtr : LOCKSL_EXCLRD : 10 );
          exsr *pssr;
        endif;

        // Check whether to update existing control record
        if pCookie <> *blanks;
          i = %lookup( pCookie : cookieval : 1 : ctlrcdmax );
          if i > 0;
            ctlrcd = ctlrcdval(i);
            exsr createRecord;
          endif;
        endif;
        // Re-use an empty or expired array entry for new control record
        for i = 1 to ctlrcdmax;
          ctlrcd = ctlrcdval(i);
          // Check for an expired (session timed-out) record
          if cookieval(i) = *blanks or
             ctlrcd.status = cStatus_Ended or
             ( ctlrcd.sesstimeout > 0 and
               %diff(curts:ctlrcd.init:*seconds) > ctlrcd.sesstimeout );
            clear cookieval(i);
            ctlrcd = pCtlRcd;
            exsr createRecord;
          endif;
        endfor;
        // Create new control record
        if ctlrcdmax < %elem( ctlrcdarr );
          ctlrcdmax = ctlrcdmax + 1;
          i = ctlrcdmax;
          ctlrcd = pCtlRcd;
          exsr createRecord;
        endif;

        // If we've reached this point then an error has occurred
        exsr *pssr;

        // createRecord: Create a record in the array
        begsr createRecord;
          // Create a new cookie (in a loop to ensure it's unique)
          if pCtlRcd.status = cStatus_Ended or
             cookieval(i) = *blanks or ctlrcd.cookieopt = 1;
            dou %lookup( wCookie : cookieval : 1 : ctlrcdmax ) = 0;
              wCookie = setCookie( curts );
            enddo;
            cookieval(i) = wCookie;
            // Create a new session identifier
            if pCtlRcd.status = cStatus_Ended or
               ctlrcd.sessionid = *blanks;
              ctlrcd.init = curts;
              ctlrcd.swapped = *off;
              TS = %char( curts );
              j = TS.M1_S + TS.S2_S + TS.MS3_S;
              if j = 0 or j > ( %len( wCookie ) - 16 );
                j = 17;
              endif;
              wSessionId = %subst( wCookie : j );
              dou %lookup( wSessionId : ssnidval : 1 : ctlrcdmax ) = 0;
                reset qusec;
                wSessionId = cryptRC4( wSessionId : Key :
                                       ENCRYPT_DATA : qusec );
                if qusec.ErrBytesAvail > 0;
                  exsr *pssr;
                endif;
              enddo;
              ctlrcd.sessionid = wSessionId;
            endif;
          endif;
          // Set the user profile, password and other fields
          select;
            // Update record to show that we're waiting for a signon
            when pCtlRcd.status <> cStatus_Active;
              ctlrcd.status = cStatus_Signon;
            // Update record with new credentials
            when pCtlRcd.status = cStatus_Active and
                 ctlrcd.status <> cStatus_Active;
              ctlrcd.status = cStatus_Active;
              ctlrcd.sysusrprf = pCtlRcd.sysusrprf;
              reset qusec;
              ctlrcd.usrprf = cryptRC4( pCtlRcd.usrprf : Key :
                                        ENCRYPT_DATA : qusec );
              if qusec.ErrBytesAvail > 0;
                exsr *pssr;
              endif;
              reset qusec;
              ctlrcd.passwd = cryptRC4( pCtlRcd.passwd : Key :
                                        ENCRYPT_DATA : qusec );
              if qusec.ErrBytesAvail > 0;
                exsr *pssr;
              endif;
            other;
          endsl;
          ctlrcd.last = curts;
          ctlrcdval(i) = ctlrcd;
          pCookie = cookieval(i);
          exsr return;
        endsr;

        // return: Return to caller
        begsr return;
          // Release lock on control user space data
          unlockslw( UsrSpcPtr : LOCKSL_EXCLRD );
          gSessionId = ctlrcd.sessionid;
          return rtnval;
        endsr;

        // *PSSR: Error-handling subroutine
        begsr *pssr;
          unlockslw( UsrSpcPtr : LOCKSL_EXCLRD );
          printf( 'WWWVALID: Error in setCtlRcd().' + EOL );
          clear pCookie;
          rtnval = -1;
          exsr return;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * swapUsrPrf(): Swap the user profile.
      *
      *   Accepts:
      *     pSessionId   (I) Session identifier
      *     pSwapType    (I) Swap to or from
      *   Returns:
      *     rc           (O) 0 if successful, otherwise -1;
      *
      *=============================================================================================
     P swapUsrPrf      B
     D                 PI            10I 0
     D   pSessionIdx                 10I 0 Const
     D   pSwapType                   10I 0 Const
      *---------------------------------------------------------------------------------------------
     D i               S             10I 0 Inz
     D ctlrcd          DS                  Likeds(ctlrcd_t)
     D PrfHandleOrig   S                   Like(PrfHandle_t) Inz Static
     D PrfHandle       S                   Like(PrfHandle_t) Inz Static
     D QUSEC           DS                  Likeds(qusec_t) Inz(*Likeds)
     D wUsrPrf         S                   Like(ctlrcd_t.usrprf)
     D wPasswd         S                   Like(ctlrcd_t.passwd)
      *---------------------------------------------------------------------------------------------
      /free

        // Get a profile handle for the original profile (once only)
        if PrfHandleOrig = *blanks;
          reset QUSEC;
          qsygetph( '*CURRENT' : *blanks : PrfHandleOrig : QUSEC );
          if QUSEC.ErrBytesAvail > 0;
            exsr *pssr;
          endif;
        endif;

        ctlrcd = ctlrcdval(pSessionIdx);
        select;
          // Not a valid user profile
          when ctlrcd.sysusrprf = *off;
            exsr *pssr;
          // Not currently swapped, so swap to user profile
          when ctlrcd.swapped = *off and pSwapType = cSwapToNew;
            // Decrypt the user profile into a temporary variable
            reset QUSEC;
            wUsrPrf = cryptRC4( ctlrcd.usrprf : Key :
                                DECRYPT_DATA : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
            // Decrypt the password into a temporary variable
            reset QUSEC;
            wPasswd = cryptRC4( ctlrcd.passwd : Key :
                                DECRYPT_DATA : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
            // Get a profile handle for the user profile
            reset QUSEC;
            qsygetph( wUsrPrf :
                      wPasswd :
                      PrfHandle :
                      QUSEC :
                      passwdlen :
                      0 );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
            // Clear the decrypted variables
            clear wUsrPrf;
            clear wPasswd;
            // Swap to the specified user profile
            reset QUSEC;
            qwtsetp( PrfHandle : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
            ctlrcd.swapped = *on;
          // Already swapped, so swap back to original
          when ctlrcd.swapped = *on and pSwapType = cSwapToOrig;
            // Swap back to the original user profile
            reset QUSEC;
            qwtsetp( PrfHandleOrig : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
            // Release the profile handle for the specified user profile
            reset QUSEC;
            qsyrlsph( PrfHandle : QUSEC );
            if QUSEC.ErrBytesAvail > 0;
              exsr *pssr;
            endif;
            ctlrcd.swapped = *off;
          // Ignore any other option
          other;
        endsl;
        ctlrcdval(pSessionIdx) = ctlrcd;

        return 0;

        begsr *pssr;
          clear wPasswd;
          printf( 'WWWVALID: Error in swapUsrPrf().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * writeOutput(): Write a line to STDOUT
      *=============================================================================================
     P writeOutput     B
     D                 PI            10I 0
     D   pBuffer                           Const Like(Buffer_t)
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
          printf( 'WWWVALID: Error in writeOutput().' + EOL );
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * getErrMsg(): Retrieve an error message
      *=============================================================================================
     P getErrMsg       B
     D                 PI           100A   Varying
     D   pMsgf                       10A   Const
     D   pErrMsgIdx                  10I 0 Const
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(qusec_t) Inz(*Likeds)
     D qMsgf           DS                  Likeds(qObj_t)
     D RTVM0100        DS         65535     Qualified
     D   BytesReturn                 10I 0
     D   BytesAvail                  10I 0
     D   MsgRtnLen                   10I 0
     D   MsgAvlLen                   10I 0
     D   HlpRtnLen                   10I 0
     D   HlpAvlLen                   10I 0
      *---------------------------------------------------------------------------------------------
      /free

        if pErrMsgIdx < 1 or pErrMsgIdx > %elem( errmsgarr );
          exsr *pssr;
        endif;

        // Retrieve the message from the specified message file.
        // If not found, use the hard-coded text in the errmsg array.
        qMsgf.Obj = pMsgf;
        qMsgf.Lib = PgmSDS.PgmLib;
        if qMsgf.Obj = *blanks;
          qMsgf.Obj = wwwvalid_name;
        endif;

        clear RTVM0100;
        reset QUSEC;
        qmhrtvm( RTVM0100 : %size( RTVM0100 ) : 'RTVM0100' :
                 errmsgid(pErrMsgIdx) :  qMsgf : *blanks : 0 :
                 '*YES' : '*NO' : QUSEC );
        if QUSEC.ErrBytesAvail = 0 and
            %subst( RTVM0100 : 25 : RTVM0100.MsgRtnLen ) <> *blanks;
          return %subst( RTVM0100 : 25 : RTVM0100.MsgRtnLen );
        else;
          printf( 'WWWVALID: Message ID %s not found in message file %s' +
                  EOL : errmsgid(pErrMsgIdx) : qMsgf.Obj );
          return errmsgtxt(pErrMsgIdx);
        endif;

        // *PSSR: Error-handling subroutine
        begsr *pssr;
          printf( 'WWWVALID: Error in getErrMsg().' + EOL );
          return '';
        endsr;

      /end-free
     P                 E
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
      * cvtcgistr(): Converts a CGI string.
      *=============================================================================================
     P cvtcgistr       B
     D                 PI          8192A   Varying
     D   p_cgistr                  8192A   Varying Const
      *---------------------------------------------------------------------------------------------
     D pos             S             10I 0
     D char2           S              2A
     D char1           S              1A
     D cgistr          S           8192A   Inz Varying
     D from            C                   x'000102030405060708090A0B0C0D1011-
     D                                       12131415161718191A1B1C1D1E1F2021-
     D                                       22232425262728292A2B2C2D2E2F3031-
     D                                       32333435363738393A3B3C3D3E3F'
     D to              C                   x'40404040404040404040404040404040-
     D                                       40404040404040404040404040404040-
     D                                       40404040404040404040404040404040-
     D                                       4040404040404040404040404040'
      *---------------------------------------------------------------------------------------------
      /free

        // Convert '+' signs to blanks
        cgistr = %xlate( '+' : ' ' : p_cgistr );

        // Convert escaped octets to characters
        pos = %scan( '%' : cgistr );
        dow pos > 0;
          char2 = %subst( cgistr : pos + 1 : 2 );
          cvtch( %addr( char1 ) : %addr( char2 ) : 2 );
          cgistr = %replace( char1 : cgistr : pos : 3 );
          if pos = %len( cgistr );
            leave;
          endif;
          pos = %scan( '%' : cgistr : pos + 1 );
        enddo;

        // Convert control characters to blanks
        cgistr = %xlate( from : to : cgistr );

        return cgistr;

      /end-free
     P                 E
      *=====================================================================
      * splitString(): Parse a string into its constituent words
      *=====================================================================
     P splitString     B
     D                 PI            10I 0
     D   string                   65535A   Const Varying Options(*Varsize)
     D   p_wordarray                             Likeds(wordarray_t)
      *---------------------------------------------------------------------
     D w               S            128A   Varying
     D c               S              1A
     D q               S              1A
     D quoted          S               N
     D l               S             10I 0
     D p               S             10I 0
      *---------------------------------------------------------------------
      /free

        q = *blanks;
        quoted = *off;
        clear p_wordarray;
        l = %len( %trimr( string ) );

        for p = 1 to l;
          c = %subst( string : p : 1 );
          select;
            when ( c = '''' or c = '"' ) and q = *blanks;
              q = c;
              quoted = *on;
            when c = q and q <> *blanks;
              q = *blanks;
              quoted = *off;
            when c = ' ' and quoted = *off;
              if %len( w ) > 0;
                p_wordarray.nbrelm +=1;
                p_wordarray.word(p_wordarray.nbrelm) = w;
                clear w;
              endif;
            other;
              w += c;
          endsl;
        endfor;
        if w <> *blanks;
          p_wordarray.nbrelm +=1;
          p_wordarray.word(p_wordarray.nbrelm) = w;
        endif;

        return 0;

        begsr *pssr;
          return -1;
        endsr;

      /end-free
     P                 E
      *=============================================================================================
      * cryptRC4(): Encrypt data using RC4 algorithm
      *=============================================================================================
     P cryptRC4        B
     D                 PI         65535A   Varying
     D   Data                     65535A   Const Varying Options(*Varsize)
     D   Password                   256A   Const Varying Options(*Varsize)
     D   Action                      10A   Const
     D   ApiError                          Likeds(QUSEC_T) Options(*Nopass)
      *---------------------------------------------------------------------------------------------
     D QUSEC           DS                  Likeds(QUSEC_t) Inz(*Likeds)
     D ALGD0300        DS                  Likeds(ALGD0300_t)
     D KEYD0200        DS                  Likeds(KEYD0200_t)
     D OutData         S          65535A
     D OutDataLen      S             10I 0
      *---------------------------------------------------------------------------------------------
      /free

        // Set algorithm definition
        clear ALGD0300;
        ALGD0300.Algorithm = STREAM_CIPHER_RC4;

        // Set key definition
        clear KEYD0200;
        KEYD0200.KeyType = KEY_TYPE_RC4;
        KEYD0200.KeyLen  = %len( Password );
        KEYD0200.KeyFmt  = *off;
        KEYD0200.Key     = Password;

        reset QUSEC;
        if Action = ENCRYPT_DATA;
          Qc3EncryptData( Data : %len( Data ) : 'DATA0100':
                          ALGD0300 : 'ALGD0300' :
                          KEYD0200 : 'KEYD0200' :
                          CRYPT_SRV_ANY : *blanks :
                          OutData :  %size( OutData ) : OutDataLen :
                          QUSEC );
        else;
          Qc3DecryptData( Data : %len( Data ) :
                          ALGD0300 : 'ALGD0300' :
                          KEYD0200 : 'KEYD0200' :
                          CRYPT_SRV_ANY : *blanks :
                          OutData :  %size( OutData ) : OutDataLen :
                          QUSEC );
        endif;
        if QUSEC.ErrBytesAvail > 0;
          exsr *pssr;
        endif;

        return %subst( OutData : 1 : OutDataLen );

        begsr *pssr;
          printf( 'WWWVALID: Error in cryptRC4().' + EOL );
          return '';
        endsr;

      /end-free
     P                 E
      *=============================================================================================
** CTDATA gErrMsg
WWW0001 Error in Web Access User Validator.
WWW0002 Invalid user ID.
WWW0003 Session has timed out. Sign in to start a new session.
WWW0004 User ID not specified.
WWW0005 Password not specified.
WWW0006 Invalid credentials.
WWW0007 Session has ended. Sign in to start a new session.
WWW0008 Page has timed out. Sign in to reconnect to your session.
WWW0009 This session was started by a different user.
WWW0010 Session not found.
WWW0011 Data level incompatibility.
