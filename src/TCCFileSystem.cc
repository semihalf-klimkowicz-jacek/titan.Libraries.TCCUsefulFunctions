///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Copyright Test Competence Center (TCC) ETH 2011                           //
//                                                                           //
// The copyright to the computer  program(s) herein  is the property of TCC. //
// The program(s) may be used and/or copied only with the written permission //
// of TCC or in accordance with  the terms and conditions  stipulated in the //
// agreement/contract under which the program(s) have been supplied          //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCFileSystem.cc
//  Description:        TCC Useful Functions: FileSystem Functions
//  Rev:                R25A
//  Prodnr:             CNL 113 472
//  Updated:            2011-07-14
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCFileSystem_Functions.hh"
#include <sys/statvfs.h>

namespace TCCFileSystem__Functions
{

INTEGER f__FS__bsize(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER (buffer.f_bsize);
  }
  else{return INTEGER (-1);}
}

INTEGER f__FS__block(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER(buffer.f_blocks);
  }
  else{return INTEGER (-1);}
}

INTEGER f__FS__bfree(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER(buffer.f_bavail);
  }
  else{return INTEGER (-1);}
}


INTEGER f__FS__dspacerate(const CHARSTRING& filename ) {
  struct statvfs buffer ;
  if(statvfs( (const char *)filename, &buffer )==0) {
    return INTEGER(buffer.f_bavail*100/buffer.f_blocks);
  }
  else{return INTEGER (-1);}
}

}
