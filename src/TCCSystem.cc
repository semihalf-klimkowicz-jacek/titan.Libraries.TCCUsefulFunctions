///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Copyright Test Competence Center (TCC) ETH 2009                           //
//                                                                           //
// The copyright to the computer  program(s) herein  is the property of TCC. //
// The program(s) may be used and/or copied only with the written permission //
// of TCC or in accordance with  the terms and conditions  stipulated in the //
// agreement/contract under which the program(s) have been supplied          //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCSystem.cc
//  Description:        TCC Useful Functions: System Functions
//  Rev:                R25A
//  Prodnr:             CNL 113 472
//  Updated:            2009-04-10
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////
#include "TCCSystem_Functions.hh"
#include <unistd.h>

namespace TCCSystem__Functions{

///////////////////////////////////////////////////////////////////////////////
//  Function: f_SYS_getpid
// 
//  Purpose:
//    Returns the pid of the process
//
//  Parameters:
//    -
// 
//  Return Value:
//    integer - pid
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
INTEGER f__SYS__getpid(){
  return getpid();
}

}
