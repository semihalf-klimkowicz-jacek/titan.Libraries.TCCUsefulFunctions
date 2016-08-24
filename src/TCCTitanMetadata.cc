///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Copyright Test Competence Center (TCC) ETH 2007                           //
//                                                                           //
// The copyright to the computer  program(s) herein  is the property of TCC. //
// The program(s) may be used and/or copied only with the written permission //
// of TCC or in accordance with  the terms and conditions  stipulated in the //
// agreement/contract under which the program(s) have been supplied          //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCTitanMetadata.cc
//  Description:        TCC Useful Functions: TitanMetadata Functions
//  Rev:                R25A
//  Prodnr:             CNL 113 472
//  Updated:            2007-10-26
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCTitanMetadata_Functions.hh"

namespace TCCTitanMetadata__Functions {

static CHARSTRING compilationtime = __DATE__" " __TIME__;

///////////////////////////////////////////////////////////////////////////////
//  Function: f__compilationTime
// 
//  Purpose:
//    Return the compilation time of module
//
//  Parameters:
//    -
// 
//  Return Value:
//    charstring - compilation time
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
CHARSTRING f__compilationTime()
{
  return compilationtime;
}

} // end of namespace
