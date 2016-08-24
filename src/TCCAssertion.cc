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
//  File:               TCCAssertion.cc
//  Description:        TCC Useful Functions: Assert Functions
//  Rev:                R25A
//  Prodnr:             CNL 113 472
//  Updated:            2007-11-12
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCAssertion_Functions.hh"

namespace TCCAssertion__Functions 
{
  
///////////////////////////////////////////////////////////////////////////////
//  Function: f__assert
// 
//  Purpose:
//    Implement TTCN assertion. 
//
//  Parameters:
//    pl__assertMessage - *in* *charstring* - assertion message
//    pl__predicate - *in* *boolean* - boolean predicate
// 
//  Return Value:
//    -
//
//  Errors:
//    - 
// 
//  Detailed description:
//    At the point of this function call, the assertion predicate must be true,
//    else assertion fails that results in a dynamic test case error
//    To use assertion optimized build shall be switched on with switch -O2 and
//    NDEBUG shall not be defined
// 
///////////////////////////////////////////////////////////////////////////////
  void f__assert(const CHARSTRING& pl__assertMessage, const BOOLEAN& pl__predicate)
  {
    #ifdef NDEBUG
    #else
    if (!(pl__predicate)) {
      TTCN_error("Assertion failed: %s!",(const char*)pl__assertMessage);  
    }
    #endif
  }
}
