///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Copyright Test Competence Center (TCC) ETH 2008                           //
//                                                                           //
// The copyright to the computer  program(s) herein  is the property of TCC. //
// The program(s) may be used and/or copied only with the written permission //
// of TCC or in accordance with  the terms and conditions  stipulated in the //
// agreement/contract under which the program(s) have been supplied          //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCEnv.cc
//  Description:        TCC Useful Functions: Environment Handling Functions.
//  Rev:                R25A
//  Prodnr:             CNL 113 472
//  Updated:            2008-01-18
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include "memory.h"
#include <string.h>
#include "TCCEnv_Functions.hh"

namespace TCCEnv__Functions {

///////////////////////////////////////////////////////////////////////////////
//  Function: f__GetEnv
// 
//  Purpose:
//    Return the environment variable specified via p_env_name
//
//  Parameters:
//    p__env__name - *in* *charstring* - name of the environment variable
// 
//  Return Value:
//    charstring - value of the environment variable
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
CHARSTRING f__GetEnv(const CHARSTRING& p__env__name)
{
  const char *val = getenv((const char *)p__env__name);
  if(!val)return CHARSTRING("");
  else return CHARSTRING(val);
}

///////////////////////////////////////////////////////////////////////////////
//  Function: f__PutEnv
// 
//  Purpose:
//    Set the environment variable p_env_name to p_env_value.
//
//  Parameters:
//    p__env__name - *in* *charstring* - name of the environment variable
//    p__env__value - *in* *charstring* - value of the environment variable
// 
//  Return Value:
//    boolean - true if set of environment variable was successful, false else
//
//  Errors:
//    - 
// 
//  Detailed description:
//    -
// 
///////////////////////////////////////////////////////////////////////////////
BOOLEAN f__PutEnv(const CHARSTRING& p__env__name,
  const CHARSTRING& p__env__value)
{
  if(p__env__name.lengthof()) {
    char *env = 
        mprintf("%s=%s", (const char*)p__env__name, (const char*)p__env__value);    
        
    int result = putenv(env);
    
    if(result) {
      TTCN_warning("putenv failed with error code %d.", result);
      return BOOLEAN(FALSE);
    }
  }
  return BOOLEAN(TRUE);
}

/*INTEGER f__UnsetEnv(const CHARSTRING& p__env__name)
{
  return INTEGER(unsetenv((const char *)p__env__name));
}*/

}//namespace
