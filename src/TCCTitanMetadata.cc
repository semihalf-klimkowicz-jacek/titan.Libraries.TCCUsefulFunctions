/******************************************************************************
* Copyright (c) 2004, 2015  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html

******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCTitanMetadata.cc
//  Description:        TCC Useful Functions: TitanMetadata Functions
//  Rev:                R22B
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
