/******************************************************************************
* Copyright (c) 2004, 2015  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html

******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCSystem.cc
//  Description:        TCC Useful Functions: System Functions
//  Rev:                R22B
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
