/******************************************************************************
* Copyright (c) 2004, 2015  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html

******************************************************************************/
///////////////////////////////////////////////////////////////////////////////
//
//  File:               TCCRegexp_Functions.ttcn
//  Description:        TCC Useful Functions: Regexp Functions
//  Rev:                R22B
//  Prodnr:             CNL 113 472
//  Updated:            2009-11-20
//  Contact:            http://ttcn.ericsson.se
//
///////////////////////////////////////////////////////////////////////////////

#include "TCCRegexp_Functions.hh"
#include <pcre.h>

namespace TCCRegexp__Functions{
  CHARSTRING f__pcre__regexp(const CHARSTRING& instr,
          const CHARSTRING& expression, const INTEGER& groupno ){
    
    pcre *re;
    const char *error_text;
    int erroroffset;
    re = pcre_compile(expression,0,&error_text,&erroroffset,NULL);
    if(re == NULL){
      TTCN_error("Compilation of the pcre regexp failled at position %d."
                 "Reason: \"%s\"",erroroffset,error_text);
      return "";
    }
    int rc;
    int max_groupno;
    
    rc=pcre_fullinfo(re,NULL,PCRE_INFO_CAPTURECOUNT,&max_groupno);
    if(rc!=0){
      TTCN_error("pcre_fullinfo failed. Error code: %d",rc);
    }
    max_groupno=(max_groupno+1)*3;
    int *ovector = (int*)Malloc(max_groupno*sizeof(int));
    rc = pcre_exec(re,NULL,instr,instr.lengthof(),0,0,ovector,max_groupno);
    
    CHARSTRING ret_val;
    if(rc<=groupno){ ret_val="";}
    else if( ovector[groupno*2] == -1 ) { ret_val="";}
    else {
      ret_val=substr(instr, ovector[groupno*2], ovector[(groupno*2)+1]- ovector[groupno*2]);
    }
    Free(ovector);
    return ret_val;
  }

  charstring__list f__pcre__regexp__list(const CHARSTRING& instr,
          const CHARSTRING& expression){
    
    pcre *re;
    const char *error_text;
    int erroroffset;
    re = pcre_compile(expression,0,&error_text,&erroroffset,NULL);
    if(re == NULL){
      TTCN_error("Compilation of the pcre regexp failled at position %d."
                 "Reason: \"%s\"",erroroffset,error_text);
      return NULL_VALUE;
    }
    int rc;
    int max_groupno;
    
    rc=pcre_fullinfo(re,NULL,PCRE_INFO_CAPTURECOUNT,&max_groupno);
    if(rc!=0){
      TTCN_error("pcre_fullinfo failed. Error code: %d",rc);
    }
    int ovecsivze=(max_groupno+1)*3;
    int *ovector = (int*)Malloc(ovecsivze*sizeof(int));
    rc = pcre_exec(re,NULL,instr,instr.lengthof(),0,0,ovector,ovecsivze);
    
    charstring__list ret_val;
    for(int a=0;a<=max_groupno;a++){
      if(rc<=a){ ret_val[a]="";}
      else if( ovector[a*2] == -1 ) { ret_val[a]="";}
      else {
        ret_val[a]=substr(instr, ovector[a*2], ovector[(a*2)+1]- ovector[a*2]);
      }
    }
    Free(ovector);
    return ret_val;
  }

}
