#pragma once
/******************************************************************************
       Module: dqr_interface.hpp
     Engineer: Arjun Suresh
  Description: Header for Sifive Trace Decoder Interface Class
  Date         Initials    Description
  3-Nov-2022   AS          Initial
******************************************************************************/
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>

#include "dqr.hpp"

using namespace std;

// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the DLL_EXPORT
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// DLLEXPORTEDAPI functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DLL_EXPORT
    #ifdef __linux__
        #define DLLEXPORTEDAPI __attribute__ ((visibility ("default")))
    #else
        #define DLLEXPORTEDAPI __declspec(dllexport)
    #endif
#else
    #ifdef __linux__
        #define DLLEXPORTEDAPI __attribute__ ((visibility ("default")))
    #else
        #define DLLEXPORTEDAPI __declspec(dllimport)
    #endif
#endif

// Interface Class that provides access to the decoder related
// functionality
class DLLEXPORTEDAPI SifiveDecoderInterface
{
private:
	char *base_name = nullptr;
	char *sf_name = nullptr;
	char *ca_name = nullptr;
	char *pf_name = nullptr;
	char *vf_name = nullptr;
	char buff[128];
	int buff_index = 0;
	bool usage_flag = false;
	bool version_flag = false;
	bool src_flag = true;
	bool file_flag = true;
	bool dasm_flag = true;
	bool trace_flag = false;
	bool func_flag = true;
	int tssize = 40;
	uint32_t freq = 0;
	char *strip_flag = nullptr;
	int  numAddrBits = 0;
	uint32_t addrDispFlags = 0;
	int srcbits = 0;
	int analytics_detail = 1;
	int itcPrintOpts = TraceDqr::ITC_OPT_NLS;
	int itcPrintChannel = 0;
	bool showCallsReturns = true;
	bool showBranches = true;
	TraceDqr::pathType pt = TraceDqr::PATH_TO_UNIX;
	int archSize = 32;
	int msgLevel = 2;
	TraceDqr::CATraceType caType = TraceDqr::CATRACE_NONE;
	TraceDqr::TraceType traceType = TraceDqr::TRACETYPE_BTM;
	char *cutPath = nullptr;
	char *newRoot = nullptr;
	bool ctf_flag = false;
public:
	// API to decode the rtd file
	virtual int Decode(char* tf_name = nullptr, char* ef_name = nullptr, char* od_name = nullptr, char* out_file = nullptr);
	// Class destructor
	virtual ~SifiveDecoderInterface() {}
};

// Exported C API function that returns the pointer to the Sifive decoder class instance
extern "C" DLLEXPORTEDAPI SifiveDecoderInterface* GetSifiveDecoderInterface();
