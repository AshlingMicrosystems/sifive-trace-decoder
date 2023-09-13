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

// Sifive Trace Decoder Error Types
typedef enum
{
    SIFIVE_TRACE_DECODER_OK,
	SIFIVE_TRACE_DECODER_FILE_NOT_FOUND,
	SIFIVE_TRACE_DECODER_CANNOT_OPEN_FILE,
	SIFIVE_TRACE_DECODER_INPUT_ARG_NULL,
	SIFIVE_TRACE_DECODER_ELF_NULL,
	SIFIVE_TRACE_DECODER_MEM_CREATE_ERR,
	SIFIVE_TRACE_DECODER_SIM_STATUS_ERROR,
	SIFIVE_TRACE_DECODER_VCD_STATUS_ERROR,
	SIFIVE_TRACE_DECODER_TRACE_STATUS_ERROR,
    SIFIVE_TRACE_DECODER_ERR
} TySifiveTraceDecodeError;

// Sifive Trace Decoder Analytics Log Level
typedef enum
{
	LEVEL_0 = 0,
	LEVEL_1 = 1,
	LEVEL_2 = 2,
	LEVEL_3 = 3
} TySifiveTraceMsgLogLevel;

// Sifive Trace Decoder Analytics Log Level
typedef enum
{
	DISABLE = 0,
	SORT_SYSTEM_TOTALS = 1,
	DISPLAY_ANALYTICS_BY_CORE = 2
} TySifiveTraceAnalyticsLogLevel;

// Sifive Trace Decoder Target Arch Size
typedef enum
{
	ARCH_GET_FROM_ELF = 0,
	ARCH_32_BIT = 32,
	ARCH_64_BIT = 64
} TySifiveTraceTargetArchSize;

// Decoder Config Structure
struct TDecoderConfig
{
	char *trace_filepath = nullptr;
	char *elf_filepath = nullptr;;
	char *objdump_path = nullptr;;
	char *strip_flag = nullptr;
	char *cutPath = nullptr;
	char *newRoot = nullptr;
	bool display_src_info = true;
	bool display_file_info = true;
	bool display_dissassembly_info = true;
	bool display_trace_msg = false;
	bool display_function_info = true;
	bool display_call_return_info = true;
	bool display_branches_info = true;
	bool display_raw_message_info = false;
	bool enable_common_trace_format = false;
	bool enable_profiling_format = false;
	uint32_t analytics_detail_log_level = TySifiveTraceAnalyticsLogLevel::DISABLE;
	TraceDqr::CATraceType cycle_accuracte_type = TraceDqr::CATRACE_NONE;
	TraceDqr::TraceType trace_type = TraceDqr::TRACETYPE_BTM;
	uint32_t numAddrBits = 0;
	uint32_t addrDispFlags = 0;
	uint32_t archSize = 0;
	uint32_t trace_msg_log_level = 1;
	uint32_t timestamp_counter_size_in_bits = 40;
	uint32_t timestamp_tick_clk_freq_hz = 0;
	uint32_t src_field_size_bits = 0;
	TraceDqr::ITCOptions itc_print_options = TraceDqr::ITC_OPT_NLS;
	uint32_t itc_print_channel = 0;
};

// Interface Class that provides access to the decoder related
// functionality
class DLLEXPORTEDAPI SifiveDecoderInterface
{
private:
	char* tf_name = nullptr; // Trace File
	char* ef_name = nullptr; // ELF File
	char* od_name = nullptr; // Objdump Path
	char *sf_name = nullptr; // Simulator File
	char *ca_name = nullptr; // Cycle Accurate Count File
	char *pf_name = nullptr; // Properties File
	char *vf_name = nullptr; // VF File
	char *strip_flag = nullptr; // Flag to strip path
	char *cutPath = nullptr; // String to cut from path
	char *newRoot = nullptr; // String to add to path after cutting cutPath string

	// Decoder Output Info Enable/Disable Flags
	bool src_flag = true;	      // Output Source Info
	bool file_flag = true;	      // Output File Info
	bool dasm_flag = true;	      // Output Dissassembly Info
	bool trace_flag = false; 	  // Output Trace Messages
	bool func_flag = true;   	  // Output Function Info
	bool showCallsReturns = true; // Output Call Return Info
	bool showBranches = true;     // Output Branch Info
	bool ctf_flag = false;		  // Output Trace as Common Trace Format (Limited Support)
	bool profile_flag = false;	  // Output PC value with timestamp only
	int numAddrBits = 0;		  // Display Address as n bits
	uint32_t addrDispFlags = 0;   // Address display formatting options
	TraceDqr::pathType pt = TraceDqr::PATH_TO_UNIX; // Display format for path info
	int analytics_detail = TySifiveTraceAnalyticsLogLevel::DISABLE;	// Output Analytics
	int msgLevel = TySifiveTraceMsgLogLevel::LEVEL_1;			    // Nexus Trace Msg logging level

	// ITC Print Settings
	int itcPrintOpts = TraceDqr::ITC_OPT_NLS; // ITC Print Options
	int itcPrintChannel = 0;                  // ITC Print Channel

	// Timestamp Info Settings
	int tssize = 40;	// Timestamp counter size in bits
	uint32_t freq = 0;	// Timestamp clock frequency

	// Cycle Accurate count and trace type settings
	TraceDqr::CATraceType caType = TraceDqr::CATRACE_NONE;    // Cycle Accurate Count Type
	TraceDqr::TraceType traceType = TraceDqr::TRACETYPE_BTM;  // Trace Type

	// Arch Size and Src bit Settings
	int srcbits = 0;												// Size of Source bit fields in bits (used for multicore tracing)
	int archSize = TySifiveTraceTargetArchSize::ARCH_GET_FROM_ELF;	// Target Architecture Size (32/64)
public:
	virtual TySifiveTraceDecodeError Configure(const TDecoderConfig& config);
	// API to decode the rtd file
	virtual TySifiveTraceDecodeError Decode(char* out_file);
	// Class destructor
	virtual ~SifiveDecoderInterface() {}
};

// Function pointer typedef
typedef SifiveDecoderInterface* (*fpGetSifiveDecoderInterface)();

// Exported C API function that returns the pointer to the Sifive decoder class instance
extern "C" DLLEXPORTEDAPI SifiveDecoderInterface* GetSifiveDecoderInterface();
