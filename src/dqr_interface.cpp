/******************************************************************************
       Module: dqr_interface.cpp
     Engineer: Arjun Suresh
  Description: Implementation for Sifive Trace Decoder Interface
  Date         Initials    Description
  3-Nov-2022   AS          Initial
******************************************************************************/
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <cstdint>

#include "dqr_interface.hpp"

/****************************************************************************
     Function: stripPath
     Engineer: Arjun Suresh
        Input: prefix - The prefix string to strip from the source path
               srcpath - The full source path
       Output: None
       return: The stripped output path
  Description: Constuctor to Initialize Trace Decoder Class
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
static const char *stripPath(const char *prefix, const char *srcpath)
{
	if (prefix == nullptr) {
		return srcpath;
	}

	if (srcpath == nullptr) {
		return nullptr;
	}

	const char *s = srcpath;

	for (;;) {
		if (*prefix == 0) {
			return s;
		}

		if (tolower(*prefix) == tolower(*s)) {
			prefix += 1;
			s += 1;
		}
		else if (*prefix == '/') {
			if (*s != '\\') {
				return srcpath;
			}
			prefix += 1;
			s += 1;
		}
		else if (*prefix == '\\') {
			if (*s != '/') {
				return srcpath;
			}
			prefix += 1;
			s += 1;
		}
		else {
			return srcpath;
		}
	}

	return nullptr;
}

/****************************************************************************
     Function: Decode
     Engineer: Arjun Suresh
        Input: tf_name - The full path to the encode trace rtd file
               ef_name - The full path to the elf file
               of_name - The full path to riscv objdump
               outfile - The full path to the output file
       Output: None
       return: The stripped output path
  Description: Function that performs the decoding
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
TySifiveTraceDecodeError SifiveDecoderInterface::Decode(char* out_file)
{
	if(out_file == nullptr)
	{
		return SIFIVE_TRACE_DECODER_INPUT_ARG_NULL;
	}

	trace = nullptr;
	sim = nullptr;
	vcd = nullptr;
	fp = nullptr;

	if (sf_name != nullptr) {
		if ( ef_name == nullptr) {
			printf("Error: Simulator requires an ELF file (-e switch)\n");
			CleanUp();
			return SIFIVE_TRACE_DECODER_ELF_NULL;
		}

		sim = new (std::nothrow) Simulator(sf_name,ef_name,od_name);
		if (sim == nullptr) {
			printf("Error: Could not create Simulator object\n");
			CleanUp();
			return SIFIVE_TRACE_DECODER_MEM_CREATE_ERR;
		}

		if (sim->getStatus() != TraceDqr::DQERR_OK) {
			printf("Error: new Simulator(%s,%d) failed\n",sf_name,archSize);
			CleanUp();
			return SIFIVE_TRACE_DECODER_SIM_STATUS_ERROR;
		}

		if (cutPath != nullptr) {
			TraceDqr::DQErr rc;

			rc = sim->subSrcPath(cutPath,newRoot);
			if (rc != TraceDqr::DQERR_OK) {
				printf("Error: Could not set cutPath or newRoot\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_ERR;
			}
		}

		srcbits = 1;
	}
	else if ((vf_name != nullptr) || (traceType == TraceDqr::TRACETYPE_VCD)) {
		if (pf_name != nullptr) {
			vcd = new (std::nothrow) VCD(pf_name);
			if (vcd == nullptr) {
				printf("Error: Could not create VCD object\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_MEM_CREATE_ERR;
			}

			if (vcd->getStatus() != TraceDqr::DQERR_OK) {
				printf("Error: new VCD(%s) failed\n",pf_name);
				CleanUp();
				return SIFIVE_TRACE_DECODER_VCD_STATUS_ERROR;
			}
		}
		else {
			if ( ef_name == nullptr) {
				printf("Error: -vf switch also requires an ELF file (-e switch)\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_ELF_NULL;
			}

			vcd = new (std::nothrow) VCD(vf_name,ef_name,od_name);
			if (vcd == nullptr) {
				printf("Error: Could not create VCD object\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_MEM_CREATE_ERR;
			}

			if (vcd->getStatus() != TraceDqr::DQERR_OK) {
				printf("Error: new VCD(%s,%s,%s) failed\n",vf_name,ef_name,od_name);
				CleanUp();
				return SIFIVE_TRACE_DECODER_VCD_STATUS_ERROR;
			}

			if (cutPath != nullptr) {
				TraceDqr::DQErr rc;

				rc = vcd->subSrcPath(cutPath,newRoot);
				if (rc != TraceDqr::DQERR_OK) {
					printf("Error: Could not set cutPath or newRoot\n");
					CleanUp();
					return SIFIVE_TRACE_DECODER_ERR;
				}
			}
		}

		srcbits = 1;
	}
	else if ((pf_name != nullptr) || (tf_name != nullptr) || (traceType == TraceDqr::TRACETYPE_BTM) || (traceType == TraceDqr::TRACETYPE_HTM)) {
		TraceDqr::DQErr rc;

		if (pf_name != nullptr) {
			// generate error message if anything was set to not-default!

			if (tf_name != nullptr) {
				printf("Error: cannot specify -t flag when -pf is also specified\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_ERR;
			}

			if (ef_name != nullptr) {
				printf("Error: cannot specify -e flag when -pf is also specified\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_ERR;
			}

			trace = new (std::nothrow) Trace(pf_name);

			if (trace == nullptr) {
				printf("Error: Could not create Trace object\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_MEM_CREATE_ERR;
			}

			if (trace->getStatus() != TraceDqr::DQERR_OK) {
				printf("Error: new Trace() failed\n",pf_name);
				CleanUp();
				return SIFIVE_TRACE_DECODER_TRACE_STATUS_ERROR;
			}
		}
		else {
			trace = new (std::nothrow) Trace(tf_name,ef_name,numAddrBits,addrDispFlags,srcbits,od_name,freq);

			if (trace == nullptr) {
				printf("Error: Could not create Trace object\n");
				CleanUp();
				return SIFIVE_TRACE_DECODER_MEM_CREATE_ERR;
			}

			if (trace->getStatus() != TraceDqr::DQERR_OK) {
				printf("Error: new Trace(%s,%s) failed\n",tf_name,ef_name);
				CleanUp();
				return SIFIVE_TRACE_DECODER_TRACE_STATUS_ERROR;
			}

			trace->setTraceType(traceType);

			if (ca_name != nullptr) {
				rc = trace->setCATraceFile(ca_name,caType);
				if (rc != TraceDqr::DQERR_OK) {
					printf("Error: Could not set cycle accurate trace file\n");
					CleanUp();
					return SIFIVE_TRACE_DECODER_ERR;
				}
			}

			trace->setTSSize(tssize);
			trace->setPathType(pt);

			if (cutPath != nullptr) {
				rc = trace->subSrcPath(cutPath,newRoot);
				if (rc != TraceDqr::DQERR_OK) {
					printf("Error: Could not set cutPath or newRoot\n");
					CleanUp();
					return SIFIVE_TRACE_DECODER_ERR;
				}
			}

			// NLS is on by default when the trace object is created. Only
			// set the print options if something has changed

			if (itcPrintOpts != TraceDqr::ITC_OPT_NLS) {
				trace->setITCPrintOptions(itcPrintOpts,4096,itcPrintChannel);
			}

			if (ctf_flag != false) {
				rc = trace->enableCTFConverter(-1,nullptr);
				if (rc != TraceDqr::DQERR_OK) {
					printf("Error: Could not set CTF file\n");
					CleanUp();
					return SIFIVE_TRACE_DECODER_ERR;
				}
			}
		}
	}
	else {
		printf("Error: must specify either simulator file, trace file, SWT trace server, properties file, or base name\n");
		CleanUp();
		return SIFIVE_TRACE_DECODER_ERR;
	}

	TraceDqr::DQErr ec;

	// main loop

//	this shouldn't be next instruction. it should be next because we may not be generating instruction'
//	we may just be dumping raw traces, or we may be dumping traces with addresses or we may be doing
//	dissasembled instruction traces or we may be adding source code
//
//	flags:
//
//		raw trace messages
//		decoded trace message
//		include trace addresses
//		include disassembly
//		include source

	// we want to be able to select the level of output, from minimal (raw trace only) to full (everything)

//	do we select when we create the trace object?
//	does it always generate as much as possible and we jsut print what we want?
//
//	should not print, but should return a string or way to make a string!
//
//	should look at source code display!

	Instruction *instInfo;
	NexusMessage *msgInfo;
	Source *srcInfo;
	char dst[10000];
	int instlevel = 1;
	const char *lastSrcFile = nullptr;
	const char *lastSrcLine = nullptr;
	unsigned int lastSrcLineNum = 0;
	TraceDqr::ADDRESS lastAddress = 0;
	int lastInstSize = 0;
	bool firstPrint = true;
	uint32_t core_mask = 0;
	TraceDqr::TIMESTAMP startTime, endTime;

	msgInfo = nullptr;

	fp = fopen(out_file, "a");
	if(!fp)
	{
		CleanUp();
		return SIFIVE_TRACE_DECODER_CANNOT_OPEN_FILE;
	}

	do {
		if (sim != nullptr) {
			ec = sim->NextInstruction(&instInfo,&srcInfo);
		}
		else if (vcd != nullptr) {
			ec = vcd->NextInstruction(&instInfo,&srcInfo);
		}
		else {
			ec = trace->NextInstruction(&instInfo,&msgInfo,&srcInfo);
		}

		if (ec == TraceDqr::DQERR_OK) {
			if(profile_flag)
			{
				if(trace != nullptr && instInfo != nullptr)
				{
					fprintf(fp, "%llx %llu\n", instInfo->address, instInfo->timestamp);
				}
			}
			if (srcInfo != nullptr) {
				if ((lastSrcFile != srcInfo->sourceFile) || (lastSrcLine != srcInfo->sourceLine) || (lastSrcLineNum != srcInfo->sourceLineNum)) {
					lastSrcFile = srcInfo->sourceFile;
					lastSrcLine = srcInfo->sourceLine;
					lastSrcLineNum = srcInfo->sourceLineNum;

					if (file_flag) {
						if (srcInfo->sourceFile != nullptr) {
							if (firstPrint == false) {
								fprintf(fp, "\n");
							}

							const char *sfp;

							sfp = stripPath(strip_flag,srcInfo->sourceFile);

							if (srcbits > 0) {
								fprintf(fp, "[%d] ",srcInfo->coreId);
							}

							int sfpl = 0;
							int sfl = 0;
							int stripped = 0;

							if (sfp != srcInfo->sourceFile) {
								sfpl = strlen(sfp);
								sfl = strlen(srcInfo->sourceFile);
								stripped = sfl - sfpl;
							}

							if (stripped < srcInfo->cutPathIndex) {
								fprintf(fp, "File: [");

								if (sfp != srcInfo->sourceFile) {
									fprintf(fp, "..");
								}

								for (int i = stripped; i < srcInfo->cutPathIndex; i++) {
									fprintf(fp, "%c",srcInfo->sourceFile[i]);
								}

								fprintf(fp, "]%s:%d\n",&srcInfo->sourceFile[srcInfo->cutPathIndex],srcInfo->sourceLineNum);
							}
							else {
								if (sfp != srcInfo->sourceFile) {
									fprintf(fp, "File: ..%s:%d\n",sfp,srcInfo->sourceLineNum);
								}
								else {
									fprintf(fp, "File: %s:%d\n",sfp,srcInfo->sourceLineNum);
								}
							}

							firstPrint = false;
						}
					}

					if (src_flag) {
						if (srcInfo->sourceLine != nullptr) {
							if (srcbits > 0) {
								fprintf(fp, "[%d] Source: %s\n",srcInfo->coreId,srcInfo->sourceLine);
							}
							else {
								fprintf(fp, "Source: %s\n",srcInfo->sourceLine);
							}

							firstPrint = false;
						}
						else
						{
							fprintf(fp, "\n");
						}
					}
				}
			}

			if (dasm_flag && (instInfo != nullptr)) {
				instInfo->addressToText(dst,sizeof dst,0);

				if (func_flag) {
					if (((instInfo->addressLabel != nullptr) && (instInfo->addressLabelOffset == 0)) || (instInfo->address != (lastAddress + lastInstSize / 8))) {
						if (srcbits > 0) {
							fprintf(fp, "[%d] ",instInfo->coreId);
						}

						if (instInfo->addressLabel != nullptr) {
							fprintf(fp, "<%s",instInfo->addressLabel);
							if (instInfo->addressLabelOffset != 0) {
								fprintf(fp, "+%x",instInfo->addressLabelOffset);
							}
							fprintf(fp, ">\n");
						}
						else {
							fprintf(fp, "label null\n");
						}
					}

					lastAddress = instInfo->address;
					lastInstSize = instInfo->instSize;
				}

				if (srcbits > 0) {
					fprintf(fp, "[%d] ", instInfo->coreId);
				}

				int n;

				if (((vcd != nullptr) || (sim != nullptr) || (ca_name != nullptr)) && (instInfo->timestamp != 0)) {
					n = fprintf(fp, "t:%d ",instInfo->timestamp);

					if (instInfo->caFlags & (TraceDqr::CAFLAG_PIPE0 | TraceDqr::CAFLAG_PIPE1)) {
						if (instInfo->caFlags & TraceDqr::CAFLAG_PIPE0) {
							n += fprintf(fp, "[0:%d",instInfo->pipeCycles);
						}
						else if (instInfo->caFlags & TraceDqr::CAFLAG_PIPE1) {
							n += fprintf(fp, "[1:%d",instInfo->pipeCycles);
						}

						if (instInfo->caFlags & TraceDqr::CAFLAG_VSTART) {
							n += fprintf(fp, "(%d)-%d(%dA,%dL,%dS)",instInfo->qDepth,instInfo->VIStartCycles,instInfo->arithInProcess,instInfo->loadInProcess,instInfo->storeInProcess);														}

						if (instInfo->caFlags & TraceDqr::CAFLAG_VARITH) {
							n += fprintf(fp, "-%dA",instInfo->VIFinishCycles);
						}

						if (instInfo->caFlags & TraceDqr::CAFLAG_VLOAD) {
							n += fprintf(fp, "-%dL",instInfo->VIFinishCycles);
						}

						if (instInfo->caFlags & TraceDqr::CAFLAG_VSTORE) {
							n += fprintf(fp, "-%dS",instInfo->VIFinishCycles);
						}

						n += fprintf(fp, "] ");
					}

					for (int i = n; i < 14; i++) {
						fprintf(fp, " ");
					}
				}
				else if (vcd != nullptr) {
					if (instInfo->caFlags & TraceDqr::CAFLAG_PIPE0) {
						n =fprintf(fp, "[0]");
					}
					else if (instInfo->caFlags & TraceDqr::CAFLAG_PIPE1) {
						n = fprintf(fp, "[1]");
					}
					else {
						n = fprintf(fp, "[?]");
					}
				}

				n = fprintf(fp, "    %s:",dst);

				for (int i = n; i < 20; i++) {
					fprintf(fp, " ");
				}

				instInfo->instructionToText(dst,sizeof dst,instlevel);
				fprintf(fp, "  %s",dst);

				if (showBranches == true) {
					switch (instInfo->brFlags) {
					case TraceDqr::BRFLAG_none:
						break;
					case TraceDqr::BRFLAG_unknown:
						fprintf(fp, " [u]");
						break;
					case TraceDqr::BRFLAG_taken:
						fprintf(fp, " [t]");
						break;
					case TraceDqr::BRFLAG_notTaken:
						fprintf(fp, " [nt]");
						break;
					}
				}

				if (showCallsReturns == true) {
					if (instInfo->CRFlag != TraceDqr::isNone) {
						const char *format = "%s";

						fprintf(fp, " [");

						if (instInfo->CRFlag & TraceDqr::isCall) {
							fprintf(fp, format,"Call");
							format = ",%s";
						}

						if (instInfo->CRFlag & TraceDqr::isReturn) {
							fprintf(fp, format,"Return");
							format = ",%s";
						}

						if (instInfo->CRFlag & TraceDqr::isSwap) {
							fprintf(fp, format,"Swap");
							format = ",%s";
						}

						if (instInfo->CRFlag & TraceDqr::isInterrupt) {
							fprintf(fp, format,"Interrupt");
							format = ",%s";
						}

						if (instInfo->CRFlag & TraceDqr::isException) {
							fprintf(fp, format,"Exception");
							format = ",%s";
						}

						if (instInfo->CRFlag & TraceDqr::isExceptionReturn) {
							fprintf(fp, format,"Exception Return");
							format = ",%s";
						}

						fprintf(fp, "]");
					}
				}

				fprintf(fp, "\n");

				firstPrint = false;
			}

			if ((trace != nullptr) && trace_flag && (msgInfo != nullptr)) {
				// got the goods! Get to it!

				if (globalDebugFlag) {
					msgInfo->dumpRawMessage();
				}

				msgInfo->messageToText(dst,sizeof dst,msgLevel);

				if (firstPrint == false) {
					fprintf(fp, "\n");
				}

				if (srcbits > 0) {
					fprintf(fp, "[%d] ",msgInfo->coreId);
				}

				fprintf(fp, "Trace: %s",dst);

				fprintf(fp, "\n");

				firstPrint = false;
			}

			if ((trace != nullptr) && (itcPrintOpts != TraceDqr::ITC_OPT_NONE)) {
				std::string s;
				bool haveStr;

				core_mask = trace->getITCPrintMask();

				for (int core = 0; core_mask != 0; core++) {
					if (core_mask & 1) {
						s = trace->getITCPrintStr(core,haveStr,startTime,endTime);
						while (haveStr != false) {
							if (firstPrint == false) {
								fprintf(fp, "\n");
							}

							if (srcbits > 0) {
								fprintf(fp, "[%d] ",msgInfo->coreId);
							}

							std::cout << "ITC Print: ";

							if ((startTime != 0) || (endTime != 0)) {
								std::cout << "Msg Tics: <" << startTime << "-" << endTime << "> ";
							}

							std::cout << s;

							firstPrint = false;

							s = trace->getITCPrintStr(core,haveStr,startTime,endTime);
						}
					}

					core_mask >>= 1;
				}
			}
		}
	} while (ec == TraceDqr::DQERR_OK);

	if (ec == TraceDqr::DQERR_EOF) {
		if (firstPrint == false) {
			fprintf(fp, "\n");
		}
		//fprintf(fp, "End of Trace File\n");
	}
	else {
		printf("Error (%d) terminated trace decode\n",ec);
		CleanUp();
		return SIFIVE_TRACE_DECODER_ERR;
	}

	if ((trace != nullptr) && (itcPrintOpts != TraceDqr::ITC_OPT_NONE)) {
		std::string s = "";
		bool haveStr;

		core_mask = trace->getITCFlushMask();

		for (int core = 0; core_mask != 0; core++) {
			if (core_mask & 1) {
				s = trace->flushITCPrintStr(core,haveStr,startTime,endTime);
				while (haveStr != false) {
					if (firstPrint == false) {
						fprintf(fp, "\n");
					}

					if (srcbits > 0) {
						fprintf(fp, "[%d] ",core);
					}

					std::cout << "ITC Print: ";

					if ((startTime != 0) || (endTime != 0)) {
						std::cout << "Msg Tics: <" << startTime << "-" << endTime << "> ";
					}

					std::cout << s;

					firstPrint = false;

					s = trace->flushITCPrintStr(core,haveStr,startTime,endTime);
				}
			}

			core_mask >>= 1;
		}
	}

	if (analytics_detail > 0) {
		if (trace != nullptr) {
			trace->analyticsToText(dst,sizeof dst,analytics_detail);
			if (firstPrint == false) {
				fprintf(fp, "\n");
			}
			firstPrint = false;
			fprintf(fp, "%s",dst);
		}
		if (sim != nullptr) {
			sim->analyticsToText(dst,sizeof dst,analytics_detail);
			if (firstPrint == false) {
				fprintf(fp, "\n");
			}
			firstPrint = false;
			fprintf(fp, "%s",dst);
		}
	}
	CleanUp();

	return SIFIVE_TRACE_DECODER_OK;
}

/****************************************************************************
     Function: CleanUp
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: None
  Description: CleanUp Function
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
void SifiveDecoderInterface::CleanUp()
{
	if(fp != nullptr)
	{
		fclose(fp);
		fp = nullptr;
	}

	if (trace != nullptr) {
		trace->cleanUp();

		delete trace;
		trace = nullptr;
	}

	if (sim != nullptr) {
		delete sim;
		sim = nullptr;
	}

	if (vcd != nullptr) {
		delete vcd;
		vcd = nullptr;
	}
}

/****************************************************************************
     Function: Configure
     Engineer: Arjun Suresh
        Input: config - Decoder config structure
       Output: None
       return: TySifiveTraceDecodeError
  Description: Function to configure the decoder
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
TySifiveTraceDecodeError SifiveDecoderInterface::Configure(const TDecoderConfig& config)
{
	tf_name = config.trace_filepath;
	ef_name = config.elf_filepath;
	od_name = config.objdump_path;
	src_flag = config.display_src_info;
	file_flag = config.display_file_info;
	dasm_flag = config.display_dissassembly_info;
	trace_flag = config.display_trace_msg;
	func_flag = config.display_function_info;
	showCallsReturns = config.display_call_return_info;
	showBranches = config.display_branches_info;
	globalDebugFlag = config.display_raw_message_info;
	ctf_flag = config.enable_common_trace_format;
	profile_flag = config.enable_profiling_format;
	analytics_detail = config.analytics_detail_log_level;
	caType = config.cycle_accuracte_type;
	traceType = config.trace_type;
	numAddrBits = config.numAddrBits;
	addrDispFlags = config.addrDispFlags;
	archSize = config.archSize;
	msgLevel = config.trace_msg_log_level;
	tssize = config.timestamp_counter_size_in_bits;
	freq = config.timestamp_tick_clk_freq_hz;
	srcbits = config.src_field_size_bits;
	itcPrintOpts = config.itc_print_options;
	itcPrintChannel = config.itc_print_channel;

	return SIFIVE_TRACE_DECODER_OK;
}

/****************************************************************************
     Function: GetSifiveDecoderInterface
     Engineer: Arjun Suresh
        Input: None
       Output: None
       return: The pointer to the interface class object
  Description: Function that creates the interface class object
  Date         Initials    Description
2-Nov-2022     AS          Initial
****************************************************************************/
SifiveDecoderInterface* GetSifiveDecoderInterface()
{
	return new SifiveDecoderInterface;
}
