#include <iostream>
#include <memory>
#include "dqr_interface.hpp"

#ifdef WINDOWS
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef WINDOWS
	#ifdef _DEBUG
		#define DECODER_DLL_PATH "..\\..\\..\\..\\Debug\\dqr.dll"
	#else
		#define DECODER_DLL_PATH ".\\dqr.dll"
	#endif
	#else
	#ifdef _DEBUG
		#define DECODER_DLL_PATH "../../Debug/libdqr.so"
	#else
		#define DECODER_DLL_PATH "../../Release/libdqr.so"
	#endif
	#define  LoadLibrary(lib)                 dlopen(lib, RTLD_LAZY)
	#define  GetProcAddress(handle, proc)     dlsym(handle, proc)
	#define  FreeLibrary(handle)              dlclose(handle)
	typedef void* HINSTANCE;
#endif

#ifdef WINDOWS
	char TRACE_FILE[] = ".\\test_samples\\suresh\\trc_encodedFile_session_id_0_1.rtd";
	char ELF_FILE[] = ".\\test_samples\\suresh\\sifive_sum.elf";
	char OUT_FILE[] = ".\\test_samples\\suresh\\trace_out.txt";
	char OBJDUMP_PATH[] = ".\\test_samples\\suresh\\riscv64-unknown-elf-objdump.exe";
#else
	char TRACE_FILE[] = "./test_samples/sifive_sum/sifive_sum.rtd";
	char ELF_FILE[] = "./test_samples/sifive_sum/sifive_sum.elf";
	char OUT_FILE[] = "./test_samples/sifive_sum/trace_out.txt";
	char OBJDUMP_PATH[] = "./bin/riscv64-unknown-elf-objdump";
#endif

int main()
{
	HINSTANCE dll_handle = LoadLibrary(DECODER_DLL_PATH);
	if (!dll_handle)
	{
		std::cout << "Could Not Open DLL ..." << std::endl;
		return -1;
	}

	fpGetSifiveDecoderInterface p_get_instance = reinterpret_cast<fpGetSifiveDecoderInterface>(GetProcAddress(dll_handle, "GetSifiveDecoderInterface"));
	std::unique_ptr<SifiveDecoderInterface> p_sifive_decoder(p_get_instance());
	SifiveDecoderInterface* decoder = p_get_instance();

	std::cout << "Configuring Decoder ..." << std::endl;
	TDecoderConfig config;
	config.trace_filepath = TRACE_FILE;
	config.elf_filepath = ELF_FILE;
	config.objdump_path = OBJDUMP_PATH;
	config.display_trace_msg = true;
	decoder->Configure(config);

	std::cout << "Decoding ..." << std::endl;
	TySifiveTraceDecodeError res = decoder->Decode(OUT_FILE);
	if (res != SIFIVE_TRACE_DECODER_OK)
	{
		std::cout << "Error in Decoding ..." << std::endl;
		return -1;
	}

	std::cout << "Decoding Complete..." << std::endl;
	return 0;
}

