#include <iostream>
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
		#define DECODER_DLL_PATH "..\\..\\..\\..\\Release\\dqr.dll"
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
char TRACE_FILE[] = ".\\test_samples\\e31_hello_debug.htm.test\\e31_hello.rtd";
char ELF_FILE[] = ".\\test_samples\\e31_hello_debug.htm.test\\e31_hello.elf";
char OUT_FILE[] = ".\\test_samples\\e31_hello_debug.htm.test\\trace_out.txt";
char OBJDUMP_PATH[] = ".\\bin\\riscv64-unknown-elf-objdump.exe";
#else
char TRACE_FILE[] = "./test_samples/e31_hello_debug.htm.test/e31_hello.rtd";
char ELF_FILE[] = "./test_samples/e31_hello_debug.htm.test/e31_hello.elf";
char OUT_FILE[] = "./test_samples/e31_hello_debug.htm.test/trace_out.txt";
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

	typedef SifiveDecoderInterface* (*fpSifiveDecoderInterface)();
	fpSifiveDecoderInterface p_get_instance = reinterpret_cast<fpSifiveDecoderInterface>(GetProcAddress(dll_handle, "GetSifiveDecoderInterface"));
	SifiveDecoderInterface* decoder = p_get_instance();

	std::cout << "Decoding ..." << std::endl;
	int res = decoder->Decode(TRACE_FILE, ELF_FILE, OBJDUMP_PATH, OUT_FILE);
	if (res != 0)
	{
		std::cout << "Error in Decoding ..." << std::endl;
		return -1;
	}
	std::cout << "Decoding Complete..." << std::endl;
	return 0;
}
