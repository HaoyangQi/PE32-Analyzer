#include <windows.h>
#include <stdio.h>
#include <time.h> //used by AnalyzeTimeDateStamp()

/*We decide not to return following structures as return value:
 *IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_OPTIONAL_HEADER, 
 *IMAGE_FILE_HEADER
 *Because the sizes of them might influence the effciency of some
 *functions.
 *However, the rest of structures can be returned in some functions.
*/

/*---------DOS Header---------*/
void GetDosHeader(FILE *fp, IMAGE_DOS_HEADER *pImgDosHdr)
{
	fseek(fp,0,SEEK_SET);
	fread(pImgDosHdr,sizeof(IMAGE_DOS_HEADER),1,fp);
}

LONG GetEntryOfPE(FILE *fp)
{
	IMAGE_DOS_HEADER ImgDosHdr;
	GetDosHeader(fp, &ImgDosHdr);
	return(ImgDosHdr.e_lfanew);
}

/*---------NT Header---------*/
void GetNtHeader(FILE *fp, IMAGE_NT_HEADERS *pImgNtHdr)
{
	LONG eope = GetEntryOfPE(fp);
	fseek(fp,eope,SEEK_SET);
	fread(pImgNtHdr,sizeof(IMAGE_NT_HEADERS),1,fp);
}

DWORD GetPeSignature(FILE *fp)
{
	IMAGE_NT_HEADERS ImgNtHdr;
	GetNtHeader(fp, &ImgNtHdr);
	return(ImgNtHdr.Signature);
}

/*---------File Header---------*/
void GetFileHeader(FILE *fp, IMAGE_FILE_HEADER *pImgFileHdr)
{
     LONG eope = GetEntryOfPE(fp);
     /*According to IMAGE_NT_HEADERS, we can locate 
	  *IMAGE_FILE_HEADER only by skipping the PE 
	  *signature(DWORD).
	  */
     fseek(fp,eope+sizeof(DWORD),SEEK_SET);
     fread(pImgFileHdr,sizeof(IMAGE_FILE_HEADER),1,fp);
}

char *GetMachineType(FILE *fp)
{
	IMAGE_FILE_HEADER ImgFileHdr;
	char *tmp;
	
	GetFileHeader(fp, &ImgFileHdr);
	
	switch(ImgFileHdr.Machine)
	{
		case IMAGE_FILE_MACHINE_UNKNOWN:
			tmp = "Applicable to Any Machine Type";
			break;
		case IMAGE_FILE_MACHINE_AM33:
			tmp = "Matsushita AM33";
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			tmp = "x64";
			break;
		case IMAGE_FILE_MACHINE_ARM:
			tmp = "ARM little endian";
			break;
		case IMAGE_FILE_MACHINE_EBC:
			tmp = "EFI byte code";
			break;
		case IMAGE_FILE_MACHINE_I386:
			tmp = "Intel 386 or later processors and compatible processors";
			break;
		case IMAGE_FILE_MACHINE_IA64:
			tmp = "Intel Itanium processor family";
			break;
		case IMAGE_FILE_MACHINE_M32R:
			tmp = "Mitsubishi M32R little endian";
			break;
		case IMAGE_FILE_MACHINE_MIPS16:
			tmp = "MIPS16";
			break;
		case IMAGE_FILE_MACHINE_MIPSFPU:
			tmp = "MIPS with FPU";
			break;
		case IMAGE_FILE_MACHINE_MIPSFPU16:
			tmp = "MIPS16 with FPU";
			break;
		case IMAGE_FILE_MACHINE_POWERPC:
			tmp = "Power PC little endian";
			break;
		case IMAGE_FILE_MACHINE_POWERPCFP:
			tmp = "Power PC with floating point support";
			break;
		case IMAGE_FILE_MACHINE_R4000:
			tmp = "MIPS little endian";
			break;
		case IMAGE_FILE_MACHINE_SH3:
			tmp = "Hitachi SH3";
			break;
		case IMAGE_FILE_MACHINE_SH3DSP:
			tmp = "Hitachi SH3 DSP";
			break;
		case IMAGE_FILE_MACHINE_SH4:
			tmp = "Hitachi SH4";
			break;
		case IMAGE_FILE_MACHINE_SH5:
			tmp = "Hitachi SH5";
			break;
		case IMAGE_FILE_MACHINE_THUMB:
			tmp = "Thumb";
			break;
		case IMAGE_FILE_MACHINE_WCEMIPSV2:
			tmp = "MIPS little-endian WCE v2";
			break;
		default:
			tmp = "Unknown Machine Type";
			break;
	}
	
	return tmp;
}

WORD GetNumberOfSection(FILE *fp)
{
	IMAGE_FILE_HEADER ImgFileHdr;
	GetFileHeader(fp, &ImgFileHdr);
	return(ImgFileHdr.NumberOfSections);
}

DWORD LocateSymbolTable(FILE *fp)
{
	IMAGE_FILE_HEADER ImgFileHdr;
	GetFileHeader(fp, &ImgFileHdr);
	return(ImgFileHdr.PointerToSymbolTable);
}

/*WARNING:
 *
 *The value of member 'NumberOfSymbols' is the sum of
 *symbols and auxiliary symbols, because the size of 
 *IMAGE_SYMBOL is same as IMAGE_AUX_SYMBOL, both are 
 *18.
 */
DWORD GetNumberOfSymbols(FILE *fp)
{
	IMAGE_FILE_HEADER ImgFileHdr;
	GetFileHeader(fp, &ImgFileHdr);
	return(ImgFileHdr.NumberOfSymbols);
}

typedef struct ImageAttributes
{
	char *AttributeDiscription;
}IA, *PIA;

WORD ImgAttrFlag[16] = 
{
	IMAGE_FILE_RELOCS_STRIPPED,
	IMAGE_FILE_EXECUTABLE_IMAGE,
	IMAGE_FILE_LINE_NUMS_STRIPPED,
	IMAGE_FILE_LOCAL_SYMS_STRIPPED,
	IMAGE_FILE_AGGRESIVE_WS_TRIM,
	IMAGE_FILE_LARGE_ADDRESS_AWARE,
	0x0040,
	IMAGE_FILE_BYTES_REVERSED_LO,
	IMAGE_FILE_32BIT_MACHINE,
	IMAGE_FILE_DEBUG_STRIPPED,
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
	IMAGE_FILE_NET_RUN_FROM_SWAP,
	IMAGE_FILE_SYSTEM,
	IMAGE_FILE_DLL,
	IMAGE_FILE_UP_SYSTEM_ONLY,
	IMAGE_FILE_BYTES_REVERSED_HI
};

char* ImgAttrDiscription[16] = 
{
	"NO_RELOCS",
	"EXECUTABLE",
	"NO_LINE_NUMS",
	"NO_LOCAL_SYMBOLS",
	"AGGRESSIVE_WORKING_SET_TRIM(Deprecated)", //must be zero in windows 2000 or higher
	"HANDLE_LARGE_ADDRESS(>2GB)",
	"Reserved",
	"LITTLE_ENDIAN(Deprecated)", //must be zero
	"BASE_ON_32BIT_MACHINE",
	"NO_DEBUG_INFO",
	"REMOVABLE_RUN_FROM_SWAP",
	"NET_RUN_FROM_SWAP",
	"SYSTEM_FILE",
	"DLL_FILE",
	"RUN_ON_UNIPROCESSOR_MACHINE",
	"BIG_ENDIAN(Deprecated)" //must be zero
};

PIA GetImageAttributes(FILE *fp)
{
	IMAGE_FILE_HEADER ImgFileHdr;
	GetFileHeader(fp, &ImgFileHdr);
	
	WORD c = ImgFileHdr.Characteristics;
	/*The number '16' is based on the number of attributes that are defined in winnt.h*/
	PIA pia = (PIA)malloc(sizeof(IA)*16);
	int i = 0;
	
	for(i=0;i<16;i++)
	{
		pia[i].AttributeDiscription = "";
	}
	
	for(i=0;i<16;i++)
	{
		if(c & ImgAttrFlag[i])
		{
			pia[i].AttributeDiscription = ImgAttrDiscription[i];
		}
		else
		{
			continue;
		}
	}
	
	return pia;
}

/*---------Optional Header---------*/
void GetOptionalHeader(FILE *fp, IMAGE_OPTIONAL_HEADER *pImgOptHdr)
{
     LONG eope = GetEntryOfPE(fp);
     fseek(fp,eope+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER),SEEK_SET);
     fread(pImgOptHdr,sizeof(IMAGE_OPTIONAL_HEADER),1,fp);
}

DWORD GetEntryPoint(FILE *fp)
{
	IMAGE_OPTIONAL_HEADER ImgOptHdr;
	GetOptionalHeader(fp, &ImgOptHdr);
	return(ImgOptHdr.AddressOfEntryPoint);
}

DWORD GetImageBase(FILE *fp)
{
	IMAGE_OPTIONAL_HEADER ImgOptHdr;
	GetOptionalHeader(fp, &ImgOptHdr);
	return(ImgOptHdr.ImageBase);
}

DWORD GetSectionAlignInMem(FILE *fp)
{
	IMAGE_OPTIONAL_HEADER ImgOptHdr;
	GetOptionalHeader(fp, &ImgOptHdr);
	return(ImgOptHdr.SectionAlignment);
}

DWORD GetSectionAlignInFile(FILE *fp)
{
	IMAGE_OPTIONAL_HEADER ImgOptHdr;
	GetOptionalHeader(fp, &ImgOptHdr);
	return(ImgOptHdr.FileAlignment);
}

DWORD GetImageSize(FILE *fp)
{
	IMAGE_OPTIONAL_HEADER ImgOptHdr;
	GetOptionalHeader(fp, &ImgOptHdr);
	return(ImgOptHdr.SizeOfImage);
}

/*available value of 'field':
IMAGE_DIRECTORY_ENTRY_EXPORT	0
IMAGE_DIRECTORY_ENTRY_IMPORT	1
IMAGE_DIRECTORY_ENTRY_RESOURCE	2
IMAGE_DIRECTORY_ENTRY_EXCEPTION	3
IMAGE_DIRECTORY_ENTRY_SECURITY	4
IMAGE_DIRECTORY_ENTRY_BASERELOC	5
IMAGE_DIRECTORY_ENTRY_DEBUG	6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT	7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE	7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR	8
IMAGE_DIRECTORY_ENTRY_TLS	9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG	10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	11
IMAGE_DIRECTORY_ENTRY_IAT	12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	14
*/

IMAGE_DATA_DIRECTORY GetSpecificDataDirectory(FILE *fp, int field)
{
	IMAGE_DATA_DIRECTORY tmp;
	IMAGE_OPTIONAL_HEADER ImgOptHdr;
	
	GetOptionalHeader(fp, &ImgOptHdr);
	
	tmp.Size = 0;
	tmp.VirtualAddress = 0;
	
	//Firstly, check member NumberOfRvaAndSizes in IMAGE_OPTIONAL_HEADER
	if(ImgOptHdr.NumberOfRvaAndSizes == 0)
	{
		return tmp;
	}
	
	//Secondly, check value of 'field'
	else if(field<0 || field>14)
	{
		return tmp;
	}
	
	else
	{
		//Check if the specific directory is empty
		if(ImgOptHdr.DataDirectory[field].VirtualAddress == 0 ||
		   ImgOptHdr.DataDirectory[field].Size == 0)
		{
			return tmp;
		}
		else
		{
			return(ImgOptHdr.DataDirectory[field]);
		}
	}
}

IMAGE_DATA_DIRECTORY GetExportDataDirectory(FILE *fp)
{
      return(GetSpecificDataDirectory(fp, 0));
}

IMAGE_DATA_DIRECTORY GetImportDataDirectory(FILE *fp)
{
      return(GetSpecificDataDirectory(fp, 1));
}

/*---------Section Header---------*/
/*Pointer Warning:
 *You must allocate enough memory 
 *(according to NumberOfSections)
 *before using this function!
 *
 *For example:
 *    IMAGE_SECTION_HEADER *pSec = (IMAGE_SECTION_HEADER *)calloc(...));
 *    GetSectionHeader(fp,&pSec);
 */
void GetSectionHeader(FILE *fp, IMAGE_SECTION_HEADER **ppSecHdr)
{
	int NumOfSec = GetNumberOfSection(fp);
	LONG eope = GetEntryOfPE(fp);
	fseek(fp, eope + sizeof(IMAGE_NT_HEADERS), SEEK_SET);
	fread(*ppSecHdr, sizeof(IMAGE_SECTION_HEADER), NumOfSec, fp);
}

IMAGE_SECTION_HEADER GetSectionHeaderByName(FILE *fp, char *SecName)
{
     int i;
     IMAGE_SECTION_HEADER tmp;
     IMAGE_SECTION_HEADER *pSecHdr;
	 int NumOfSec;
	 
	 NumOfSec = GetNumberOfSection(fp);
	 pSecHdr = (IMAGE_SECTION_HEADER*)calloc(NumOfSec, sizeof(IMAGE_SECTION_HEADER));
	 GetSectionHeader(fp, &pSecHdr);
	 
     //Start searching the section
     for (i = 0; i < NumOfSec; i++)
     {
         if(!strcmp(pSecHdr->Name,SecName))
         {
             return *pSecHdr;
         }
         else
         {
             pSecHdr++;
         }
     }
     
     /*If cannot search the section, clear the member "Name" which is in IMAGE_SECTION_HEADER*/
     
     /*WARNING: For some reason, we cannot free the pointer pSecHdr yet. If we
	  *do it now, program will crash.*/
     //free(pSecHdr);
	 
     for (i=0;i<8;i++)
     {
         tmp.Name[i] = '\0';
     }
     
     return(tmp);
}

typedef struct SectionAttribute
{
	char *c;
}SA, *PSA;

DWORD SecAttrFlag[41] = 
{
	0x00000000, 0x00000001, 0x00000002, 0x00000004, 0x00000008,
	0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100,
	0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00008000,
	0x00020000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 
	0x00200000, 0x00300000, 0x00400000, 0x00500000, 0x00600000, 
	0x00700000, 0x00800000, 0x00900000, 0x00A00000, 0x00B00000, 
	0x00C00000, 0x00D00000, 0x00E00000, 0x01000000, 0x02000000, 
	0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 
	0x80000000
};

char* SecAttrDiscription[41] = 
{
	"Reserved", "Reserved", "Reserved", "Reserved", 
	"TYPE_NO_PAD", //valid in object file only
	"Reserved", 
	"CNT_CODE", "CNT_INITIALIZED_DATA", "CNT_UNINITIALIZED_DATA", 
	"LNK_OTHER(Reserved)",
	"LNK_INFO(.drectve)", //valid in object file only
	"Reserved",
	"LNK_REMOVE", //valid in object file only
	"LNK_COMDAT", //valid in object file only
	"GPREL", //GP = Global Pointer
	"MEM_PURGEABLE(Reserved)", "MEM_16BIT(Reserved)", 
	"MEM_LOCKED(Reserved)", "MEM_PRELOAD(Reserved)",
	/*-------Valid in object file only------------*/
	"ALIGN_1-BYTE","ALIGN_2-BYTE","ALIGN_4-BYTE",
	"ALIGN_8-BYTE","ALIGN_16-BYTE","ALIGN_32-BYTE",
	"ALIGN_64-BYTE","ALIGN_128-BYTE","ALIGN_256-BYTE",
	"ALIGN_512-BYTE","ALIGN_1024-BYTE","ALIGN_2048-BYTE",
	"ALIGN_4096-BYTE","ALIGN_8192-BYTE",
	/*--------------------------------------------*/
	"LNK_NRELOC_OVFL", "MEM_DISCARDABLE", "MEM_NOT_CACHED",
	"MEM_NOT_PAGED", "MEM_SHARED", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"
};

PSA GetAttributeOfSpecificSection(IMAGE_SECTION_HEADER SecHdr)
{
	DWORD c = SecHdr.Characteristics;
	int i = 0;
	PSA psa = (PSA)malloc(sizeof(SA)*41);
	
	for(i=0;i<41;i++)
	{
		psa[i].c = "";
	}
	
	for(i=0;i<41;i++)
	{
		if(c & SecAttrFlag[i])
		{
			psa[i].c = SecAttrDiscription[i];
		}
		else
		{
			continue;
		}
	}
	
	return psa;
}

/*---------Import Table---------*/

DWORD RVAtoFOA(FILE*, DWORD);

int GetTheNumOfImportModule(FILE *fp)
{
    IMAGE_IMPORT_DESCRIPTOR IID;
    IMAGE_SECTION_HEADER idata;
    IMAGE_DATA_DIRECTORY imp;
    DWORD ImpFOA;
    int ModuleCnt = 0;
    
	idata = GetSectionHeaderByName(fp, ".idata");
    
	if(idata.Name[0] == '\0')
    {
    	imp = GetImportDataDirectory(fp);
    	
    	if((imp.Size == 0) && (imp.VirtualAddress == 0))
    	{
    		return -1;
    	}
    	
    	ImpFOA = RVAtoFOA(fp, imp.VirtualAddress);
    }
    else
    {
		ImpFOA = idata.PointerToRawData;
    }
    
    fseek(fp, ImpFOA, SEEK_SET);
    
    while(1)
    {
    	fread(&IID, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, fp);
    	if ((IID.u.Characteristics == 0)    &&
    	    (IID.u.OriginalFirstThunk == 0) &&
    	    (IID.FirstThunk == 0)           &&
    	    (IID.ForwarderChain == 0)       &&
    	    (IID.Name == 0)                 &&
    	    (IID.TimeDateStamp == 0))
    	{
    		break;
    	}
    	ModuleCnt++;
	}
    
    return ModuleCnt;
}

/*Pointer Warning:
 *You must allocate enough memory (according to GetTheNumOfImportModule())
 *before using this function!
 *
 *For example:
 *    IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)calloc(...));
 *    GetImportModuleTable(fp,&pIID);
 *
 */
void GetImportModuleTable(FILE *fp, IMAGE_IMPORT_DESCRIPTOR **ppIID)
{
	IMAGE_SECTION_HEADER idata;
	IMAGE_DATA_DIRECTORY imp;
	int NumOfMod;
	
	idata = GetSectionHeaderByName(fp, ".idata");
	NumOfMod = GetTheNumOfImportModule(fp);
	
    if(NumOfMod == -1)
    {
    	*ppIID = NULL;
    	return;
    }
	
	if(idata.Name[0] == '\0')
    {
    	imp = GetImportDataDirectory(fp);
    	
    	if((imp.Size == 0) && (imp.VirtualAddress == 0))
    	{
    		*ppIID = NULL;
			return;
    	}
    	
    	fseek(fp, RVAtoFOA(fp, imp.VirtualAddress), SEEK_SET);
    }
    else
    {
    	fseek(fp, idata.PointerToRawData, SEEK_SET);
    }
    
	fread(*ppIID, sizeof(IMAGE_IMPORT_DESCRIPTOR), NumOfMod, fp);
	return;
}

/*
 *VA:5000----->  +-----------------+  <-----RawOffset:1200
 *   |           |     .idata      |        |
 *   |0x270      |      ...        |        |also is: 0x270
 *   |           | IID->Name=5270  |        |
 *VA:5270----->  | "KERNEL32.DLL"  |  <-----RawOffset:1470
 *               +-----------------+
 *
 *The third parameter is same as the second parameter in GetTheNumOfImportModule()
 *
 *You can use a "for" loop to print all DLL names
*/

#define NAMELEN 100

typedef struct ImportModuleNameList
{
	char name[NAMELEN];
}IMNL, *PIMNL;

PIMNL GetModuleName(FILE *fp, IMAGE_IMPORT_DESCRIPTOR *pIID)
{
	PIMNL mnl;
	IMAGE_SECTION_HEADER idata;
	IMAGE_DATA_DIRECTORY imp;
	DWORD idataRawAddr, idataVA, ModNameRawOffset;
	int NumMod;
	int i = 0;
	
	idata = GetSectionHeaderByName(fp, ".idata");
	NumMod = GetTheNumOfImportModule(fp);
	
    if(NumMod == -1)
    {
    	return NULL;
    }
	
	if(idata.Name[0] == '\0')
    {
    	imp = GetImportDataDirectory(fp);
    	
    	if((imp.Size == 0) && (imp.VirtualAddress == 0))
    	{
			return NULL;
    	}
    	
    	idataRawAddr = RVAtoFOA(fp, imp.VirtualAddress);
    	idataVA = imp.VirtualAddress;
    }
    else
    {
    	idataRawAddr = idata.PointerToRawData;
    	idataVA = idata.VirtualAddress;
    }
    
	mnl = (PIMNL)malloc(sizeof(IMNL)*NumMod);
	
	for(i=0;i<NumMod;i++)
	{
		ModNameRawOffset = idataRawAddr + (pIID[i].Name - idataVA);
     	fseek(fp,ModNameRawOffset,SEEK_SET);
     	fread(mnl[i].name,NAMELEN,1,fp);
	}
	
	return mnl;
}

//Warning: If 2 or more dll names are same, use GetImportModuleTable()
IMAGE_IMPORT_DESCRIPTOR GetSpecificImportLibraryInfo(FILE *fp, char *DllName)
{
	IMAGE_IMPORT_DESCRIPTOR *IID;
	IMAGE_IMPORT_DESCRIPTOR tmp;
	PIMNL mnl;
	int NumMod;
	int i;
	
	tmp.u.Characteristics = 0;
	tmp.u.OriginalFirstThunk = 0;
	tmp.FirstThunk = 0;
	tmp.ForwarderChain = 0;
	tmp.Name = 0;
	tmp.TimeDateStamp = 0;
	
	NumMod = GetTheNumOfImportModule(fp);
	IID = (IMAGE_IMPORT_DESCRIPTOR*)calloc(NumMod,sizeof(IMAGE_IMPORT_DESCRIPTOR));
	
	GetImportModuleTable(fp,&IID);
	mnl = GetModuleName(fp,IID);
	
	for(i=0;i<NumMod;i++)
	{
		if(!strcmp((*mnl).name,DllName))
		{
			return *IID;
		}
		else
		{
			IID++;
			mnl++;
		}
	}
	
	return tmp;
}

typedef struct NumberOfFunction
{
	char *name;
	int func;
}NOF, *PNOF;

PNOF EnumNumberOfFunction(FILE *fp)
{
	IMAGE_IMPORT_DESCRIPTOR *pIID;
	IMAGE_THUNK_DATA trunk;
	PIMNL pmnl;
	PNOF pnf;
	int NumMod;
	int i;
	
	NumMod = GetTheNumOfImportModule(fp);
	pIID = (IMAGE_IMPORT_DESCRIPTOR*)calloc(NumMod, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	pnf = (PNOF)calloc(NumMod, sizeof(NOF));
	pmnl = (PIMNL)calloc(NumMod, sizeof(IMNL));
	
	GetImportModuleTable(fp, &pIID);
	pmnl = GetModuleName(fp, pIID);
	
	for(i=0;i<NumMod;i++)
	{
		pnf[i].name = pmnl[i].name;
	}
	
	//free(pmnl);
	
	/*WARNING: We cannot free pmnl, because pnf->name is a pointer, if we
	 * free pmnl now, result would be unpredictable.
	 */
	
	for(i=0;i<NumMod;i++)
	{
		if(pIID[i].u.Characteristics == 0)        //Try to search in HNT
		{
			if(pIID[i].u.OriginalFirstThunk == 0) //Try to search in HNT
			{
				if(pIID[i].FirstThunk == 0)       //Try to search in IAT
				{
					pnf[i].func = 0;
					continue;
				}
				else
				{
					fseek(fp, RVAtoFOA(fp,pIID[i].FirstThunk), SEEK_SET);
				}
			}
			fseek(fp, RVAtoFOA(fp,pIID[i].u.OriginalFirstThunk), SEEK_SET);
		}
		else
		{
			fseek(fp, RVAtoFOA(fp,pIID[i].u.Characteristics), SEEK_SET);
		}
		
		while(1)
		{
			fread(&trunk, sizeof(IMAGE_THUNK_DATA), 1, fp);
			if((trunk.u1.ForwarderString == 0) && 
			   (trunk.u1.Function == 0) && 
			   (trunk.u1.Ordinal == 0) && 
			   (trunk.u1.AddressOfData == 0))
			{
				break;
			}
			(pnf[i].func)++;
		}
	}
	
	free(pIID);
	
	return pnf;
}

/*Warning: If 2 or more dll names are same, this function will calcculate
 *the sum of the number of functions and return. See more details, 
 *EnumNumberOfFunction() can be used.
 */
int GetNumberOfFunctionByName(FILE *fp, char *DllName)
{
	IMAGE_IMPORT_DESCRIPTOR IID;
	IMAGE_THUNK_DATA trunk;
	PNOF pnf;
	int NumMod;
	int sum=0;
	int i=0;
	
	NumMod = GetTheNumOfImportModule(fp);
	pnf = EnumNumberOfFunction(fp);
	
	if((pnf == NULL) || (NumMod == -1))
	{
		return -1;
	}
	
	for(i=0;i<NumMod;i++)
	{
		if(!strcmp(pnf[i].name,DllName))
		{
			sum = sum + pnf[i].func;
		}
	}
	
	return sum;
}

/*                    Import Table Structure
 *Firstly, we locate FOA of the beginning of import table, then we reach
 *IID(IMAGE_IMPORT_DESCRIPTOR) array. Each IID decribes one dll.
 *
 *Secondly, use member of IID 'Characteristics' or 'OriginalFirstThunk'
 *(Both are RVA) to reach HNT(Hint Name Table). HNT is an array that is
 *made of IMAGE_THUNK_DATA, each trunk decribes one function. Each function
 *can be imported as ordinal(Ordinal) or Name(AddressOfData). HNT will not 
 *be changed.
 *
 *Thirdly, use member of IID 'FirstThunk'(RVA) to reach IAT(Import Address Table). 
 *IAT is exactly same as HNT in static analyzing. However, IAT will be 
 *overwritten by PE loader in memory, in order to make 'FirstThunk' point 
 *to the real address of this function in memory.
 *                                                          +-->Point to real address of function
 * +--------+      +---+       +---+      +-------------+   |  +---+                  (in memory)
 * |DLL Name|<-----|IID|-+-+-->|HNT|----->|Function Name|<--+--|IAT|<--+
 * +--------+      +---+ | |   +---+      +-------------+   |  +---+   |
 * +--------+      +---+ | +-->|HNT|----->|Function Name|<--+--|IAT|<--+
 * |DLL Name|<-----|IID| | |   +---+      +-------------+   |  +---+   |
 * +--------+      +---+ | +-->|HNT|----->|Function Name|<--+--|IAT|<--+
 * +--------+      +---+ | |   +---+      +-------------+   |  +---+   |
 * |DLL Name|<-----|IID| | +-->|HNT|----->|Function Name|<--+--|IAT|<--+
 * +--------+      +---+ |     +---+      +-------------+      +---+   |
 *    ...           ...  |      ...             ...             ...    |
 *                       +---------------------------------------------+
 *
*/

/*Just in case, we choose not to load HNT or IAT by dll name, 
 *replaced by an IID.
*/

typedef struct NameTableInfo
{
	int FuncNum;
	IMAGE_THUNK_DATA* NameTable;
}NTI, *PNTI;

NTI GetHNT(FILE *fp, IMAGE_IMPORT_DESCRIPTOR IID)
{
	IMAGE_THUNK_DATA trunk;
	NTI nti;
	DWORD TrunkFOA;
	int NumFunc = 0;
	
	nti.FuncNum = 0;
	nti.NameTable = NULL;
	
	if(IID.u.Characteristics == 0) //Try to search HNT
	{
		if(IID.u.OriginalFirstThunk == 0)
		{
			return nti;
		}
		TrunkFOA = RVAtoFOA(fp,IID.u.OriginalFirstThunk);
	}
	else
	{
		TrunkFOA = RVAtoFOA(fp,IID.u.Characteristics);
	}
	
	fseek(fp, TrunkFOA, SEEK_SET);
	
	while(1)
	{
		fread(&trunk, sizeof(IMAGE_THUNK_DATA), 1, fp);
		if((trunk.u1.ForwarderString == 0) && 
		   (trunk.u1.Function == 0) && 
		   (trunk.u1.Ordinal == 0) && 
		   (trunk.u1.AddressOfData == 0))
		{
			break;
		}
		NumFunc++;
	}
	
	nti.NameTable = (IMAGE_THUNK_DATA*)calloc(NumFunc, sizeof(IMAGE_THUNK_DATA));
	nti.FuncNum = NumFunc;
	
	fseek(fp, TrunkFOA, SEEK_SET);
	fread(nti.NameTable, sizeof(IMAGE_THUNK_DATA), NumFunc, fp);
	
	return nti;
}

NTI GetIAT(FILE *fp, IMAGE_IMPORT_DESCRIPTOR IID)
{
	IMAGE_THUNK_DATA trunk;
	NTI nti;
	DWORD TrunkFOA;
	int NumFunc = 0;
	
	nti.FuncNum = 0;
	nti.NameTable = NULL;
	
	if(IID.FirstThunk == 0) //Try to search IAT
	{
		return nti;
	}
	else
	{
		TrunkFOA = RVAtoFOA(fp,IID.FirstThunk);
	}
	
	fseek(fp, TrunkFOA, SEEK_SET);
	
	while(1)
	{
		fread(&trunk, sizeof(IMAGE_THUNK_DATA), 1, fp);
		if((trunk.u1.ForwarderString == 0) && 
		   (trunk.u1.Function == 0) && 
		   (trunk.u1.Ordinal == 0) && 
		   (trunk.u1.AddressOfData == 0))
		{
			break;
		}
		NumFunc++;
	}
	
	nti.NameTable = (IMAGE_THUNK_DATA*)calloc(NumFunc, sizeof(IMAGE_THUNK_DATA));
	nti.FuncNum = NumFunc;
	
	fseek(fp, TrunkFOA, SEEK_SET);
	fread(nti.NameTable, sizeof(IMAGE_THUNK_DATA), NumFunc, fp);
	
	return nti;
}

/*In fact, member 'AddressOfData' in IMAGE_THUNK_DATA point to an another 
 *array of struct called IMAGE_IMPORT_BY_NAME. The first member 'Hint' is
 *not necessary, and the second one can be used as an address pointer to 
 *help us locate function name, but it is not worth. Therefore, we choose 
 *to skip 'Hint'(WORD) directly and read name by ourselves.
 *So we locate a function name like this:
 *      Function Name FOA = RVAtoFOA(AddressOfData)+sizeof(WORD)
 *Function names are end of '\0', so we can create a long enough array to
 *store them.
*/

typedef struct FunctionNameList
{
	char FuncName[NAMELEN];
	DWORD BoundAddr;
}FNL, *PFNL;

PFNL EnumFunctionNameFromHNT(FILE *fp, IMAGE_IMPORT_DESCRIPTOR IID)
{
	NTI nti;
	PFNL fnl;
	int i;
	
	nti = GetHNT(fp, IID);
	fnl = (PFNL)calloc(nti.FuncNum, sizeof(FNL));
	
	for(i=0;i<nti.FuncNum;i++)
	{
		fseek(fp, RVAtoFOA(fp,nti.NameTable[i].u1.AddressOfData)+sizeof(WORD), SEEK_SET);
		
		if(nti.NameTable[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)
		{
			snprintf(fnl[i].FuncName, 
		    	     NAMELEN, 
		        	 "%d\t(Import by ordinal)", 
					 IMAGE_ORDINAL(nti.NameTable[i].u1.Ordinal));
		}
		else
		{
			fread(fnl[i].FuncName, NAMELEN, 1, fp);
		}
		
		if(IID.TimeDateStamp == 0) //No bound
		{
			fnl[i].BoundAddr = 0;
		}
		else if((int)IID.TimeDateStamp == -1) //Has bound
		{
			fnl[i].BoundAddr = nti.NameTable[i].u1.Function;
		}
		else
		{
			fnl[i].BoundAddr = 0;
		}
	}
	
	return fnl;
}

/*Actually, this function has same result as EnumFunctionNameFromHNT in 
 *static analyzing. But when the image is loaded in memory, the union 
 *member 'AddressOfData' will be overwritten by PE loader to make it point
 *at real address of this function in memory.
 */
PFNL EnumFunctionNameFromIAT(FILE *fp, IMAGE_IMPORT_DESCRIPTOR IID)
{
	NTI nti;
	PFNL fnl;
	int i;
	
	nti = GetIAT(fp, IID);
	fnl = (PFNL)calloc(nti.FuncNum, sizeof(FNL));
	
	for(i=0;i<nti.FuncNum;i++)
	{
		fseek(fp, RVAtoFOA(fp,nti.NameTable[i].u1.AddressOfData)+sizeof(WORD), SEEK_SET);
		
		if(nti.NameTable[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)
		{
			snprintf(fnl[i].FuncName, 
		    	     NAMELEN, 
		        	 "%d\t(Import by ordinal)", 
					 IMAGE_ORDINAL(nti.NameTable[i].u1.Ordinal));
		}
		else
		{
			fread(fnl[i].FuncName, NAMELEN, 1, fp);
		}
		
		if(IID.TimeDateStamp == 0) //No bound
		{
			fnl[i].BoundAddr = 0;
		}
		else if((int)IID.TimeDateStamp == -1) //Has bound
		{
			fnl[i].BoundAddr = nti.NameTable[i].u1.Function;
		}
		else
		{
			fnl[i].BoundAddr = 0;
		}
	}
	
	return fnl;
}

/*------------------------------*/

/*---------Export Table---------*/

IMAGE_EXPORT_DIRECTORY GetExportTableHeader(FILE *fp)
{
	IMAGE_SECTION_HEADER edata;
    IMAGE_DATA_DIRECTORY idd;
    IMAGE_EXPORT_DIRECTORY exp, *tmp;
    DWORD ExportTableFOA;
    
    tmp = (IMAGE_EXPORT_DIRECTORY*)calloc(1, sizeof(IMAGE_EXPORT_DIRECTORY));
    
    edata = GetSectionHeaderByName(fp, ".edata");
    
	if(edata.Name[0] == '\0')
    {
    	idd = GetExportDataDirectory(fp);
    	
    	if((idd.Size == 0) && (idd.VirtualAddress == 0))
    	{
    		return *tmp;
    	}
    	
    	ExportTableFOA = RVAtoFOA(fp, idd.VirtualAddress);
    }
    else
    {
    	ExportTableFOA = edata.PointerToRawData;
    }
    
    free(tmp);
    
    fseek(fp, ExportTableFOA, SEEK_SET);
    fread(&exp, sizeof(IMAGE_EXPORT_DIRECTORY), 1, fp);
    
    return exp;
}

DWORD GetNumberOfExportFunction(FILE *fp)
{
	IMAGE_EXPORT_DIRECTORY exp;
    
    exp = GetExportTableHeader(fp);
    
    if(exp.NumberOfFunctions == 0)
    {
    	return -1;
    }
    
	return exp.NumberOfFunctions;
}

DWORD GetNumberOfExportFunctionByName(FILE *fp)
{
	IMAGE_EXPORT_DIRECTORY exp;
    
    exp = GetExportTableHeader(fp);
    
    if(exp.NumberOfFunctions == 0)
    {
    	return -1;
    }
    
	return exp.NumberOfNames;
}

DWORD GetNumberOfExportFunctionByOrdn(FILE *fp)
{
	IMAGE_EXPORT_DIRECTORY exp;
    
    exp = GetExportTableHeader(fp);
    
    if(exp.NumberOfFunctions == 0)
    {
    	return -1;
    }
    
	return(exp.NumberOfFunctions - exp.NumberOfNames);
}

/*Addresses in FAT(Function Address Table) are RVAs, However, 
 *if it is a forwarder, it will be a FOA.*/
DWORD* GetFAT(FILE *fp)
{
	IMAGE_EXPORT_DIRECTORY IED;
	DWORD NumFunc;
	DWORD FATFOA;
	DWORD *FuncAddr;
	
	IED =  GetExportTableHeader(fp);
	
	if(IED.NumberOfFunctions == 0)
	{
		return NULL;
	}
	
	NumFunc = GetNumberOfExportFunction(fp);
	FuncAddr = (DWORD*)calloc(NumFunc, sizeof(DWORD));
	FATFOA = RVAtoFOA(fp, IED.AddressOfFunctions);
	
	fseek(fp, FATFOA, SEEK_SET);
	fread(FuncAddr, sizeof(DWORD), NumFunc, fp);
	
	return FuncAddr;
}

DWORD AdjustNumberOfExportFunction(FILE *fp)
{
	DWORD NumFunc;
	DWORD RealNumFunc=0;
	DWORD *FAT;
	int i;
	
	NumFunc = GetNumberOfExportFunction(fp);
	
	if((int)NumFunc == -1)
	{
		return -1;
	}
	
	FAT = GetFAT(fp);
	
	for(i=0;i<NumFunc;i++)
	{
		while(FAT[i] == 0)
		{
			i++;
		}
		RealNumFunc++;
	}
	
	return RealNumFunc;
}

/*FNT - Function Name Table*/
DWORD* GetFNT(FILE *fp)
{
	IMAGE_EXPORT_DIRECTORY IED;
	DWORD NumName;
	DWORD FNTFOA;
	DWORD *FuncName;
	
	IED =  GetExportTableHeader(fp);
	
	if(IED.NumberOfFunctions == 0)
	{
		return NULL;
	}
	
	if((IED.AddressOfNames == 0) || (IED.NumberOfNames == 0))
	{
		NumName = GetNumberOfExportFunctionByOrdn(fp);
		
		if((int)NumName == -1)
		{
			return NULL;
		}
		
		FuncName = (DWORD*)calloc(NumName, sizeof(DWORD));
	}
	else
	{
		NumName = IED.NumberOfNames;
		FuncName = (DWORD*)calloc(NumName, sizeof(DWORD));
		FNTFOA = RVAtoFOA(fp, IED.AddressOfNames);
		fseek(fp, FNTFOA, SEEK_SET);
		fread(FuncName, sizeof(DWORD), NumName, fp);
	}
	
	return FuncName;
}

/*FOT - Function Ordinal Table*/
/*Warning: The number of elements in FOT equals IED.NumberOfNames*/
WORD* GetFOT(FILE *fp)
{
	IMAGE_EXPORT_DIRECTORY IED;
	DWORD NumName;
	DWORD FOTFOA;
	WORD *FuncOrdn;
	int i;
	
	IED =  GetExportTableHeader(fp);
	
	if(IED.NumberOfFunctions == 0)
	{
		return NULL;
	}
	
	if((IED.AddressOfNames == 0) || (IED.NumberOfNames == 0))
	{
		NumName = GetNumberOfExportFunctionByOrdn(fp);
		
		if((int)NumName == -1)
		{
			return NULL;
		}
	}
	else
	{
		NumName = IED.NumberOfNames;
	}
	
	FuncOrdn = (WORD*)calloc(NumName, sizeof(WORD));
	
	if(IED.AddressOfNameOrdinals != 0)
	{
		FOTFOA = RVAtoFOA(fp, IED.AddressOfNameOrdinals);
		
		fseek(fp, FOTFOA, SEEK_SET);
		fread(FuncOrdn, sizeof(WORD), NumName, fp);
	}
	else
	{
		for(i=0;i<NumName;i++)
		{
			FuncOrdn[i] = i;
		}
	}
	
	return FuncOrdn;
}

typedef struct ExportInfo
{
	WORD Index;
	char Forwarder[NAMELEN];
	char Name[NAMELEN];
	DWORD Addr;    //RVA, if it is a forwarder, set it to 0
	DWORD RawAddr; //FOA, if it is a forwarder, set it to 0
}EI, *PEI;

PEI GetExportInfo(FILE *fp)
{
	PEI pei;
	IMAGE_DATA_DIRECTORY idd;
	IMAGE_EXPORT_DIRECTORY IED;
	DWORD *FAT;
	DWORD *FNT;
	WORD  *FOT;
	DWORD NumFunc;
	int RealNumFunc=0;
	int i, j=0;
	
	idd = GetExportDataDirectory(fp);
	if(idd.Size==0 || idd.VirtualAddress==0)
	{
		return NULL;
	}
	
	FAT = GetFAT(fp);
	FNT = GetFNT(fp);
	FOT = GetFOT(fp);
	NumFunc = GetNumberOfExportFunction(fp);
	IED = GetExportTableHeader(fp);
	
	for(i=0;i<NumFunc;i++)
	{
		while(FAT[i] == 0)
		{
			i++;
		}
		RealNumFunc++;
	}
	
	pei = (PEI)calloc(RealNumFunc, sizeof(EI));
	
	for(i=0;i<NumFunc;i++)
	{
		while(FAT[i] == 0)
		{
			i++;
		}
		
		pei[j].Index = FOT[i] + IED.Base;
		
		/*Read function name and adjust function address*/
		if(FNT[i] != 0)
		{
			if((FAT[FOT[i]] > RVAtoFOA(fp,idd.VirtualAddress)) && 
			   (FAT[FOT[i]] < RVAtoFOA(fp,idd.VirtualAddress)+idd.Size))
			{
				fseek(fp, RVAtoFOA(fp, FAT[FOT[i]]), SEEK_SET);
				fread(pei[j].Forwarder, NAMELEN, 1, fp);
				
				pei[j].Addr = 0;
				pei[j].RawAddr = 0;
			}
			else
			{
				pei[j].Addr = FAT[FOT[i]];
				pei[j].RawAddr = RVAtoFOA(fp, FAT[FOT[i]]);
			}
			
			fseek(fp, RVAtoFOA(fp, FNT[i]), SEEK_SET);
			fread(pei[j].Name, NAMELEN, 1, fp);
		}
		else
		{
			if((FAT[FOT[i]] > RVAtoFOA(fp,idd.VirtualAddress)) && 
			   (FAT[FOT[i]] < RVAtoFOA(fp,idd.VirtualAddress)+idd.Size))
			{
				pei[j].Addr = 0;
				pei[j].RawAddr = 0;
			}
			else
			{
				pei[j].Addr = FAT[FOT[i]];
				pei[j].RawAddr = RVAtoFOA(fp, FAT[FOT[i]]);
			}
		}
		
		j++;
	}
	
	return pei;
}

/*------------------------------*/

/*---------Symbol Table---------*/

int GetNumberOfAuxSymbol(FILE *fp)
{
	IMAGE_SYMBOL *sym;
	int i;
	int auxcnt=0;
	DWORD SymFOA = LocateSymbolTable(fp);
	DWORD NumSym = GetNumberOfSymbols(fp);
	
	sym = (IMAGE_SYMBOL*)calloc(NumSym, sizeof(IMAGE_SYMBOL));
	
	fseek(fp, SymFOA, SEEK_SET);
	fread(sym, sizeof(IMAGE_SYMBOL), NumSym, fp);
	
	for(i=0;i<NumSym;i++)
	{
		auxcnt += sym[i].NumberOfAuxSymbols;
		i += sym[i].NumberOfAuxSymbols; //Skip these aux symbols
	}
	
	free(sym);
	return auxcnt;
}

typedef struct SymbolInfo
{
	char name[NAMELEN];
	/*SectionNumber
	 *
	 *Use GetSectionHeader(fp, &pSec)
	 *The section that has this symbol = pSec[SectionNumber-1]
	 *
	 *The following value has special meaning:
	 *
	 *IMAGE_SYM_UNDEFINED(0) The symbol record is not yet assigned a section.
	 *IMAGE_SYM_ABSOLUTE(-1) The symbol has an absolute (non-relocatable) value 
	 *                       and is not an address.
	 *IMAGE_SYM_DEBUG(-2)    The symbol provides general type or debugging information.
	 */
	short SectionNumber;
	WORD Type1;    //sym[i].Type & 0xf
	BOOL Type2[3]; //[0] - ISPTR(sym[i].Type)
	               //[1] - ISFCN(sym[i].Type)
	               //[2] - ISARY(sym[i].Type)
	BYTE StorageClass;
	BYTE NumberOfAuxSymbols;
}SI, *PSI;

/*About the symbol name
 *If the length of a symbol name is short than 8 bytes, it will be stored
 *in IMAGE_SYMBOL.N.ShortName. Otherwise, A file offset will be stored in 
 *IMAGE_SYMBOL.N.Name.Long, and IMAGE_SYMBOL.N.Name.Short will be set to 
 *zero. That offset points to the symbol name, which is in a data table 
 *called String Table. It is originally at the end of the file.
*/

PSI GetSymbolInfo(FILE *fp)
{
	IMAGE_SYMBOL *sym;
	PSI psi, tmp;
	int i=0,j=0,k=0;
	char ShortName[IMAGE_SIZEOF_SHORT_NAME + 1];
	DWORD SymFOA;
	DWORD NumSym;
	DWORD SymbolSize;
	DWORD LongNameAddr;//String table FOA + sym.N.Name.Long + SymbolSize
	
	SymFOA = LocateSymbolTable(fp);
	NumSym = GetNumberOfSymbols(fp);
	
	if(SymFOA == 0 || NumSym == 0)
	{
		return NULL;
	}
	
	SymbolSize = sizeof(IMAGE_SYMBOL)*NumSym;
	
	sym = (IMAGE_SYMBOL*)calloc(NumSym, sizeof(IMAGE_SYMBOL));
	psi = (PSI)calloc(NumSym - GetNumberOfAuxSymbol(fp), sizeof(SI));
	tmp = (PSI)calloc(NumSym, sizeof(SI));
	
	fseek(fp, SymFOA, SEEK_SET);
	fread(sym, sizeof(IMAGE_SYMBOL), NumSym, fp);
	
	for(i=0;i<NumSym;i++)
	{
		/*The Core Of Symbol Analyzing
		 *
		 *We must rule out some targets first, because some times, 
		 *auxiliary symbol table entries may follow this record. 
		 *Thus, we skip those symbols.
		*/
		
        if(sym[i].N.Name.Short != 0) //This is a short name
        {
            for(j=0;j<IMAGE_SIZEOF_SHORT_NAME;j++)
			{
				/*The Core Of Symbol Analyzing
				 *We also need to rule out some names that have unacceptable character, 
				 *just in case.
				 */
				if ((sym[i].N.ShortName[j]>0x1f) && (sym[i].N.ShortName[j]<0x7f))
				{
					ShortName[j] = sym[i].N.ShortName[j];
				}
				else
				{
					ShortName[j] = '\0';
				}
            }
			strncpy(tmp[i].name, ShortName, IMAGE_SIZEOF_SHORT_NAME);
        }
        
        else //This is a long name
		{
			LongNameAddr = SymFOA + SymbolSize + sym[i].N.Name.Long;
			fseek(fp, LongNameAddr, SEEK_SET);
			fread(tmp[i].name, NAMELEN, 1, fp);
		}
		
		tmp[i].SectionNumber = sym[i].SectionNumber;
		tmp[i].Type1 = sym[i].Type & 0xf;
		tmp[i].Type2[0] = ISPTR(sym[i].Type);
		tmp[i].Type2[1] = ISFCN(sym[i].Type);
		tmp[i].Type2[2] = ISARY(sym[i].Type);
		tmp[i].StorageClass = sym[i].StorageClass;
		tmp[i].NumberOfAuxSymbols = sym[i].NumberOfAuxSymbols;
        
        psi[k] = tmp[i];
		
		/*The Core Of Symbol Analyzing
		 *Finally, we need to jump over auxiliary symbol table(s).
		 */
		i += sym[i].NumberOfAuxSymbols;
		k++;
	}
	
	return psi;
}

PIMAGE_AUX_SYMBOL GetAuxSymbolInfo(FILE *fp)
{
	IMAGE_AUX_SYMBOL *aux;
	IMAGE_SYMBOL *sym;
	int NumAux;
	DWORD SymFOA;
	DWORD NumSym;
	DWORD AuxFOA;
	DWORD AuxStart;
	int i, j, k=0;
	
	SymFOA = LocateSymbolTable(fp);
	NumSym = GetNumberOfSymbols(fp);
	NumAux = GetNumberOfAuxSymbol(fp);
	aux = (PIMAGE_AUX_SYMBOL)calloc(NumAux, sizeof(IMAGE_AUX_SYMBOL));
	sym = (IMAGE_SYMBOL*)calloc(NumSym, sizeof(IMAGE_SYMBOL));
	
	fseek(fp, SymFOA, SEEK_SET);
	fread(sym, sizeof(IMAGE_SYMBOL), NumSym, fp);
	
	int tmp;
	
	for(i=0;i<NumSym;i++)
	{
		tmp = sym[i].NumberOfAuxSymbols;
		
		if(tmp != 0)
		{
			AuxStart = SymFOA + sizeof(IMAGE_SYMBOL) * (i + 1);
			
			for(j=0;j<tmp;j++)
			{
				i+=1;
				AuxFOA = SymFOA + sizeof(IMAGE_SYMBOL) * i;
				fseek(fp, AuxFOA, SEEK_SET);
				fread(&(aux[k]), sizeof(IMAGE_AUX_SYMBOL), 1, fp);
				fseek(fp, AuxStart, SEEK_SET);
				k+=1;
			}
		}
	}
	
	free(sym);
	return aux;
}

#define FUNCDEF  1
#define BFEF     2
#define WEAKEXT  3
#define FILENAME 4
#define SECDEF   5

/*Algorithm:
 *If we want to analyze aux symbol(s), sometimes, we need the symbol which has them.
 *For example: A symbol table psi[0] has 2 aux symbol, so we read aux[0] and aux[1].
 *Because GetAuxSymbolInfo() returns a aux symbol table list in correct order.
*/

void AnalyzeAuxSymbol(FILE *fp, int AnalyzeFlag)
{
	PSI psi;
	IMAGE_AUX_SYMBOL *aux;
	DWORD NumSym;
	int i, j, k=0;
	
	psi = GetSymbolInfo(fp);
	aux = GetAuxSymbolInfo(fp);
	NumSym = GetNumberOfAuxSymbol(fp);
	
	switch(AnalyzeFlag)
	{
		case FUNCDEF:
		{
			for(i=0;i<NumSym;i++)
			{
				if(psi[i].StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
				   psi[i].Type2[1]                                 &&
				   psi[i].SectionNumber > 0)
				{
					for(j=0;j<psi[i].NumberOfAuxSymbols;j++)
					{
						printf("%s()\n\t"
						       "Index: 0x%x\n\t"
						       "Sec: %d\n\t"
							   "Size: %d\n\t"
							   "LineNum: 0x%x\n\t"
							   "Next: 0x%x\n", 
							   psi[i].name,
							   aux[k].Sym.TagIndex,
							   psi[i].SectionNumber,
							   aux[k].Sym.Misc.TotalSize,
							   aux[k].Sym.FcnAry.Function.PointerToLinenumber,
							   aux[k].Sym.FcnAry.Function.PointerToNextFunction);
						k++;
					}
				}
				else
				{
					k+=psi[i].NumberOfAuxSymbols;
				}
			}
			break;
		}
		
		case BFEF:
		{
			for(i=0;i<NumSym;i++)
			{
				if((psi[i].StorageClass == IMAGE_SYM_CLASS_FUNCTION) &&
				   (!strcmp(psi[i].name, ".bf"))                     &&
				   (!strcmp(psi[i].name, ".lf"))                     &&
				   (!strcmp(psi[i].name, ".ef")))
				{
					for(j=0;j<psi[i].NumberOfAuxSymbols;j++)
					{
						printf("%s\n\t"
							   "Line Number: %d\n", 
							   psi[i].name,
							   aux[k].Sym.Misc.LnSz.Linenumber);
						
						if(!strcmp(psi[i].name, ".bf"))
						{
							printf("\tNext: 0x%x\n", 
							       aux[k].Sym.FcnAry.Function.PointerToNextFunction);
						}
						
						k++;
					}
				}
				else
				{
					k+=psi[i].NumberOfAuxSymbols;
				}
			}
			break;
		}
		
		case WEAKEXT:
		{
			for(i=0;i<NumSym;i++)
			{
				if(psi[i].StorageClass == IMAGE_SYM_CLASS_FILE &&
				   psi[i].SectionNumber == IMAGE_SYM_UNDEFINED)
				{
					for(j=0;j<psi[i].NumberOfAuxSymbols;j++)
					{
						printf("%s\n\t"
						       "Index: 0x%x\n\t", 
							   psi[i].name,
							   aux[k].Sym.TagIndex);
						
						printf("Characteristic: ");
						
						switch(aux[k].Sym.Misc.TotalSize)
						{
							case IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY:
								printf("No library search\n");
								break;
							
							case IMAGE_WEAK_EXTERN_SEARCH_LIBRARY:
								printf("Library search\n");
								break;
							
							case IMAGE_WEAK_EXTERN_SEARCH_ALIAS:
								printf("Alias record\n");
								break;
							
							default:
								printf("Unknown\n");
								break;
						}
						
						k++;
					}
				}
				else
				{
					k+=psi[i].NumberOfAuxSymbols;
				}
			}
			break;
		}
		
		case FILENAME:
		{		
			WORD tmp1, tmp2, tmp3;
			DWORD LongName;
			DWORD StringTableFOA = LocateSymbolTable(fp) + 
			                       GetNumberOfSymbols(fp) * 
								   sizeof(IMAGE_SYMBOL);
			char c[NAMELEN];
			
			for(i=0;i<NumSym;i++)
			{
				if(psi[i].StorageClass == IMAGE_SYM_CLASS_FILE &&
				   (!strcmp(psi[i].name, ".file")))
				{
					for(j=0;j<psi[i].NumberOfAuxSymbols;j++)
					{
						printf("%s\n\t", psi[i].name);
						printf("Source code file name: ");
						
						tmp1 = MAKEWORD(aux[k].File.Name[0], aux[k].File.Name[1]);
						
						if(tmp1==0x0000)
						{
							tmp2 = MAKEWORD(aux[k].File.Name[2], aux[k].File.Name[3]);
							tmp3 = MAKEWORD(aux[k].File.Name[4], aux[k].File.Name[5]);
							LongName = MAKELONG(tmp3, tmp2);
							fseek(fp, StringTableFOA+LongName, SEEK_SET);
							fread(c, NAMELEN, 1,fp);
							printf("%s\n", c);
						}
						else
						{
							printf("%s\n", aux[k].File.Name);
						}
						
						printf("\n");
						k++;
					}
				}
				else
				{
					k+=psi[i].NumberOfAuxSymbols;
				}
			}
			break;
		}
		
		case SECDEF:
		{
			for(i=0;i<NumSym;i++)
			{
				if(psi[i].StorageClass == IMAGE_SYM_CLASS_STATIC &&
				   (!strncmp(psi[i].name, ".", 1)))
				{
					for(j=0;j<psi[i].NumberOfAuxSymbols;j++)
					{
						printf("%s\n\t"
						       "Length: 0x%x\n\t"
							   "Number of reloc: %d\n\t"
							   "Number of linenum: %d\n", 
							   psi[i].name,
							   aux[k].Section.Length,
							   aux[k].Section.NumberOfRelocations,
							   aux[k].Section.NumberOfLinenumbers);
						
						k++;
					}
				}
				else
				{
					k+=psi[i].NumberOfAuxSymbols;
				}
			}
			break;
		}
		
		default:
			printf("Unrecognized flag.\n");
			break;
	}
	
}

/*------------------------------*/

/*---------Base Relocation Table---------*/

int GetNumberOfRelocBlock(FILE *fp)
{
	IMAGE_SECTION_HEADER reloc;
	IMAGE_DATA_DIRECTORY idd;
	IMAGE_BASE_RELOCATION IBR;
	DWORD relocRawAddr, relocVA;
	DWORD NumFixup;
	WORD *fixups;
	int i=0;
	
	reloc = GetSectionHeaderByName(fp, ".reloc");
	
	if(reloc.Name[0] == '\0')
	{
    	idd = GetSpecificDataDirectory(fp, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    	
    	if((idd.Size == 0) && (idd.VirtualAddress == 0))
    	{
			return 0;
    	}
    	
    	relocRawAddr = RVAtoFOA(fp, idd.VirtualAddress);
    	relocVA = idd.VirtualAddress;
    }
    else
    {
		relocRawAddr = reloc.PointerToRawData;
    	relocVA = reloc.VirtualAddress;
    }
    
    fseek(fp, relocRawAddr, SEEK_SET);
    
    while(1)
    {
    	fread(&IBR, IMAGE_SIZEOF_BASE_RELOCATION, 1, fp);
    	
    	if(IBR.SizeOfBlock == 0 && IBR.VirtualAddress == 0)
    	{
    		break;
    	}
    	
    	NumFixup = (IBR.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(WORD);
    	
    	fixups = (WORD*)calloc(NumFixup, sizeof(WORD));
    	
    	fread(fixups, sizeof(WORD), NumFixup, fp);
    	
    	i++;
    	
    	free(fixups);
    }
    
    return i;
}

typedef struct BaseRelocationBlock
{
	DWORD StartVA; //IMAGE_BASE_RELOCATION.VirtualAddress
	WORD *Type;    //High 4 bits
	int NumFixup;
	DWORD *Offset; //Low 12 bits
	WORD *HighAdj; //Only for IMAGE_REL_BASED_HIGHADJ
}BRB, *PBRB;

PBRB GetRelocBlock(FILE *fp)
{
	IMAGE_SECTION_HEADER reloc;
	IMAGE_DATA_DIRECTORY idd;
	IMAGE_BASE_RELOCATION IBR;
	DWORD relocRawAddr, relocVA;
	DWORD NumBlock;
	WORD *fixups;
	PBRB pbrb;
	int i=0, j=0, k=0;
	
	reloc = GetSectionHeaderByName(fp, ".reloc");
	
	if(reloc.Name[0] == '\0')
	{
    	idd = GetSpecificDataDirectory(fp, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    	
    	if((idd.Size == 0) && (idd.VirtualAddress == 0))
    	{
			return NULL;
    	}
    	
    	relocRawAddr = RVAtoFOA(fp, idd.VirtualAddress);
    	relocVA = idd.VirtualAddress;
    }
    else
    {
		relocRawAddr = reloc.PointerToRawData;
    	relocVA = reloc.VirtualAddress;
    }
    
    NumBlock = GetNumberOfRelocBlock(fp);
    
    if(NumBlock == 0)
    {
    	return NULL;
    }
    
    pbrb = (PBRB)calloc(NumBlock, sizeof(BRB));
    
    fseek(fp, relocRawAddr, SEEK_SET);
    
    for(i=0;i<NumBlock;i++)
    {
    	fread(&IBR, IMAGE_SIZEOF_BASE_RELOCATION, 1, fp);
    	
    	pbrb[i].StartVA = IBR.VirtualAddress;
    	pbrb[i].NumFixup = (IBR.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(WORD);
    	pbrb[i].Offset = (DWORD*)calloc(pbrb[i].NumFixup, sizeof(DWORD));
    	pbrb[i].Type = (WORD*)calloc(pbrb[i].NumFixup, sizeof(WORD));
    	pbrb[i].HighAdj = (WORD*)calloc(pbrb[i].NumFixup, sizeof(WORD));
    	
    	fixups = (WORD*)calloc(pbrb[i].NumFixup, sizeof(WORD));
    	fread(fixups, sizeof(WORD), pbrb[i].NumFixup, fp);
    	
    	j=0;
    	for(k=0;k<pbrb[i].NumFixup;k++)
    	{
    		pbrb[i].Type[j] = (WORD)(fixups[k] >> 12);
			pbrb[i].Offset[j] = fixups[k] & 0x0fff;
    		
			if (pbrb[i].Type[j] == IMAGE_REL_BASED_HIGHADJ)
			{
            	k++;
            	pbrb[i].HighAdj[j] = fixups[k];
        	}
			else
			{
            	pbrb[i].HighAdj[j] = 0;
        	}
        	
        	j++;
    	}
    	
    	free(fixups);
    }
    
    return pbrb;
}

/*---------------------------------------*/

/*---------Resource Table---------*/

/*Comments Warning: Please do not remove these comments in this section, 
 *Those functions are not finished yet.


IMAGE_RESOURCE_DIRECTORY GetResourceRoot(FILE *fp)
{
	IMAGE_SECTION_HEADER rsrc;
    IMAGE_DATA_DIRECTORY idd;
    IMAGE_RESOURCE_DIRECTORY ird, *pird;
    IMAGE_RESOURCE_DIRECTORY_ENTRY *pirde;
    DWORD ResourceTableFOA;
    
    pird = (IMAGE_RESOURCE_DIRECTORY*)calloc(1, sizeof(IMAGE_RESOURCE_DIRECTORY));
    
    rsrc = GetSectionHeaderByName(fp, ".rsrc");
    
	if(rsrc.Name[0] == '\0')
    {
    	idd = GetSpecificDataDirectory(fp, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    	
    	if((idd.Size == 0) && (idd.VirtualAddress == 0))
    	{
    		return *pird;
    	}
    	
    	ResourceTableFOA = RVAtoFOA(fp, idd.VirtualAddress);
    }
    else
    {
    	ResourceTableFOA = rsrc.PointerToRawData;
    }
    
    free(pird);
    
    fseek(fp, ResourceTableFOA, SEEK_SET);
    fread(&ird, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
    /*
    //Get second level
    WORD NumEntries = ird.NumberOfIdEntries + ird.NumberOfNamedEntries;
    pirde = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)calloc(NumEntries, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
    fread(pirde, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), NumEntries, fp);
    
    //Analyze second level
    int i;
    for(i=0;i<NumEntries;i++)
    {
    	if(pirde[i].u.s.NameIsString == 0)
    	{
    		printf("ID:%d\n\t", pirde[i].u.Name);
    	}
    	else
    	{
    		printf("%x\n\t", pirde[i].u.s.NameOffset);//IMAGE_RESOURCE_DIR_STRING_U
    	}
    	
    	if(pirde[i].u2.s2.DataIsDirectory)
    	{
    		printf("%x\n",pirde[i].u2.s2.OffsetToDirectory);
    	}
    	else
    	{
    		printf("$$$$$$$$$$$$$\n");//pirde[i].u2.OffsetToData
    	}
    }
    *
    return ird;
}

void ReachResourceData(IMAGE_RESOURCE_DIRECTORY ird)
{
	//IMAGE_RESOURCE_DIRECTORY ird = GetResourceRoot(fp);
	WORD NumEntries = ird.NumberOfIdEntries + ird.NumberOfNamedEntries;
	
	
}
*/
/*--------------------------------*/

/*---------Certificate Table---------*/
/*
int GetNumberOfCertificate(FILE *fp)
{
	//IMAGE_SECTION_HEADER reloc;
	IMAGE_DATA_DIRECTORY idd;
	IMAGE_BASE_RELOCATION IBR;
	DWORD relocRawAddr, relocVA;
	DWORD NumFixup;
	WORD *fixups;
	int i=0;
	
	reloc = GetSectionHeaderByName(fp, ".reloc");
	
	if(reloc.Name[0] == '\0')
	{
    	idd = GetSpecificDataDirectory(fp, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    	
    	if((idd.Size == 0) && (idd.VirtualAddress == 0))
    	{
			return 0;
    	}
    	
    	relocRawAddr = RVAtoFOA(fp, idd.VirtualAddress);
    	relocVA = idd.VirtualAddress;
    }
    else
    {
		relocRawAddr = reloc.PointerToRawData;
    	relocVA = reloc.VirtualAddress;
    }
    
    fseek(fp, relocRawAddr, SEEK_SET);
    
    while(1)
    {
    	fread(&IBR, IMAGE_SIZEOF_BASE_RELOCATION, 1, fp);
    	
    	if(IBR.SizeOfBlock == 0 && IBR.VirtualAddress == 0)
    	{
    		break;
    	}
    	
    	NumFixup = (IBR.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(WORD);
    	
    	fixups = (WORD*)calloc(NumFixup, sizeof(WORD));
    	
    	fread(fixups, sizeof(WORD), NumFixup, fp);
    	
    	i++;
    	
    	free(fixups);
    }
    
    return i;
}
*/


/*-----------------------------------*/

/*---------Additional Help Functions---------*/

/*We can design a function that can transfer an address from 
 *RVA (Relative Virtual Address) to FOA (File Offset Address).
 *
 *Algorithm:
 *Compare this RVA with a VA of the start of each section and a VA of the 
 *end of this section. If RVA is in this region, use algorithm; if not, 
 *move to next section.
 *
 *Start VA: IMAGE_SECTION_HEADER.VirtualAddress
 *End VA: IMAGE_SECTION_HEADER.VirtualAddress + IMAGE_SECTION_HEADER.SizeOfRawData
 *        or
 *        IMAGE_SECTION_HEADER.VirtualAddress + IMAGE_SECTION_HEADER.Misc.VirtualSize
 *(SizeOfRawData is the size after alignment, VirtualSize is the real size, but the
 * difference will not influence the result.)
 *
 *if RVA>StartVA && RVA<EndVA            <---if RVA in this section
 *   FOA = RowAddress + (RVA - StartVA)  <---algorithm
 *else                                   <---if not
 *   Next Section                        <---repeat this in next section
 *
 *If we still cannot locate this RVA in a section after searching every section, then 
 *this RVA should be a invalid value, so we can return -1 or something can warn users.
 *
 *Sometimes, this function is not the most efficient way to calculate FOA, so we also 
 *can use algorithm directly.
*/

DWORD RVAtoFOA(FILE *fp, DWORD RVA)
{
	DWORD StartVA = 0, EndVA = 0, FOA = -1;
	IMAGE_SECTION_HEADER *psh;
	int nSectionCount;
	int i;
	
	nSectionCount = GetNumberOfSection(fp);
	psh = (IMAGE_SECTION_HEADER*)calloc(nSectionCount, sizeof(IMAGE_SECTION_HEADER));
	GetSectionHeader(fp,&psh);
	
	for(i=0;i<nSectionCount;i++)
	{
		StartVA = (*psh).VirtualAddress;
		EndVA = (*psh).VirtualAddress + (*psh).SizeOfRawData;
		
		if(RVA>=StartVA && RVA<=EndVA)
		{
			FOA = (*psh).PointerToRawData + (RVA - (*psh).VirtualAddress);
			break;
		}
		else
		{
			psh++;
		}
	}
	
	return FOA;
}

/*Analyze a time date stamp.*/
char* AnalyzeTimeDateStamp(DWORD time)
{
	return ctime((long*)&time);
}

/*-------------------------------------------*/

int main(int argc, char **argv)
{
    FILE *fp;
    //fp = fopen(argv[1],"rb");
    
    IMAGE_FILE_HEADER fh;
    WORD sn;
    PIA pia;
    IMAGE_SECTION_HEADER *psh;
    PSA psa;
    IMAGE_OPTIONAL_HEADER oh;
    IMAGE_DATA_DIRECTORY edd,idd;
    int NumMod;
    IMAGE_IMPORT_DESCRIPTOR *IID;
    IMNL *pmnl;
    FNL *fnl;
    NOF *nof;
    SI *psi;
    PEI pei;
    IMAGE_AUX_SYMBOL *aux;
    int i=0,j=0;
	
	fp = fopen(argv[1],"rb");
    if(!fp)
    {
    	printf("Cannot open file.");
		return 1;
    }
    
    NumMod = GetTheNumOfImportModule(fp);
	sn = GetNumberOfSection(fp);
    
    if(sn ==0)
    {
    	printf("Error: Cannot locate section(s).");
    	return 1;
    }
    
	if(NumMod == -1)
    {
    	printf("Warning: No import table.\n");
    }
    
    psh = (IMAGE_SECTION_HEADER*)calloc(sn, sizeof(IMAGE_SECTION_HEADER));
    IID = (IMAGE_IMPORT_DESCRIPTOR*)calloc(NumMod,sizeof(IMAGE_IMPORT_DESCRIPTOR));
    pmnl = (PIMNL)calloc(NumMod,sizeof(IMNL));
    
    GetFileHeader(fp,&fh);
    pia = GetImageAttributes(fp);
    GetSectionHeader(fp,&psh);
    GetOptionalHeader(fp,&oh);
    edd = GetExportDataDirectory(fp);
    idd = GetImportDataDirectory(fp);
    GetImportModuleTable(fp,&IID);
    nof = EnumNumberOfFunction(fp);
    pei = GetExportInfo(fp);
    psi = GetSymbolInfo(fp);
    
    printf("-----Basic information of this image-----\n\n");
    
    printf("Machine Type: %s.\n"
	       "Symbol Table Address: %X.\n"
		   "Number of Symbols: %d.\n", 
		   GetMachineType(fp),
		   LocateSymbolTable(fp),
		   GetNumberOfSymbols(fp));
	
	printf("File Attributes:\n");
	for(i=0;i<16;i++)
	{
		if(pia[i].AttributeDiscription == "")
		{
			continue;
		}
		else
		{
			printf("\t%s\n", pia[i].AttributeDiscription);
		}
	}
	
	printf("\n-----------------------------------------\n\n");
    
    printf("----------Section Analyzing---------\n\n");
    
    for(i=0;i<sn;i++)
    {
        printf("Section %s\n"
               "SizeOfRawData: 0x%X\n"
               "PointerToRawData: 0x%X\n",
               psh[i].Name,
               psh[i].SizeOfRawData,
               psh[i].PointerToRawData);
        
        psa = GetAttributeOfSpecificSection(psh[i]);
        
        printf("Section Attributes:\n");
        for(j=0;j<41;j++)
        {
        	if(psa[j].c == "")
        	{
        		continue;
        	}
        	else
        	{
        		printf("\t%s\n",psa[j].c);
        	}
        }
        
        printf("\n");
    }
    
    printf("------------------------------------\n\n");
    
    printf("-----------Import Table-----------\n\n");
    
    printf("Import table: VA:0x%X\tSize:%d\n",idd.VirtualAddress,idd.Size);
    
    if(nof==NULL)
    {
    	printf("No Import Table.\n");
    }
    
    else
    {
    	printf("Number of Module:%d\n", NumMod);
    	
    	printf("Module/Function Name List:\n");
    	
    	for (i=0;i<NumMod;i++)
    	{
    		printf("%d->\t%s(%d)\n", i+1, nof[i].name, nof[i].func);
    		fnl = EnumFunctionNameFromHNT(fp, IID[i]);
    		
    		for(j=0;j<nof[i].func;j++)
    		{
    			printf("\t\t| %s", fnl[j].FuncName);
    			if(fnl[j].BoundAddr != 0)
    			{
    				printf(" (Bound to %08x)\n", fnl[j].BoundAddr);
    			}
    			else
    			{
    				printf("\n");
    			}
    		}
    	}
    }
    
    printf("----------------------------------\n\n");
    
    printf("-----------Export Table-----------\n\n");
    
    if(pei==NULL)
    {
    	printf("No Export Table.\n");
    }
	else
	{
		printf(" Ordn\tAddr\t\t\t\tName\t\t\tForwarder\n"
    	       "------\t--------\t---------------------------------\t-----------\n");
    	
    	for(i=0;i<AdjustNumberOfExportFunction(fp);i++)
    	{
    		printf("%d\t", pei[i].Index);
    		if(pei[i].Addr == 0)
    		{
    			printf("N/A\t\t");
    			if(pei[i].Name[0] == '\0')
    			{
    				printf("N/A");
    			}
    			else
    			{
    				printf("%s", pei[i].Name);
    			}
    			printf("(%s)\n", pei[i].Forwarder);
    		}
    		else
    		{
    			printf("%08x\t",pei[i].Addr);
    			if(pei[i].Name[0] == '\0')
    			{
    				printf("N/A\n");
    			}
    			else
    			{
    				printf("%s\n", pei[i].Name);
    			}
    		}
    	}
	}
	
    printf("----------------------------------\n\n");
    
    printf("-----------Symbol Table-----------\n\n");
    
    if(psi == NULL)
    {
    	printf("No Symbol Information.\n");
    }
	else
	{
		for(i=0;i<GetNumberOfSymbols(fp) - GetNumberOfAuxSymbol(fp);i++)
    	{
    		printf("%d\t%s", i+1, psi[i].name);
   		 	if(psi[i].Type2[1])
    		{
    			printf("()\n");
    		}
    		else
    		{
    			printf("\n");
    		}
    	}
	}
	
    printf("\n--------------------------------\n\n");
    
    printf("-----------Relocation Table-----------\n\n");
    
    PBRB pbrb = GetRelocBlock(fp);
	
	if(pbrb == NULL)
	{
		printf("No Relocation Information.\n");
	}
	
	for(i=0;i<GetNumberOfRelocBlock(fp);i++)
	{
		printf("%d->   VA: %x\n", i+1, pbrb[i].StartVA);
		printf(" Offset     Type       VA\n"
		       "--------  --------  --------\n");
		for(j=0;j<pbrb[i].NumFixup;j++)
		{
			printf("%08x  ", pbrb[i].Offset[j]);
			switch(pbrb[i].Type[j])
			{
				case IMAGE_REL_BASED_ABSOLUTE:
					printf("ABS       ");
					break;
				
				case IMAGE_REL_BASED_HIGH:
					printf("HIGH      ");
					break;
				
				case IMAGE_REL_BASED_LOW:
					printf("LOW       ");
					break;
				
				case IMAGE_REL_BASED_HIGHLOW:
					printf("HIGHADJ   ");
					break;
				
				case IMAGE_REL_BASED_HIGHADJ:
					printf("HIGHADJ   ");
					break;
				
				case IMAGE_REL_BASED_MIPS_JMPADDR:
					printf("JMPADDR   ");
					break;
					
				default:
					printf("???       ");
					break;
			}
			
			if(pbrb[i].Type[j] == IMAGE_REL_BASED_MIPS_JMPADDR)
			{
				printf("%08x\n", pbrb[i].HighAdj[j]);
			}
			else if(pbrb[i].Type[j] == IMAGE_REL_BASED_ABSOLUTE)
			{
				printf("\n");
			}
			else
			{
				printf("%08x\n", pbrb[i].Offset[j] + pbrb[i].StartVA);
			}
		}
		
		printf("\n");
	}
	
	printf("--------------------------------------\n\n");
	
    free(psh);
    free(IID);
    free(pmnl);
    
    fclose(fp);
    
    printf("Analysis complete.");
    return 0;
}
