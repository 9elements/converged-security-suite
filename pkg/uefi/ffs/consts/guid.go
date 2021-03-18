package consts

import (
	"github.com/linuxboot/fiano/pkg/guid"
)

var (
	// GUIDModuleTcgPie is the GUID of UEFI node "TcgPie"
	GUIDModuleTcgPie = *guid.MustParse("2BE1E4A6-6505-43B3-9FFC-A3C8330E0432")

	// GUIDModuleTcg2Pie is the GUID of UEFI node "Tcg2Pie"
	GUIDModuleTcg2Pie = *guid.MustParse("A0C98B77-CBA5-4BB8-993B-4AF6CE33ECE4")

	// GUIDDXE is the GUID of UEFI node "DXE"
	GUIDDXE = *guid.MustParse("5C60F367-A505-419A-859E-2A4FF6CA6FE5")

	// GUIDDXEContainer is the GUID of UEFI node containing compressed "DXE".
	GUIDDXEContainer = *guid.MustParse("4F1C52D3-D824-4D2A-A2F0-EC40C23C5916")

	// GUIDAmiTcgPlatformPeiAfterMem is the GUID of UEFI node "AmiTcgPlatformPeiAfterMem"
	GUIDAmiTcgPlatformPeiAfterMem = *guid.MustParse("9B3F28D5-10A6-46C8-BA72-BD40B847A71A")

	// GUIDAmiTpm20PlatformPei is the GUID of UEFI node "AmiTpm20PlatformPei".
	GUIDAmiTpm20PlatformPei = *guid.MustParse("0D8039FF-49E9-4CC9-A806-BB7C31B0BCB0")

	// GUIDSignOn is the GUID of the UEFI node with "SignOn".
	GUIDSignOn = *guid.MustParse("A59A0056-3341-44b5-9C9C-6D76F7673817")

	// GUIDFid is the GUID of the UEFI node with "Fid" (I guess it is "firmware ID"/"flash ID" or something like that, IDK)
	GUIDFid = *guid.MustParse("3FD1D3A2-99F7-420b-BC69-8BB1D492A332")
)
