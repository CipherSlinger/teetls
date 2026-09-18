package csvattest

const (
	ReportSize     = 0x9f4
	PageSize       = 4096
	UserDataSize   = 64
	NonceSize      = 16
	HashSize       = 32
	SealingKeySize = 32
	SignedSize     = 0xb4

	OffsetReportPubkeyDigest = 0x000
	OffsetReportVMID         = 0x020
	OffsetReportVMVersion    = 0x030
	OffsetUserData           = 0x040
	OffsetMNonce             = 0x080
	OffsetMeasure            = 0x090
	OffsetReportPolicy       = 0x0b0
	OffsetReportSigUsage     = 0x0b4
	OffsetReportSigAlgo      = 0x0b8
	OffsetANonce             = 0x0bc
	OffsetReportSig1         = 0x0c0
	OffsetPEKCert            = 0x150
	OffsetChipID             = 0x974
	OffsetReserved2          = 0x9b4
	OffsetMAC                = 0x9d4

	HrkCertSize = 0x340
	CSVCertSize = 0x824
	HskCekSize  = HrkCertSize + CSVCertSize
	ChipIDSize  = 64

	OffsetRootKeyUsage = 0x024
	OffsetRootPubKey   = 0x040
	OffsetRootSig      = 0x240

	OffsetCSVPubKeyUsage = 0x008
	OffsetCSVPubKey      = 0x010
	OffsetCSVSig1Usage   = 0x414
	OffsetCSVSig1        = 0x41c
	OffsetCSVSig2Usage   = 0x61c
	OffsetCSVSig2        = 0x624

	OffsetECCPubKeyQX     = 0x004
	OffsetECCPubKeyQY     = 0x04c
	OffsetECCPubKeyUserID = 0x094
	OffsetHygonSigR       = 0x000
	OffsetHygonSigS       = 0x048

	KeyUsageHRK     = 0x0
	KeyUsageHSK     = 0x13
	KeyUsageInvalid = 0x1000
	KeyUsagePEK     = 0x1002
	KeyUsageCEK     = 0x1004
	CurveIDSM2      = 0x3

	HRKCertURL = "https://cert.hygon.cn/hrk"
	KDSCertURL = "https://cert.hygon.cn/hsk_cek?snumber="

	defaultCSVGuestDevice = "/dev/csv-guest"
	defaultUserDataText   = "user data"

	csvGuestIOCType          = 'D'
	getAttestationReportNR   = 1
	csvGuestMemSize          = 16
	getAttestationReportIOCT = uintptr((3 << 30) | (csvGuestMemSize << 16) | (csvGuestIOCType << 8) | getAttestationReportNR)
)
