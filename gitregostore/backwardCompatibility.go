package gitregostore

import (
	"strings"
)

// oldControlIdsMapping - maps old cis ids to new generated ids for backward compatibility.
// key = old id. value = new id.
var oldControlIdsMapping = map[string]string{
	"CIS-1.1.1":  "C-0092",
	"CIS-1.1.2":  "C-0093",
	"CIS-1.1.3":  "C-0094",
	"CIS-1.1.4":  "C-0095",
	"CIS-1.1.5":  "C-0096",
	"CIS-1.1.6":  "C-0097",
	"CIS-1.1.7":  "C-0098",
	"CIS-1.1.8":  "C-0099",
	"CIS-1.1.9":  "C-0100",
	"CIS-1.1.10": "C-0101",
	"CIS-1.1.11": "C-0102",
	"CIS-1.1.12": "C-0103",
	"CIS-1.1.13": "C-0104",
	"CIS-1.1.14": "C-0105",
	"CIS-1.1.15": "C-0106",
	"CIS-1.1.16": "C-0107",
	"CIS-1.1.17": "C-0108",
	"CIS-1.1.18": "C-0109",
	"CIS-1.1.19": "C-0110",
	"CIS-1.1.20": "C-0111",
	"CIS-1.1.21": "C-0112",
	"CIS-1.2.1":  "C-0113",
	"CIS-1.2.2":  "C-0114",
	"CIS-1.2.3":  "C-0115",
	"CIS-1.2.4":  "C-0116",
	"CIS-1.2.5":  "C-0117",
	"CIS-1.2.6":  "C-0118",
	"CIS-1.2.7":  "C-0119",
	"CIS-1.2.8":  "C-0120",
	"CIS-1.2.9":  "C-0121",
	"CIS-1.2.10": "C-0122",
	"CIS-1.2.11": "C-0123",
	"CIS-1.2.12": "C-0124",
	"CIS-1.2.13": "C-0125",
	"CIS-1.2.14": "C-0126",
	"CIS-1.2.15": "C-0127",
	"CIS-1.2.16": "C-0128",
	"CIS-1.2.17": "C-0129",
	"CIS-1.2.18": "C-0130",
	"CIS-1.2.19": "C-0131",
	"CIS-1.2.20": "C-0132",
	"CIS-1.2.21": "C-0133",
	"CIS-1.2.22": "C-0134",
	"CIS-1.2.23": "C-0135",
	"CIS-1.2.24": "C-0136",
	"CIS-1.2.25": "C-0137",
	"CIS-1.2.26": "C-0138",
	"CIS-1.2.27": "C-0139",
	"CIS-1.2.28": "C-0140",
	"CIS-1.2.29": "C-0141",
	"CIS-1.2.30": "C-0142",
	"CIS-1.2.31": "C-0143",
	"CIS-1.3.1":  "C-0144",
	"CIS-1.3.2":  "C-0145",
	"CIS-1.3.3":  "C-0146",
	"CIS-1.3.4":  "C-0147",
	"CIS-1.3.5":  "C-0148",
	"CIS-1.3.6":  "C-0149",
	"CIS-1.3.7":  "C-0150",
	"CIS-1.4.1":  "C-0151",
	"CIS-1.4.2":  "C-0152",
	"CIS-2.1":    "C-0153",
	"CIS-2.2":    "C-0154",
	"CIS-2.3":    "C-0155",
	"CIS-2.4":    "C-0156",
	"CIS-2.5":    "C-0157",
	"CIS-2.6":    "C-0158",
	"CIS-2.7":    "C-0159",
	"CIS-3.2.1":  "C-0160",
	"CIS-3.2.2":  "C-0161",
	"CIS-4.1.1":  "C-0162",
	"CIS-4.1.2":  "C-0163",
	"CIS-4.1.3":  "C-0164",
	"CIS-4.1.4":  "C-0165",
	"CIS-4.1.5":  "C-0166",
	"CIS-4.1.6":  "C-0167",
	"CIS-4.1.7":  "C-0168",
	"CIS-4.1.8":  "C-0169",
	"CIS-4.1.9":  "C-0170",
	"CIS-4.1.10": "C-0171",
	"CIS-4.2.1":  "C-0172",
	"CIS-4.2.2":  "C-0173",
	"CIS-4.2.3":  "C-0174",
	"CIS-4.2.4":  "C-0175",
	"CIS-4.2.5":  "C-0176",
	"CIS-4.2.6":  "C-0177",
	"CIS-4.2.7":  "C-0178",
	"CIS-4.2.8":  "C-0179",
	"CIS-4.2.9":  "C-0180",
	"CIS-4.2.10": "C-0181",
	"CIS-4.2.11": "C-0182",
	"CIS-4.2.12": "C-0183",
	"CIS-4.2.13": "C-0184",
	"CIS-5.1.1":  "C-0185",
	"CIS-5.1.2":  "C-0186",
	"CIS-5.1.3":  "C-0187",
	"CIS-5.1.4":  "C-0188",
	"CIS-5.1.5":  "C-0189",
	"CIS-5.1.6":  "C-0190",
	"CIS-5.1.8":  "C-0191",
	"CIS-5.2.1":  "C-0192",
	"CIS-5.2.2":  "C-0193",
	"CIS-5.2.3":  "C-0194",
	"CIS-5.2.4":  "C-0195",
	"CIS-5.2.5":  "C-0196",
	"CIS-5.2.6":  "C-0197",
	"CIS-5.2.7":  "C-0198",
	"CIS-5.2.8":  "C-0199",
	"CIS-5.2.9":  "C-0200",
	"CIS-5.2.10": "C-0201",
	"CIS-5.2.11": "C-0202",
	"CIS-5.2.12": "C-0203",
	"CIS-5.2.13": "C-0204",
	"CIS-5.3.1":  "C-0205",
	"CIS-5.3.2":  "C-0206",
	"CIS-5.4.1":  "C-0207",
	"CIS-5.4.2":  "C-0208",
	"CIS-5.7.1":  "C-0209",
	"CIS-5.7.2":  "C-0210",
	"CIS-5.7.3":  "C-0211",
	"CIS-5.7.4":  "C-0212",
}

const (
	cisFrameworkOldName = "CIS"
	cisFrameworkNewName = "cis-v1.23-t1.0.1"
)

// reverseMap - get a map[string]string typed struct and invert key and values.
func reverseMap(in map[string]string) map[string]string {

	n := make(map[string]string, len(oldControlIdsMapping))
	for k, v := range oldControlIdsMapping {
		n[v] = k
	}

	return n
}

// Hold inverted control ids.
// key = new id. value = old id.
var invertedOldControlIdsMapping = reverseMap(oldControlIdsMapping)

// newControlID - look for new controlID in oldControlIdsMapping. If doesn't exist, return the sent controlID.
func newControlID(controlID string) string {
	if newControlID, exist := oldControlIdsMapping[strings.ToUpper(controlID)]; exist {
		return newControlID
	}

	return controlID

}

// newFrameworkName - convert old cis name to new one, if exist, otherwise return frameworkName
func newFrameworkName(frameworkName string) string {
	if strings.EqualFold(frameworkName, cisFrameworkOldName) {
		return cisFrameworkNewName
	}

	return frameworkName
}

// baseControlName - get control name from cis control name structure "[old_cis_id] [controlName]".
func baseControlName(controlID string, controlName string) string {

	if oldControlID, exist := invertedOldControlIdsMapping[strings.ToUpper(controlID)]; exist {
		return strings.Replace(controlName, strings.ToUpper(oldControlID)+" ", "", -1)
	}

	return controlName

}

// // getNewControlName - build new control name "[old_cis_id] [controlName]" if the controlID is new and was originally a cis id, otherwise return controlName
// func newControlName(controlID string, controlName string) string {

// 	if value, exist := invertedOldControlIdsMapping[strings.ToUpper(controlID)]; exist {

// 		// if new control id was found, construct new name.
// 		return strings.ToUpper(value) + " " + controlName
//
// 	return controlName
//
// }
