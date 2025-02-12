SHA256_HASH_KEY = 'sha256_hash'
FIRST_SEEN_KEY = 'first_seen'
LAST_SEEN_KEY = 'last_seen'
FILE_TYPE_KEY = 'file_type'
FILE_NAME_KEY = 'file_name'
FILE_SIZE_KEY = 'file_size'
FILE_EXT_KEY = 'file_ext'
POPULAR_THREAT_CLASSIFICATION = 'popular_threat_classification'

file_info_dict_template = \
    {
        SHA256_HASH_KEY: None,
        FIRST_SEEN_KEY: None,
        FILE_TYPE_KEY: None,
        FILE_NAME_KEY: None,
        FILE_SIZE_KEY: None,
        FILE_EXT_KEY: None,
        POPULAR_THREAT_CLASSIFICATION: None
    }


def new_file_info_dict(sha256_hash, first_seen=None, file_type=None, file_name=None, file_size=None, file_ext=None, popular_threat_classification=None):
    file_info_dict = file_info_dict_template.copy()
    file_info_dict[SHA256_HASH_KEY] = sha256_hash
    file_info_dict[FIRST_SEEN_KEY] = first_seen
    file_info_dict[FILE_TYPE_KEY] = file_type
    file_info_dict[FILE_NAME_KEY] = file_name
    file_info_dict[FILE_SIZE_KEY] = file_size
    file_info_dict[FILE_EXT_KEY] = file_ext
    file_info_dict[POPULAR_THREAT_CLASSIFICATION] = popular_threat_classification

    return file_info_dict


"""
Sample json representation of MalwareBazaar file information (essentially the lowest common dominator file info)
    {"sha256_hash": "110a91b180bc3421d6c10d8dccd371994872e48a2414d12cf5c9dc0f15f1ee1f",
     "sha3_384_hash": "832dd901acdba83ec4ed261079b1cfd94742130d353b9be3d3edf243f6497abf0f36bd11399321f4a7c59d9ca3f97a57",
     "sha1_hash": "9f057d94c9b77d6286073dc5b5c382bcba67a3b2", "md5_hash": "ea372104f1e9f069068e3752b543c7b0",
     "first_seen": "2022-05-05 15:17:50", "last_seen": "2022-05-05 15:22:15", "file_name": "Invoice.exe",
     "file_size": 270017, "file_type_mime": "application/x-dosexec", "file_type": "exe", "reporter": "GovCERT_CH",
     "anonymous": 0, "signature": "AgentTesla", "imphash": "56a78d55f3f7af51443e58e0ce2fb5f6",
     "tlsh": "T1704412827790C493E8B14B303E3A9F7E95EB842528A8DB5F43508B5A7E11781592DFB3", "telfhash": "None",
     "ssdeep": "6144:HNeZmbFbpPhnmoF3EPQQxbG37bCveL0vDxeiDWM6Wzon+Z:HNlbppJnmGKQQxi3SQziDtTo+Z",
     "dhash_icon": "b2a89c96a2cada72", "tags": ["AgentTesla", "exe"],
     "intelligence": {"clamav": ["SecuriteInfo.com.Trojan.NSISX.Spy.Gen.2.6896.UNOFFICIAL"], "downloads": "105",
                      "uploads": "2", "mail": "None"}},
"""
