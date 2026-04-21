# Key Store Configuration

# Base key for PIN derivation
BASE_KEY_CATALOG_ID                 ?= 1
BASE_KEY_GROUP_ID                   ?= 2
BASE_KEY_SLOT_ID                    ?= 1

# Token objects: always stored in NVM - not configurable
AES_TOKEN_CATALOG_ID                ?= 1
AES_TOKEN_GROUP_ID                  ?= 4
AES_TOKEN_GROUP_SIZE                ?= 18

HMAC_TOKEN_CATALOG_ID               ?= 1
HMAC_TOKEN_GROUP_ID                 ?= 5
HMAC_TOKEN_GROUP_SIZE               ?= 18

ECC_PAIR_TOKEN_CATALOG_ID           ?= 1
ECC_PAIR_TOKEN_GROUP_ID             ?= 6
ECC_PAIR_TOKEN_GROUP_SIZE           ?= 1

ECC_PUB_TOKEN_CATALOG_ID            ?= 1
ECC_PUB_TOKEN_GROUP_ID              ?= 8
ECC_PUB_TOKEN_GROUP_SIZE            ?= 2

RSA_PAIR_TOKEN_CATALOG_ID           ?= 1
RSA_PAIR_TOKEN_GROUP_ID             ?= 9
RSA_PAIR_TOKEN_GROUP_SIZE           ?= 1

RSA_PUB_TOKEN_CATALOG_ID            ?= 1
RSA_PUB_TOKEN_GROUP_ID              ?= 11
RSA_PUB_TOKEN_GROUP_SIZE            ?= 2

# Session objects: RAM, except key pairs which require NVM due to HSE
# constraints
AES_SESSION_CATALOG_ID              ?= 2
AES_SESSION_GROUP_ID                ?= 2
AES_SESSION_GROUP_SIZE              ?= 3

HMAC_SESSION_CATALOG_ID             ?= 2
HMAC_SESSION_GROUP_ID               ?= 3
HMAC_SESSION_GROUP_SIZE             ?= 2

SHARED_SECRET_SESSION_CATALOG_ID    ?= 2
SHARED_SECRET_SESSION_GROUP_ID      ?= 4
SHARED_SECRET_SESSION_GROUP_SIZE    ?= 3

ECC_PUB_SESSION_CATALOG_ID          ?= 2
ECC_PUB_SESSION_GROUP_ID            ?= 5
ECC_PUB_SESSION_GROUP_SIZE          ?= 2

RSA_PUB_SESSION_CATALOG_ID          ?= 2
RSA_PUB_SESSION_GROUP_ID            ?= 6
RSA_PUB_SESSION_GROUP_SIZE          ?= 2

ECC_PAIR_SESSION_CATALOG_ID         ?= 1
ECC_PAIR_SESSION_GROUP_ID           ?= 7
ECC_PAIR_SESSION_GROUP_SIZE         ?= 2

RSA_PAIR_SESSION_CATALOG_ID         ?= 1
RSA_PAIR_SESSION_GROUP_ID           ?= 10
RSA_PAIR_SESSION_GROUP_SIZE         ?= 2
