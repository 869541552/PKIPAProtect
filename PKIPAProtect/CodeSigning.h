//
//  CodeSigning.h
//  PKIPAProtect
//
//  Created by Pinkney on 2020/5/14.
//  Copyright © 2020 Pinkney. All rights reserved.
//

#ifndef CodeSigning_h
#define CodeSigning_h

#include <stdio.h>
// codes from https://opensource.apple.com/source/Security/Security-55179.1/libsecurity_codesigning/lib/cscdefs.h

enum {
    CSMAGIC_REQUIREMENT = 0xfade0c00,       /* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,      /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,     /* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */

    CSSLOT_CODEDIRECTORY = 0,               /* slot index for CodeDirectory */
};
/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
    uint32_t type;                  /* type of entry */
    uint32_t offset;                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                 /* magic number */
    uint32_t length;                /* total length of SuperBlob */
    uint32_t count;                 /* number of index entries following */
    CS_BlobIndex index[];           /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;


/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                 /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */
    uint32_t version;               /* compatibility version */
    uint32_t flags;                 /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */
    uint32_t identOffset;           /* offset of identifier string */
    uint32_t nSpecialSlots;         /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;             /* limit to main image signature range */
    uint8_t hashSize;               /* size of each hash in bytes */
    uint8_t hashType;               /* type of hash (cdHashType* constants) */
    uint8_t spare1;                 /* unused (must be zero) */
    uint8_t pageSize;               /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

static inline const CS_CodeDirectory *findCodeDirectory(const CS_SuperBlob *embedded)
{
    if (embedded && ntohl(embedded->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
        const CS_BlobIndex *limit = &embedded->index[ntohl(embedded->count)];
        const CS_BlobIndex *p;
        for (p = embedded->index; p < limit; ++p)
            if (ntohl(p->type) == CSSLOT_CODEDIRECTORY) {
                const unsigned char *base = (const unsigned char *)embedded;
                const CS_CodeDirectory *cd = (const CS_CodeDirectory *)(base + ntohl(p->offset));
                if (ntohl(cd->magic) == CSMAGIC_CODEDIRECTORY){
                    return cd;
                }
                else{
                    break;
                }
            }
    }
    // not found
    return NULL;
}
#endif /* CodeSigning_h */
