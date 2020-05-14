//
//  CodeSigning.c
//  PKIPAProtect
//
//  Created by Pinkney on 2020/5/14.
//  Copyright © 2020 Pinkney. All rights reserved.
//

#include "CodeSigning.h"
#include <string.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <mach/mach_init.h>
#import <mach/mach_traps.h>
#import <mach/vm_map.h>
#define min(a,b) ( ((a)>(b)) ? (b):(a) )
unsigned char validateSlot(const void *data, size_t length, size_t slot, const CS_CodeDirectory *codeDirectory)
{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH + 1] = {0, };
    CC_SHA1(data, (CC_LONG)length, digest);
    return (memcmp(digest, (void *)((char *)codeDirectory + ntohl(codeDirectory->hashOffset) + 20*slot), 20) == 0);
}

void checkCodeSignature(void *binaryContent){
    struct load_command *machoCmd;
    const struct mach_header *machoHeader;

    machoHeader = (const struct mach_header *) binaryContent;
    if(machoHeader->magic == FAT_CIGAM){
        unsigned int offset = 0;
        struct fat_arch *fatArch = (struct fat_arch *)((struct fat_header *)machoHeader + 1);
        struct fat_header *fatHeader = (struct fat_header *)machoHeader;
        for(uint32_t i = 0; i < ntohl(fatHeader->nfat_arch); i++)
        {
            if(sizeof(int *) == 4 && !(ntohl(fatArch->cputype) & CPU_ARCH_ABI64)) // check 32bit section for 32bit architecture
            {
                offset = ntohl(fatArch->offset);
                break;
            }
            else if(sizeof(int *) == 8 && (ntohl(fatArch->cputype) & CPU_ARCH_ABI64)) // and 64bit section for 64bit architecture
            {
                offset = ntohl(fatArch->offset);
                break;
            }
            fatArch = (struct fat_arch *)((uint8_t *)fatArch + sizeof(struct fat_arch));
        }
        machoHeader = (const struct mach_header *)((uint8_t *)machoHeader + offset);
    }
    if(machoHeader->magic == MH_MAGIC)    // 32bit
    {
        machoCmd = (struct load_command *)((struct mach_header *)machoHeader + 1);
    }
    else if(machoHeader->magic == MH_MAGIC_64)   // 64bit
    {
        machoCmd = (struct load_command *)((struct mach_header_64 *)machoHeader + 1);
    }
    for(uint32_t i=0; i < machoHeader->ncmds && machoCmd != NULL; i++){
        if(machoCmd->cmd == LC_CODE_SIGNATURE)
        {
            struct linkedit_data_command *codeSigCmd = (struct linkedit_data_command *) machoCmd;

            const CS_SuperBlob *codeEmbedded = (const CS_SuperBlob *)&((char *)machoHeader)[codeSigCmd->dataoff];
            void *binaryBase = (void *)machoHeader;

            const CS_BlobIndex curIndex = codeEmbedded->index[0];
            const CS_CodeDirectory *codeDirectory = (const CS_CodeDirectory *)((char *)codeEmbedded + ntohl(curIndex.offset));

            size_t pageSize = codeDirectory->pageSize ? (1 << codeDirectory->pageSize) : 0;
            size_t remaining = ntohl(codeDirectory->codeLimit);
            size_t processed = 0;
            for(size_t slot = 0; slot < ntohl(codeDirectory->nCodeSlots); ++slot){
                size_t size = min(remaining, pageSize);
                if(!validateSlot(binaryBase+processed, size, slot, codeDirectory)){
                    return;
                }
                processed += size;
                remaining -= size;
            }
            printf("[*] Code is valid!");
        }
    }
    machoCmd = (struct load_command *)((uint8_t *)machoCmd + machoCmd->cmdsize);
}


