//
//  PKMobileProvisionInfo.m
//  PKIPAProtect
//
//  Created by Pinkney on 2020/5/13.
//  Copyright © 2020 Pinkney. All rights reserved.
//

#import "PKMobileProvisionInfo.h"
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <mach/mach_init.h>
#import <mach/mach_traps.h>
#import <mach/vm_map.h>
#import <UIKit/UIKit.h>

@interface PKMobileProvisionInfo ()
@property (nonatomic, strong) NSString *teamID;
@property (nonatomic, strong) NSString *appID;
@property (nonatomic, strong) NSString *groupID;
@property (nonatomic, strong) NSString *bundleID;
@end

@implementation PKMobileProvisionInfo
+ (instancetype)shareInstance {
    static PKMobileProvisionInfo *_instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _instance = [[PKMobileProvisionInfo alloc] init];
        [_instance readeMbedded];
    });
    return _instance;
}

#pragma mark - Private Methods

- (void)readeMbedded {
    // 读取 ipa 包中的 embedded.mobileprovision 文件内容, 真实内容是 xml 格式
    // 描述文件路径
    NSString *embeddedPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    // 读取application-identifier 注意描述文件的编码要使用:NSASCIIStringEncoding
    NSString *embeddedProvisioning = [NSString stringWithContentsOfFile:embeddedPath encoding:NSASCIIStringEncoding error:nil];
    NSArray *embeddedProvisioningLines = [embeddedProvisioning componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (int i = 0; i < embeddedProvisioningLines.count; i++) {
        if ([embeddedProvisioningLines[i] rangeOfString:@"com.apple.security.application-groups"].location != NSNotFound) {
            // application-identifier
            NSInteger fromPosition = [embeddedProvisioningLines[i + 2] rangeOfString:@"<string>"].location + 8;
            NSInteger toPosition = [embeddedProvisioningLines[i + 2] rangeOfString:@"</string>"].location;

            NSRange range;
            range.location = fromPosition;
            range.length = toPosition - fromPosition;

            NSString *group = [embeddedProvisioningLines[i + 2] substringWithRange:range];
            self.groupID = group;
        } else if ([embeddedProvisioningLines[i] rangeOfString:@"application-identifier"].location != NSNotFound) {
            // com.apple.security.application-groups
            NSInteger fromPosition = [embeddedProvisioningLines[i + 1] rangeOfString:@"<string>"].location + 8;
            NSInteger toPosition = [embeddedProvisioningLines[i + 1] rangeOfString:@"</string>"].location;

            NSRange range;
            range.location = fromPosition;
            range.length = toPosition - fromPosition;

            self.appID = [embeddedProvisioningLines[i + 1] substringWithRange:range];
            NSArray *identifierComponents = [self.appID componentsSeparatedByString:@"."];
            self.teamID = [identifierComponents firstObject];
            NSString *replaceStr = [NSString stringWithFormat:@"%@.", self.teamID];
            self.bundleID = [self.appID stringByReplacingOccurrencesOfString:replaceStr withString:@""];
        }

        if (self.teamID.length > 0 && self.appID.length > 0 && self.groupID.length > 0) {
            break;
        }
    }
}

#pragma mark - Public Methods

- (void)checkAppleId:(NSString *)appID {
    // 对比签名ID
    if (![self.appID isEqual:appID] && appID.length > 0) {
        //exit
        exit(1);
    }
}

#pragma mark - Getter

- (NSString *)getTeamIdentifier {
    return self.teamID;
}

- (NSString *)getAppIdentifier {
    return self.appID;
}

- (NSString *)getGroupIdentifier {
    return self.groupID;
}

- (NSString *)getBundleIdentifier {
    return self.bundleID;
}

const char *Jailbreak_Tool_pathes[] = {
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt"
};

char *printEnv(void){
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    return env;
}

/** 当前设备是否越狱 */
+ (BOOL)isDeviceJailbreak
{
    // 判断是否存在越狱文件
    for (int i = 0; i < 5; i++) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithUTF8String:Jailbreak_Tool_pathes[i]]]) {
            NSLog(@"此设备越狱!");
            return YES;
        }
    }
    // 判断是否存在cydia应用
    if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]){
        NSLog(@"此设备越狱!");
        return YES;
    }
    
    // 读取系统所有的应用名称
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/User/Applications/"]){
        NSLog(@"此设备越狱!");
        return YES;
    }
    
    
    NSLog(@"此设备没有越狱");
    return NO;
}

/** 文件是否被篡改 */
+ (BOOL)isDocumentHasBeenTamper
{
    NSBundle *bundle = [NSBundle mainBundle];
    NSDictionary *info = [bundle infoDictionary];
    if ([info objectForKey:@"SignerIdentity"] != nil)
    {
        return YES;
    }
    return NO;
}

+(BOOL)isBinaryEncrypted{
    int cryptid = binaryCryptid();
    if (cryptid == 1) {
        return YES;
    }
    return NO;
}

/// cryptid为加密状态，0表示未加密，1表示解密；
int binaryCryptid()
{
    // checking current binary's LC_ENCRYPTION_INFO
    const void *binaryBase;
    struct load_command *machoCmd = NULL;
    const struct mach_header *machoHeader;

    NSString *path = [[NSBundle mainBundle] executablePath];
    NSData *filedata = [NSData dataWithContentsOfFile:path];
    binaryBase = (char *)[filedata bytes];

    machoHeader = (const struct mach_header *) binaryBase;

    if(machoHeader->magic == FAT_CIGAM)
    {
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
        if(machoCmd->cmd == LC_ENCRYPTION_INFO)
        {
            struct encryption_info_command *cryptCmd = (struct encryption_info_command *) machoCmd;
            return cryptCmd->cryptid;
        }
        if(machoCmd->cmd == LC_ENCRYPTION_INFO_64)
        {
            struct encryption_info_command_64 *cryptCmd = (struct encryption_info_command_64 *) machoCmd;
            return cryptCmd->cryptid;
        }
        machoCmd = (struct load_command *)((uint8_t *)machoCmd + machoCmd->cmdsize);
    }
    return 0; // couldn't find cryptcmd
}

@end
