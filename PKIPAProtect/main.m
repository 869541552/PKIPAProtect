//
//  main.m
//  PKIPAProtect
//
//  Created by Pinkney on 2020/5/13.
//  Copyright © 2020 Pinkney. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include <dlfcn.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif
///防止动态调试
void disable_gdb_check(){
    void *handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
       ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
       ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
       dlclose(handle);
}

/**防二次打包
  *针对签名embedded.mobileprovision hash值检验
   *获取打包后的/_CodeSignature/CodeResources中embedded.mobileprovision的hash值
   获取方法：
      例如获取ad-hoc打包方式，先打包一次得到ipa，解压进入/_CodeSignature/CodeResources找到embedded.mobileprovision的hash值
 */
#define PROVISION_HASH @"MhYnl+9zo9DC08IzP8AVPEvORck="
static NSDictionary *rootDic=nil;
///针对签名就行认证，如果全面不匹配直接退出
void checkEmbeddedHash()
{
    NSString *newPath = [[NSBundle mainBundle] resourcePath];

    if (!rootDic) {
        rootDic = [[NSDictionary alloc] initWithContentsOfFile:[newPath stringByAppendingString:@"/_CodeSignature/CodeResources"]];
    }
    NSDictionary *fileDic = [rootDic objectForKey:@"files2"];
    NSDictionary *infoDic = [fileDic objectForKey:@"embedded.mobileprovision"];
    NSData *tempData = [infoDic objectForKey:@"hash"];
    NSString *hashStr = [tempData base64EncodedStringWithOptions:0];
    if (![PROVISION_HASH isEqualToString:hashStr]) {
        abort();//退出应用
    }
}

int main(int argc, char * argv[]) {
#ifdef RELEASE
    disable_gdb_check();
    checkEmbeddedHash();
#endif
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
