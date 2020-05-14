//
//  PKMobileProvisionInfo.h
//  PKIPAProtect
//
//  Created by Pinkney on 2020/5/13.
//  Copyright © 2020 Pinkney. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

//防止IPA包被二次打包的方案：
//
//1、检测plist文件中是否有SignerIdentity值，SignerIdentity值只有ipa包被反编译后篡改二进制文件再次打包，才会有此值。(注：如果替换资源文件，比如图片、plist文件等是没有SignerIdentity这个值的。猜测只有改了二进制文件才会有此值(待验证) )
//
//2、检测 cryptid 的值来检测二进制文件是否被篡改。网上说这也是一种解决方案，但是cryptid这个值好像在Mach-o中才有，目前还不知道如何获取该值。可以通过检测cryptid的值来检测是否被篡改，篡改过cryptid的值为0   cryptid为加密状态，0表示未加密，1表示解密；
//
//3、IPA包上传到TestFlight或者App Store后，计算安装包中重要文件的MD5 值，服务器记录，在应用运行前首先将本地计算的 MD5 值和服务器记录的 MD5 值 进行对比，如不同，则退出应用。(注：该方案已经通过验证，项目已上线)
/*
       如果二次打包的话，一般篡改者都会更换一下IPA包里的embedded.mobileprovision文件，我想可不可以从这个文件入手来解决问题，通过验证这个文件的MD5值来做验证(CodeResources文件中已经有该文件对应的MD5值了)。经过测试发现，正常用Xcode打出来的包是有这个文件的，但是，IPA包上传到App Store被苹果处理之后，就没有这个文件了，所以，该方案不可行。

 更新：

      看了iOS App签名的原理之后，再对embedded.mobileprovision文件做一下详细说明。为什么IPA包上传到App Store被苹果处理之后就没有这个文件了呢？因为embedded.mobileprovision文件里边存储的是证书相关的公钥私钥信息，苹果会用自己的私钥验证这里边的内容，如果验证通过则说明该APP是安全的合法的，之后就会将该文件删除，因为，App Store的APP苹果会用自己的公钥私钥进行重签名(也就是加壳)，这样该文件就失去它的意义了，所以被删除了。这也就是为啥证书过期之后，从App Store上已经下载过的APP还可以继续使用的原因。

      而通过企业证书分发的APP，IPA包里边还是有这个文件的，这时候苹果做安全校验的时候就是通过这个文件去做的，所以，如果企业证书过期了，这时候企业分发的APP就立马不能安装使用了，并且已经下载安装的APP也不能使用。

 总结embedded.mobileprovision文件存在的情况：

    不存在该文件：App Store下载的IPA、Cydia商店(越狱手机上的)下载的IPA。

    存在该文件：Xcode打出来的IPA、企业证书分发的IPA、越狱手机上自己二次打包的IPA
 */
/**
iOS 安全防护之重签名防护，通过读取 embedded.mobileprovision ，取出里面相关信息比较
注意：
embedded.mobileprovision
1、在 App Store 下载的 App 中不会存在，
2、在模拟器 build 包也不会存在
*/


@interface PKMobileProvisionInfo : NSObject
+ (instancetype)shareInstance;

/**
 通过传入真实 AppIdentifier 来检查包是否为重签名的包
 */
- (void)checkAppleId:(NSString *)appID;

/**
 com.apple.developer.team-identifier

 @return team identifier
 */
- (NSString *)getTeamIdentifier;

/**
 application-identifier

 @return app identifier
 */
- (NSString *)getAppIdentifier;

/**
 com.apple.security.application-groups

 @return group id
 */
- (NSString *)getGroupIdentifier;

/**
 bunlde Identifier 与 AppIdentifier 区别是少个 team 头

 @return bundle id
 */
- (NSString *)getBundleIdentifier;

/** 当前设备是否越狱 */
+ (BOOL)isDeviceJailbreak;

/** 文件是否被篡改 */
+ (BOOL)isDocumentHasBeenTamper;

+(BOOL)isBinaryEncrypted;
@end

NS_ASSUME_NONNULL_END
