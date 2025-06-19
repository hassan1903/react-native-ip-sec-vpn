//
//  RNIpSecVpnBridge.m
//  RNIpSecVpn
//
//  Copyright © 2025 HK Kucukoztas. All rights reserved.
//

#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

@interface RCT_EXTERN_MODULE(RNIpSecVpn, RCTEventEmitter)

RCT_EXTERN_METHOD(prepare:(RCTPromiseResolveBlock)findEventsWithResolver
                  rejecter:(RCTPromiseRejectBlock)rejecter)

RCT_EXTERN_METHOD(connect:(NSString *)address
                  username:(NSString *)username
                  password:(NSString *)password
                  vpnType:(NSString *)vpnType
                  enableKillSwitch:(BOOL)enableKillSwitch
                  mtu:(NSNumber *_Nonnull)mtu
                  findEventsWithResolver:(RCTPromiseResolveBlock)findEventsWithResolver
                  rejecter:(RCTPromiseRejectBlock)rejecter)

RCT_EXTERN_METHOD(disconnect:(NSString *)vpnType
                  findEventsWithResolver:(RCTPromiseResolveBlock)findEventsWithResolver
                  rejecter:(RCTPromiseRejectBlock)rejecter)

RCT_EXTERN_METHOD(getCurrentState:(NSString *)vpnType
                  findEventsWithResolver:(RCTPromiseResolveBlock)findEventsWithResolver
                  rejecter:(RCTPromiseRejectBlock)rejecter)

RCT_EXTERN_METHOD(getCharonErrorState:(RCTPromiseResolveBlock)findEventsWithResolver
                  rejecter:(RCTPromiseRejectBlock)rejecter)

@end
