//
//  RNIpSecVpn.swift
//  RNIpSecVpn
//
//  Created by Sina Javaheri on 25/02/1399.
//  Copyright © 1399 AP Sijav. All rights reserved.
//

import Foundation
import NetworkExtension
import Security



// Identifiers
let serviceIdentifier = "MySerivice"
let userAccount = "authenticatedUser"
let accessGroup = "MySerivice"

// Arguments for the keychain queries
var kSecAttrAccessGroupSwift = NSString(format: kSecClass)

let kSecClassValue = kSecClass as CFString
let kSecAttrAccountValue = kSecAttrAccount as CFString
let kSecValueDataValue = kSecValueData as CFString
let kSecClassGenericPasswordValue = kSecClassGenericPassword as CFString
let kSecAttrServiceValue = kSecAttrService as CFString
let kSecMatchLimitValue = kSecMatchLimit as CFString
let kSecReturnDataValue = kSecReturnData as CFString
let kSecMatchLimitOneValue = kSecMatchLimitOne as CFString
let kSecAttrGenericValue = kSecAttrGeneric as CFString
let kSecAttrAccessibleValue = kSecAttrAccessible as CFString


class KeychainService: NSObject {
    func save(key: String, value: String) {
        let keyData: Data = key.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
        let valueData: Data = value.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!

        let keychainQuery = NSMutableDictionary()
        keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
        keychainQuery[kSecAttrGenericValue as! NSCopying] = keyData
        keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
        keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
        keychainQuery[kSecAttrAccessibleValue as! NSCopying] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        keychainQuery[kSecValueData as! NSCopying] = valueData
        // Delete any existing items
        SecItemDelete(keychainQuery as CFDictionary)
        SecItemAdd(keychainQuery as CFDictionary, nil)
    }

    func load(key: String) -> Data {
        let keyData: Data = key.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
        let keychainQuery = NSMutableDictionary()
        keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
        keychainQuery[kSecAttrGenericValue as! NSCopying] = keyData
        keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
        keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
        keychainQuery[kSecAttrAccessibleValue as! NSCopying] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        keychainQuery[kSecMatchLimit] = kSecMatchLimitOne
        keychainQuery[kSecReturnPersistentRef] = kCFBooleanTrue

        var result: AnyObject?
        let status = withUnsafeMutablePointer(to: &result) { SecItemCopyMatching(keychainQuery, UnsafeMutablePointer($0)) }

        if status == errSecSuccess {
            if let data = result as! NSData? {
                if NSString(data: data as Data, encoding: String.Encoding.utf8.rawValue) != nil {}
                return data as Data
            }
        }
        return "".data(using: .utf8)!
    }
}

@objc(RNIpSecVpn)
class RNIpSecVpn: RCTEventEmitter {
    
    @objc override static func requiresMainQueueSetup() -> Bool {
        return true
    }

    override func supportedEvents() -> [String]! {
        return [ "stateChanged" ]
    }
    
    @objc
    func prepare(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {

        // Register to be notified of changes in the status. These notifications only work when app is in foreground.
        NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object : nil , queue: nil) {
            notification in let nevpnconn = notification.object as! NEVPNConnection
            self.sendEvent(withName: "stateChanged", body: [ "state" : checkNEStatus(status: nevpnconn.status) ])
        }
        findEventsWithResolver(nil)
    }
    
    @objc
    func connect(
    _ address: NSString,
    username: NSString,
    password: NSString,
    vpnType: NSString,
    enableKillSwitch: Bool,
    mtu: NSNumber,
    findEventsWithResolver: @escaping RCTPromiseResolveBlock,
    rejecter: @escaping RCTPromiseRejectBlock
    ) -> Void {
        let vpnManager = NEVPNManager.shared()
        let kcs = KeychainService()

        vpnManager.loadFromPreferences { error in
            if let error = error {
                print("❌ Failed to load preferences:", error)
                rejecter("VPN_PREF_LOAD_ERR", error.localizedDescription, error)
                return
            }
            let p = NEVPNProtocolIKEv2()
                /* With Password Start */
                /*
                p.username = username as String
                p.remoteIdentifier = address as String
                p.serverAddress = address as String
                p.authenticationMethod = NEVPNIKEAuthenticationMethod.none
                p.childSecurityAssociationParameters.diffieHellmanGroup = NEVPNIKEv2DiffieHellmanGroup.group20
                p.childSecurityAssociationParameters.lifetimeMinutes = 1440
                p.childSecurityAssociationParameters.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithm.algorithmAES256GCM
                p.childSecurityAssociationParameters.integrityAlgorithm = NEVPNIKEv2IntegrityAlgorithm.SHA384
                p.ikeSecurityAssociationParameters.diffieHellmanGroup = NEVPNIKEv2DiffieHellmanGroup.group20
                p.ikeSecurityAssociationParameters.lifetimeMinutes = 1440
                p.ikeSecurityAssociationParameters.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithm.algorithmAES256GCM
                p.ikeSecurityAssociationParameters.integrityAlgorithm = NEVPNIKEv2IntegrityAlgorithm.SHA384
                p.enablePFS = true
                p.enableRevocationCheck = true

                kcs.save(key: "password", value: password as String)
                p.passwordReference = kcs.load(key: "password")

                p.useExtendedAuthentication = true
                p.disconnectOnSleep = false
                */
                /* With Password End */

                /* Without Password Start */
                p.serverAddress = address as String
                p.remoteIdentifier = address as String
                p.localIdentifier = ""
                p.username = nil
                p.authenticationMethod = .sharedSecret

                kcs.save(key: "sharedSecret", value: password as String)
                p.sharedSecretReference = kcs.load(key: "sharedSecret")
                p.passwordReference = nil

                p.useExtendedAuthentication = true
                p.disconnectOnSleep = false

                vpnManager.protocolConfiguration = p
                vpnManager.isEnabled = true

                // ✅ On-demand rules
                var rules = [NEOnDemandRule]()

                if enableKillSwitch {
                    let connectRule = NEOnDemandRuleConnect()
                    connectRule.interfaceTypeMatch = .any

                    let disconnectRule = NEOnDemandRuleDisconnect()
                    disconnectRule.interfaceTypeMatch = .any

                    rules = [connectRule, disconnectRule]
                } else {
                    let connectRule = NEOnDemandRuleConnect()
                    connectRule.interfaceTypeMatch = .any

                    rules = [connectRule]
                }

                vpnManager.isOnDemandEnabled = true
                vpnManager.onDemandRules = rules
                /* Without Password End */
                // ✅ Save and start
                vpnManager.saveToPreferences { saveError in
                    if let saveError = saveError {
                        print("❌ Failed to save preferences:", saveError)
                        rejecter("VPN_SAVE_ERR", saveError.localizedDescription, saveError)
                        return
                    }

                    do {
                        try vpnManager.connection.startVPNTunnel()
                        print("✅ VPN started")
                        findEventsWithResolver(nil)
                    } catch let startErr {
                        print("❌ VPN start failed:", startErr)
                        rejecter("VPN_START_ERR", startErr.localizedDescription, startErr)
                    }
                }
            }
    }
    
    @objc
    func disconnect(_ enableKillSwitch: Bool, findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        let vpnManager = NEVPNManager.shared()
        vpnManager.loadFromPreferences(completionHandler: { error in
            if error != nil {
                print("VPN Disconnect error", error!)
            } else {
                vpnManager.connection.stopVPNTunnel()

                let p = NEVPNProtocolIKEv2()
                let kcs = KeychainService()
                p.username = nil
                p.remoteIdentifier = ""
                p.localIdentifier = ""
                p.serverAddress = ""
                p.authenticationMethod = NEVPNIKEAuthenticationMethod.sharedSecret

                kcs.save(key: "sharedSecret", value: "")
                p.sharedSecretReference = kcs.load(key: "sharedSecret")
                p.passwordReference = nil

                p.disconnectOnSleep = false

                vpnManager.onDemandRules = []
                vpnManager.isOnDemandEnabled = false
                vpnManager.protocolConfiguration = p
                vpnManager.isEnabled = false
                vpnManager.saveToPreferences()
            }
        })
        findEventsWithResolver(nil)
    }
    
    @objc
    func getCurrentState(_ findEventsWithResolver:RCTPromiseResolveBlock, rejecter:RCTPromiseRejectBlock) -> Void {
        let vpnManager = NEVPNManager.shared()
        let status = checkNEStatus(status: vpnManager.connection.status)
        if(status.intValue < 5){
            findEventsWithResolver(status)
        } else {
            rejecter("VPN_ERR", "Unknown state", NSError())
            fatalError()
        }
    }
    
    @objc
    func getCharonErrorState(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) -> Void {
        findEventsWithResolver(nil)
    }

}


func checkNEStatus( status:NEVPNStatus ) -> NSNumber {
    switch status {
    case .connecting:
        return 1
    case .connected:
        return 2
    case .disconnecting:
        return 3
    case .disconnected:
        return 0
    case .invalid:
        return 0
    case .reasserting:
        return 4
    @unknown default:
        return 5
    }
}
