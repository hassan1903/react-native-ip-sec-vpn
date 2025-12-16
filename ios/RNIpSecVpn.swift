//
//  RNIpSecVpn.swift
//  RNIpSecVpn
//
//  Created by Hasan Kucukoztas on 25/02/2024.
//  Copyright © 2025 HK Kucukoztas. All rights reserved.

import Foundation
import NetworkExtension
import Security

let kSecClassValue = kSecClass as CFString
let kSecAttrAccountValue = kSecAttrAccount as CFString
let kSecClassGenericPasswordValue = kSecClassGenericPassword as CFString
let kSecAttrServiceValue = kSecAttrService as CFString
let kSecAttrAccessibleValue = kSecAttrAccessible as CFString

class KeychainService: NSObject {
  func save(key: String, value: String) {
    let keyData: Data = key.data(
      using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
    let valueData: Data = value.data(
      using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!

    let keychainQuery = NSMutableDictionary()
    keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
    keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
    keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
    keychainQuery[kSecAttrAccessibleValue as! NSCopying] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    keychainQuery[kSecValueData as! NSCopying] = valueData
    // Delete any existing items
    SecItemDelete(keychainQuery as CFDictionary)
    SecItemAdd(keychainQuery as CFDictionary, nil)
  }

  func load(key: String) -> Data {
    let keyData: Data = key.data(
      using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
    let keychainQuery = NSMutableDictionary()
    keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
    keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
    keychainQuery[kSecAttrServiceValue as! NSCopying] = "VPN"
    keychainQuery[kSecAttrAccessibleValue as! NSCopying] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    keychainQuery[kSecMatchLimit] = kSecMatchLimitOne
    keychainQuery[kSecReturnPersistentRef] = kCFBooleanTrue

    var result: AnyObject?
    let status = withUnsafeMutablePointer(to: &result) {
      SecItemCopyMatching(keychainQuery, UnsafeMutablePointer($0))
    }

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
    return ["stateChanged"]
  }

  @objc
  func prepare(_ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock) {
    // Register to be notified of changes in the status. These notifications only work when app is in foreground.
    NotificationCenter.default.addObserver(
      forName: NSNotification.Name.NEVPNStatusDidChange, object: nil, queue: nil
    ) {
      notification in
      let nevpnconn = notification.object as! NEVPNConnection
      self.sendEvent(
        withName: "stateChanged", body: ["state": checkNEStatus(status: nevpnconn.status)])
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
  ) {
    if vpnType.lowercased == "wireguard" {
      NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if let error = error {
          rejecter("VPN_PREF_LOAD_ERR", error.localizedDescription, error)
          return
        }

        let manager = managers?.first ?? NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.astravpn.app.PacketTunnel"
        proto.serverAddress = address as String

        let rawWgConfig = password as String
        let cleanWgConfig = rawWgConfig.replacingOccurrences(of: "\\n", with: "\n")
        proto.providerConfiguration = ["wgQuickConfig": cleanWgConfig]

        print("WG Config:\n\(cleanWgConfig)")
        print("proto.providerConfiguration:\n\(proto.providerConfiguration ?? [:])")

        manager.protocolConfiguration = proto
        manager.localizedDescription = "AstraVPN WireGuard"
        manager.isEnabled = true

        manager.saveToPreferences { error in
          if let error = error {
            rejecter("VPN_SAVE_ERR", error.localizedDescription, error)
            return
          }

          manager.loadFromPreferences { error in
            if let error = error {
              rejecter("VPN_RELOAD_ERR", error.localizedDescription, error)
              return
            }

            do {
              try manager.connection.startVPNTunnel()
              print("✅ VPN started successfully")
              findEventsWithResolver(nil)
            } catch let error {
              print("❌ startVPNTunnel() failed: \(error.localizedDescription)")
              rejecter("VPN_START_ERR", error.localizedDescription, error)
            }
          }
        }
      }
      return
    }

    let vpnManager = NEVPNManager.shared()
    let kcs = KeychainService()

    vpnManager.loadFromPreferences { error in
      if let error = error {
        print("❌ Failed to load preferences:", error)
        rejecter("VPN_PREF_LOAD_ERR", error.localizedDescription, error)
        return
      }
      let p = NEVPNProtocolIKEv2()
      if username != "" {
        /* With Password Start */
        p.username = username as String
        p.remoteIdentifier = address as String
        p.serverAddress = address as String
        p.authenticationMethod = NEVPNIKEAuthenticationMethod.sharedSecret
        p.childSecurityAssociationParameters.diffieHellmanGroup =
          NEVPNIKEv2DiffieHellmanGroup.group20
        p.childSecurityAssociationParameters.lifetimeMinutes = 1440
        p.childSecurityAssociationParameters.encryptionAlgorithm =
          NEVPNIKEv2EncryptionAlgorithm.algorithmAES256GCM
        p.childSecurityAssociationParameters.integrityAlgorithm =
          NEVPNIKEv2IntegrityAlgorithm.SHA384
        p.ikeSecurityAssociationParameters.diffieHellmanGroup = NEVPNIKEv2DiffieHellmanGroup.group20
        p.ikeSecurityAssociationParameters.lifetimeMinutes = 1440
        p.ikeSecurityAssociationParameters.encryptionAlgorithm =
          NEVPNIKEv2EncryptionAlgorithm.algorithmAES256GCM
        p.ikeSecurityAssociationParameters.integrityAlgorithm = NEVPNIKEv2IntegrityAlgorithm.SHA384
        p.enablePFS = true
        p.enableRevocationCheck = true

        kcs.save(key: "vpnPassword", value: password as String)
        p.passwordReference = kcs.load(key: "vpnPassword")
        p.useExtendedAuthentication = true
        p.sharedSecretReference = nil
        /* With Password End */
      } else {
        /* Without Password Start */
        p.username = nil
        p.remoteIdentifier = address as String
        p.serverAddress = address as String
        p.authenticationMethod = NEVPNIKEAuthenticationMethod.sharedSecret

        kcs.save(key: "sharedSecret", value: password as String)
        p.sharedSecretReference = kcs.load(key: "sharedSecret")
        p.passwordReference = nil
        p.useExtendedAuthentication = false

        /* Without Password End */
      }
      p.disconnectOnSleep = false
      // ✅ On-demand rules
      var rules = [NEOnDemandRule]()
      let rule = NEOnDemandRuleConnect()
      rule.interfaceTypeMatch = .any
      rules.append(rule)
      if enableKillSwitch {
        let disconnectRule = NEOnDemandRuleDisconnect()
        disconnectRule.interfaceTypeMatch = .any
        rules.append(disconnectRule)
      }
      vpnManager.onDemandRules = rules
      vpnManager.isOnDemandEnabled = true
      vpnManager.protocolConfiguration = p
      vpnManager.isEnabled = true
      // ✅ Save and start

      vpnManager.saveToPreferences(completionHandler: { (saveError) -> Void in
        if error != nil {
          print("VPN Preferences save error", saveError as Any)
        } else {
          vpnManager.loadFromPreferences(completionHandler: { loadError in

            if error != nil {
              print("VPN Preferences load error:")
              rejecter("VPN_ERR", "VPN Preferences load error:", loadError)
            } else {
              var startError: NSError?

              do {
                try vpnManager.connection.startVPNTunnel()
              } catch let error as NSError {
                startError = error
                print(startError ?? "VPN Manager cannot start tunnel")
                rejecter("VPN_ERR", "VPN Manager cannot start tunnel", startError)
              } catch {
                print("Fatal Error")
                rejecter("VPN_ERR", "Fatal Error", NSError(domain: "", code: 200, userInfo: nil))
                fatalError()
              }
              if startError != nil {
                print("VPN Preferences error: 3")
                print(startError ?? "Start Error")
                rejecter("VPN_ERR", "VPN Preferences error: 3", startError)
              } else {
                print("VPN started successfully..")
                findEventsWithResolver(nil)
              }
            }
          })
        }
      })
    }
  }

  @objc
  func disconnect(
    _ vpnType: NSString,
    username: NSString,
    findEventsWithResolver: @escaping RCTPromiseResolveBlock,
    rejecter: @escaping RCTPromiseRejectBlock
  ) {
    if vpnType.lowercased == "wireguard" {
      NETunnelProviderManager.loadAllFromPreferences { managers, error in
        guard error == nil, let manager = managers?.first else {
          rejecter("VPN_ERR", error?.localizedDescription ?? "No VPN manager", error)
          return
        }

        if manager.connection.status == .connected || manager.connection.status == .connecting {
          manager.connection.stopVPNTunnel()
          print("🔌 VPN disconnected.")
        } else {
          print("🔹 VPN already disconnected.")
        }

        findEventsWithResolver(nil)
      }
    } else {
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
          p.serverAddress = ""
          if username != "" {
            p.authenticationMethod = NEVPNIKEAuthenticationMethod.sharedSecret
            kcs.save(key: "vpnPassword", value: "")
            p.passwordReference = kcs.load(key: "vpnPassword")
            p.useExtendedAuthentication = true
          } else {
            p.authenticationMethod = NEVPNIKEAuthenticationMethod.sharedSecret

            kcs.save(key: "sharedSecret", value: "")
            p.sharedSecretReference = kcs.load(key: "sharedSecret")
            p.useExtendedAuthentication = false

          }
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
  }

  @objc
  func getCurrentState(
    _ vpnType: NSString,
    findEventsWithResolver: @escaping RCTPromiseResolveBlock,
    rejecter: @escaping RCTPromiseRejectBlock
  ) {
    if vpnType.lowercased == "wireguard" {
      let wgManager = NETunnelProviderManager()
      wgManager.loadFromPreferences { _ in
        let status = checkNEStatus(status: wgManager.connection.status)
        findEventsWithResolver(status)
      }
    } else {
      let vpnManager = NEVPNManager.shared()
      let status = checkNEStatus(status: vpnManager.connection.status)
      if status.intValue < 5 {
        findEventsWithResolver(status)
      } else {
        rejecter("VPN_ERR", "Unknown state", NSError())
        fatalError()
      }
    }
  }

  @objc
  func getCharonErrorState(
    _ findEventsWithResolver: RCTPromiseResolveBlock, rejecter: RCTPromiseRejectBlock
  ) {
    findEventsWithResolver(nil)
  }
}

func checkNEStatus(status: NEVPNStatus) -> NSNumber {
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
