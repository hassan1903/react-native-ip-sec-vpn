//
//  RNIpSecVpn.swift
//  RNIpSecVpn
//
//  Created by Hasan Kucukoztas on 25/02/2024.
//  Copyright © 2025 HK Kucukoztas. All rights reserved.

import CryptoKit
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

  // -----------------------------
  // WireGuard support (ADDED)
  // Does not touch save/load above
  // -----------------------------

  func saveWgString(key: String, value: String) {
    let keyData: Data = key.data(
      using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!
    let valueData: Data = value.data(
      using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!

    let keychainQuery = NSMutableDictionary()
    keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
    keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
    keychainQuery[kSecAttrServiceValue as! NSCopying] = "WG_KEYS"  // separate namespace
    keychainQuery[kSecAttrAccessibleValue as! NSCopying] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    keychainQuery[kSecValueData as! NSCopying] = valueData

    SecItemDelete(keychainQuery as CFDictionary)
    SecItemAdd(keychainQuery as CFDictionary, nil)
  }

  func loadWgString(key: String) -> String? {
    let keyData: Data = key.data(
      using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)!

    let keychainQuery = NSMutableDictionary()
    keychainQuery[kSecClassValue as! NSCopying] = kSecClassGenericPasswordValue
    keychainQuery[kSecAttrAccountValue as! NSCopying] = keyData
    keychainQuery[kSecAttrServiceValue as! NSCopying] = "WG_KEYS"
    keychainQuery[kSecAttrAccessibleValue as! NSCopying] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    keychainQuery[kSecMatchLimit] = kSecMatchLimitOne
    keychainQuery[kSecReturnData] = kCFBooleanTrue

    var result: AnyObject?
    let status = withUnsafeMutablePointer(to: &result) {
      SecItemCopyMatching(keychainQuery, UnsafeMutablePointer($0))
    }

    guard status == errSecSuccess, let data = result as? Data else {
      return nil
    }
    return String(data: data, encoding: .utf8)
  }

  func getOrCreateWgKeyPair(
    privateKeyKey: String = "wg_priv_key",
    publicKeyKey: String = "wg_pub_key",
    generator: () -> (priv: String, pub: String)
  ) -> (priv: String, pub: String) {
    if let priv = loadWgString(key: privateKeyKey),
      let pub = loadWgString(key: publicKeyKey),
      !priv.isEmpty, !pub.isEmpty
    {
      return (priv, pub)
    }

    let keys = generator()
    saveWgString(key: privateKeyKey, value: keys.priv)
    saveWgString(key: publicKeyKey, value: keys.pub)
    return keys
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
    if (vpnType as String).lowercased() == "wireguard" {
      let baseUrl =
        "https://faas-sfo3-7872a1dd.doserverless.co/api/v1/namespaces"
      let apiToken = password as String

      let kcs = KeychainService()
      let keys = kcs.getOrCreateWgKeyPair {
        let kp = generateWgKeyPairBase64()
        return (priv: kp.privateKey, pub: kp.publicKey)
      }

      Task {
        do {
          let reg = try await wgRegister(
            baseUrl: baseUrl, apiToken: apiToken, clientPublicKey: keys.pub,
            ipAddress: address as String)

          let wgConfig = buildWgQuickConfig(
            clientPrivateKey: keys.priv,
            internalIp: reg.internal_ip,
            dns: reg.dns,
            serverPublicKey: reg.server_public_key,
            endpoint: reg.endpoint,
            mtu: mtu.intValue > 0 ? mtu.intValue : nil
          )

          NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
              rejecter("VPN_PREF_LOAD_ERR", error.localizedDescription, error)
              return
            }

            let manager =
              managers?.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                  == "com.astravpn.app.PacketTunnel"
              }) ?? NETunnelProviderManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.astravpn.app.PacketTunnel"
            proto.serverAddress = reg.endpoint
            proto.providerConfiguration = ["wgQuickConfig": wgConfig]

            manager.protocolConfiguration = proto
            manager.localizedDescription = "Astra VPN"
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
        } catch {
          rejecter("WG_REGISTER_ERR", error.localizedDescription, error)
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
        if saveError != nil {
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
    if (vpnType as String).lowercased() == "wireguard" {
      NETunnelProviderManager.loadAllFromPreferences { managers, error in
        guard
          error == nil,
          let manager = managers?.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
              == "com.astravpn.app.PacketTunnel"
          })
        else {
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
    if (vpnType as String).lowercased() == "wireguard" {
      NETunnelProviderManager.loadAllFromPreferences { managers, _ in
        let manager = managers?.first(where: {
          ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
            == "com.astravpn.app.PacketTunnel"
        })
        let status = checkNEStatus(status: manager?.connection.status ?? .disconnected)
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

private func generateWgKeyPairBase64() -> (privateKey: String, publicKey: String) {
  let priv = Curve25519.KeyAgreement.PrivateKey()
  let pub = priv.publicKey

  // WireGuard expects 32-byte keys, base64-encoded (with padding is OK)
  let privB64 = priv.rawRepresentation.base64EncodedString()
  let pubB64 = pub.rawRepresentation.base64EncodedString()

  return (privB64, pubB64)
}

private struct WgRegisterResponse: Decodable {
  let status: String
  let internal_ip: String
  let server_public_key: String
  let endpoint: String
  let dns: String
}

private func wgRegister(
  baseUrl: String, apiToken: String, clientPublicKey: String, ipAddress: String
) async throws
  -> WgRegisterResponse
{
  guard let url = URL(string: "\(baseUrl)/fn-3fc1a7d1-bb38-4db8-bc59-ceeb612001a8/actions/register-wg-vpn?blocking=true&result=true") else {
    throw NSError(domain: "WG", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid baseUrl"])
  }

  var request = URLRequest(url: url)
  request.httpMethod = "POST"
  request.setValue("application/json", forHTTPHeaderField: "Content-Type")
  request.setValue("Basic NDBhMjUwM2UtNjIwZS00OGNiLWE2OTUtOGIzOTlkM2VjODk2OjIzZWdrQXJNOTBoRjFlN2JqMkdaZ1pzaE1SUUR1aU5zejdIY2d2ZU5mc0NJYlhvejlpS2l5dFJTV0VrYVNHSUo=", forHTTPHeaderField: "Authorization")

  let payload = [
    "public_key": clientPublicKey,
    "api_token": apiToken,
    "registration_api_ip": ipAddress,
  ]
  request.httpBody = try JSONSerialization.data(withJSONObject: payload)

  let (data, resp) = try await URLSession.shared.data(for: request)

  if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
    let body = String(data: data, encoding: .utf8) ?? ""
    throw NSError(
      domain: "WG", code: http.statusCode,
      userInfo: [NSLocalizedDescriptionKey: "Register failed: \(http.statusCode) \(body)"])
  }

  return try JSONDecoder().decode(WgRegisterResponse.self, from: data)
}

private func buildWgQuickConfig(
  clientPrivateKey: String,
  internalIp: String,
  dns: String,
  serverPublicKey: String,
  endpoint: String,
  mtu: Int?
) -> String {
  var lines: [String] = [
    "[Interface]",
    "PrivateKey=\(clientPrivateKey)",
    "Address=\(internalIp)",
    "DNS=\(dns)",
  ]
  if let mtu { lines.append("MTU=\(mtu)") }

  lines += [
    "",
    "[Peer]",
    "PublicKey=\(serverPublicKey)",
    "Endpoint=\(endpoint)",
    "AllowedIPs=0.0.0.0/0, ::/0",
    "PersistentKeepalive=25",
  ]

  return lines.joined(separator: "\n")
}
