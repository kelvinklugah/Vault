import Foundation
import Capacitor
import LocalAuthentication
import Security
import UIKit

@objc(VaultBioPlugin)
public class VaultBioPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "VaultBioPlugin"
    public let jsName = "VaultBio"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "available", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "store", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "retrieve", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "remove", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "exportBegin", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "exportAppend", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "exportFinish", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "exportAbort", returnType: CAPPluginReturnPromise)
    ]

    private let service = "app.vault.bio.secret"
    private var handle: FileHandle?
    private var exportDir: URL?
    private var exportFile: URL?

    // MARK: Face ID bound key

    @objc func available(_ call: CAPPluginCall) {
        var error: NSError?
        let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        call.resolve(["available": ok])
    }

    @objc func store(_ call: CAPPluginCall) {
        guard let s = call.getString("secret"), let data = Data(base64Encoded: s) else {
            call.reject("Invalid secret")
            return
        }
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            &cfError
        ) else {
            call.reject("Face ID or a passcode isn't set up on this iPhone")
            return
        }
        let match: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        SecItemDelete(match as CFDictionary)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessControl as String: access,
            kSecValueData as String: data
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecSuccess {
            call.resolve()
        } else {
            call.reject("Keychain error \(status)")
        }
    }

    @objc func retrieve(_ call: CAPPluginCall) {
        let context = LAContext()
        context.localizedReason = "Unlock your vault"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]
        DispatchQueue.global(qos: .userInitiated).async {
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            DispatchQueue.main.async {
                if status == errSecSuccess, let data = item as? Data {
                    call.resolve(["secret": data.base64EncodedString()])
                } else if status == errSecUserCanceled || status == errSecAuthFailed {
                    call.reject("Cancelled", "CANCELLED")
                } else {
                    call.reject("Keychain error \(status)")
                }
            }
        }
    }

    @objc func remove(_ call: CAPPluginCall) {
        let match: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        SecItemDelete(match as CFDictionary)
        call.resolve()
    }

    // MARK: Export through the iOS share sheet

    @objc func exportBegin(_ call: CAPPluginCall) {
        cleanup()
        let raw = call.getString("name") ?? "file"
        var name = raw.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
        if name.isEmpty { name = "file" }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let file = dir.appendingPathComponent(name)
            FileManager.default.createFile(atPath: file.path, contents: nil)
            handle = try FileHandle(forWritingTo: file)
            exportDir = dir
            exportFile = file
            call.resolve()
        } catch {
            call.reject("Couldn't create the export file")
        }
    }

    @objc func exportAppend(_ call: CAPPluginCall) {
        guard let h = handle, let s = call.getString("data"), let data = Data(base64Encoded: s) else {
            call.reject("Invalid data")
            return
        }
        do {
            try h.write(contentsOf: data)
            call.resolve()
        } catch {
            call.reject("Write failed. The iPhone may be out of space.")
        }
    }

    @objc func exportFinish(_ call: CAPPluginCall) {
        try? handle?.close()
        handle = nil
        guard let file = exportFile else {
            call.reject("No file to share")
            return
        }
        DispatchQueue.main.async {
            let sheet = UIActivityViewController(activityItems: [file], applicationActivities: nil)
            sheet.completionWithItemsHandler = { [weak self] _, _, _, _ in
                self?.cleanup()
            }
            if let pop = sheet.popoverPresentationController, let view = self.bridge?.viewController?.view {
                pop.sourceView = view
                pop.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 0, height: 0)
                pop.permittedArrowDirections = []
            }
            self.bridge?.viewController?.present(sheet, animated: true)
            call.resolve()
        }
    }

    @objc func exportAbort(_ call: CAPPluginCall) {
        cleanup()
        call.resolve()
    }

    private func cleanup() {
        try? handle?.close()
        handle = nil
        if let dir = exportDir {
            try? FileManager.default.removeItem(at: dir)
        }
        exportDir = nil
        exportFile = nil
    }
}
