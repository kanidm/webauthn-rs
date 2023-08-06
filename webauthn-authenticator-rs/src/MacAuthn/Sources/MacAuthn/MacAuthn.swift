import AuthenticationServices
import SwiftRs
import Cocoa

enum Result {
    case ok([String: Any])
    case error(String)
}

class ApplicationDelegate: NSObject, NSApplicationDelegate, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    let window: NSWindow
    let authController: ASAuthorizationController
    var result: Result = .error("task did not finish")
    
    init(window: NSWindow, authController: ASAuthorizationController) {
        self.window = window
        self.authController = authController
    }
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        authController.delegate = self
        authController.presentationContextProvider = self
        authController.performRequests()
    }
    
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return window
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration {
            let rawId = credential.credentialID.toBase64Url()
            let clientDataJSON = credential.rawClientDataJSON.toBase64Url()
            let attestationObject = credential.rawAttestationObject!.toBase64Url()
            self.result = .ok([
                "id": rawId,
                "rawId": rawId,
                "type": "public-key",
                "response": [
                    "clientDataJSON": clientDataJSON,
                    "attestationObject": attestationObject
                ]
            ])
        } else if let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
            let signature = credential.signature.toBase64Url()
            let clientDataJSON = credential.rawClientDataJSON.toBase64Url()
            let authenticatorData = credential.rawAuthenticatorData.toBase64Url()
            let rawId = credential.credentialID.toBase64Url()
            self.result = .ok([
                "id": rawId,
                "rawId": rawId,
                "type": "public-key",
                "response": [
                    "clientDataJSON": clientDataJSON,
                    "authenticatorData": authenticatorData,
                    "signature": signature
                ]
            ])
        } else if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            let rawId = credential.credentialID.toBase64Url()
            let clientDataJSON = credential.rawClientDataJSON.toBase64Url()
            let attestationObject = credential.rawAttestationObject!.toBase64Url()
            self.result = .ok([
                "id": rawId,
                "rawId": rawId,
                "type": "public-key",
                "response": [
                    "clientDataJSON": clientDataJSON,
                    "attestationObject": attestationObject
                ]
            ])
        } else if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            let signature = credential.signature.toBase64Url()
            let clientDataJSON = credential.rawClientDataJSON.toBase64Url()
            let authenticatorData = credential.rawAuthenticatorData.toBase64Url()
            let rawId = credential.credentialID.toBase64Url()
            self.result = .ok([
                "id": rawId,
                "rawId": rawId,
                "type": "public-key",
                "response": [
                    "clientDataJSON": clientDataJSON,
                    "authenticatorData": authenticatorData,
                    "signature": signature
                ]
            ])
        } else {
            self.result = .error("unhandled credential")
        }
        NSApplication.shared.stop(0)
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        self.result = .error(error.localizedDescription)
        NSApplication.shared.stop(0)
    }
}

// ASAuthorizationController expects an ASPresentationAnchor (a NSWindow)
// in order to know where to place itself. This function can create such
// a window and run the NSRunLoop event loop to completion for it.
func run(authController: ASAuthorizationController) -> String {
    NSApplication.shared.setActivationPolicy(.regular)
    let window = NSWindow(contentRect: NSMakeRect(0, 0, 1, 1), styleMask: .borderless, backing: .buffered, defer: false)
    window.center()
    window.makeKeyAndOrderFront(window)
    
    let applicationDelegate = ApplicationDelegate(window: window, authController: authController)
    NSApplication.shared.delegate = applicationDelegate
    
    NSApplication.shared.activate(ignoringOtherApps: true)
    NSApplication.shared.run()
    
    // Rust expects one of either {"data": ...} or {"error": ...}
    switch applicationDelegate.result {
    case let .ok(data):
        return String(data: try! JSONSerialization.data(withJSONObject: ["data": data]), encoding: .utf8)!
    case let .error(message):
        return String(data: try! JSONSerialization.data(withJSONObject: ["error": message]), encoding: .utf8)!
    }
}

@_cdecl("perform_register")
public func performRegister(options: SRString) -> SRString {
    let options = try! JSONDecoder().decode(PublicKeyCredentialCreationOptions.self, from: Data(options.toArray()))
    
    let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.rp.id)
    let platformKeyRequest = platformProvider.createCredentialRegistrationRequest(challenge: options.challenge.decodeBase64Url()!, name: options.user.name, userID: options.user.id.decodeBase64Url()!)
    platformKeyRequest.displayName = options.user.displayName
    platformKeyRequest.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference.init(rawValue: options.authenticatorSelection.userVerification ?? "preferred")
    
    let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: options.rp.id)
    
    let securityKeyRequest = securityKeyProvider.createCredentialRegistrationRequest(challenge: options.challenge.decodeBase64Url()!, displayName: options.user.displayName, name: options.user.name, userID: options.user.id.decodeBase64Url()!)
    
    securityKeyRequest.credentialParameters = []
    for publicKeyParam in options.pubKeyCredParams {
        let algorithm = ASCOSEAlgorithmIdentifier(rawValue: publicKeyParam.alg)
        let parameters = ASAuthorizationPublicKeyCredentialParameters(algorithm: algorithm)
        securityKeyRequest.credentialParameters.append(parameters)
    }
    
    securityKeyRequest.excludedCredentials = []
    for credential in (options.excludeCredentials ?? []) {
        let id = credential.id.decodeBase64Url()!
        let transports = credential.transports?.map {
            ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.init(rawValue: $0)
        } ?? ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
        let credential = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: id, transports: transports)
        securityKeyRequest.excludedCredentials.append(credential)
    }
    
    securityKeyRequest.attestationPreference = ASAuthorizationPublicKeyCredentialAttestationKind(rawValue: options.attestation ?? "none")
    securityKeyRequest.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference.init(rawValue: options.authenticatorSelection.userVerification ?? "preferred")
    
    if options.authenticatorSelection.requireResidentKey == true {
        securityKeyRequest.residentKeyPreference = .required
    } else {
        securityKeyRequest.residentKeyPreference = .preferred
    }
    
    let authController = ASAuthorizationController(authorizationRequests: [platformKeyRequest, securityKeyRequest])
    
    return SRString(run(authController: authController))
}

@_cdecl("perform_auth")
public func performAuth(options: SRString) -> SRString {
    let options = try! JSONDecoder().decode(PublicKeyCredentialRequestOptions.self, from: Data(options.toArray()))
    
    let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
    let securityKeyRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: options.challenge.decodeBase64Url()!)
    
    let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.rpId)
    let platformKeyRequest = platformProvider.createCredentialAssertionRequest(challenge: options.challenge.decodeBase64Url()!)
    
    securityKeyRequest.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference.init(rawValue: options.userVerification ?? "preferred")
    
    securityKeyRequest.allowedCredentials = []
    for credential in (options.allowCredentials ?? []) {
        let id = credential.id.decodeBase64Url()!
        let transports = credential.transports?.map {
            ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.init(rawValue: $0)
        } ?? ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
        let descriptor = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: id, transports: transports)
        securityKeyRequest.allowedCredentials.append(descriptor)
    }
    // Setting allowedCredentials can hang for some reason: https://developer.apple.com/forums/thread/727267
    securityKeyRequest.allowedCredentials = []
    
    let authController = ASAuthorizationController(authorizationRequests: [platformKeyRequest, securityKeyRequest])
    
    return SRString(run(authController: authController))
}
