//
//  File.swift
//  
//
//  Created by snek on 2023-08-05.
//

import Foundation

struct PublicKeyCredentialDescriptor: Decodable {
    let id: String
    let transports: [String]?
}

struct PublicKeyCredentialUserEntity: Decodable {
    let id: String
    let name: String
    let displayName: String
}

struct PublicKeyCredentialRpEntity: Decodable {
    let id: String
    let name: String
}

struct PublicKeyCredentialParameters: Decodable {
    let type: String
    let alg: Int
}

struct AuthenticatorSelectionCriteria: Decodable {
    let userVerification: String?
    let requireResidentKey: Bool?
}

struct PublicKeyCredentialCreationOptions: Decodable {
    let rp: PublicKeyCredentialRpEntity
    let user: PublicKeyCredentialUserEntity
    let challenge: String
    let pubKeyCredParams: [PublicKeyCredentialParameters]
    let timeout: Double
    let excludeCredentials: [PublicKeyCredentialDescriptor]?
    let authenticatorSelection: AuthenticatorSelectionCriteria
    let attestation: String?
}

struct PublicKeyCredentialRequestOptions: Decodable {
    let challenge: String
    let timeout: Double
    let rpId: String
    let allowCredentials: [PublicKeyCredentialDescriptor]?
    let userVerification: String?
}

extension String {
    func decodeBase64Url() -> Data? {
        var base64 = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return Data(base64Encoded: base64)
    }
}

extension Data {
    func toBase64Url() -> String {
        return self
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
