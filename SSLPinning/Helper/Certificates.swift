//
//  Certificates.swift
//  SSLPinning
//
//  Created by Milan Panchal on 10/03/21.
//

import Foundation

struct Certificate {
    
    static func certificateData(for filename: String) -> Data {
        let filePath = Bundle.main.path(forResource: filename, ofType: "cer")!
        let data = try! Data(contentsOf: URL(fileURLWithPath: filePath))
        return data
    }
    
    static func certificate(for filename: String) -> SecCertificate {
        
        let data = certificateData(for: filename)
        let certificate = SecCertificateCreateWithData(nil, data as CFData)!
        
        return certificate
    }
    
}
