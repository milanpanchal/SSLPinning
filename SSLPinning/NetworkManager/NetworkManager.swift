//
//  NetworkManager.swift
//  SSLPinning
//
//  Created by Milan Panchal on 09/03/21.
//

import Foundation

/// Search public keys on following url
/// https://www.ssllabs.com/ssltest/analyze.html

enum SSLPinning {
    case github
    case stackexchange
}

extension SSLPinning {
    var publicKey: String {
        switch self {
        case .github: return "4PhpWPCTGkqmmjRFussirzvNSi4LjL7WWhUSAVFIXDc="
        case .stackexchange: return "Egh2jmqyvXll2mvK7IZYVjB8OdtPg0BsUZXTdx0pWZQ="
        }
    }
    
    var cerName: String {
        switch self {
        case .github: return "github.com"
        case .stackexchange: return "stackexchange.com"
        }
    }
}

class NetworkManager: NSObject {
        
    private var isCertificatePinning: Bool = false
    private let sslPinningServer = SSLPinning.github
    
    /// URLSession with configured certificate pinning
    lazy var session: URLSession = {
        URLSession(configuration: URLSessionConfiguration.ephemeral,
                   delegate: self,
                   delegateQueue: OperationQueue.main)
    }()

    static let shared: NetworkManager = {
        return NetworkManager()
    }()

    override init() {
        super.init()
    }
    
    func callAPI(withURL url: URL, isCertificatePinning: Bool, completion: @escaping (String) -> Void) {
        
        self.isCertificatePinning = isCertificatePinning
        var responseMessage = ""
        
        let task = session.dataTask(with: url) { (data, response, error) in
            if error != nil {
                print("error: \(error!.localizedDescription): \(error!)")
                responseMessage = "Pinning failed"
            } else if let data = data {
                print("Received data:\n\(data.toString)")
                if isCertificatePinning {
                    responseMessage = "Certificate pinning is successfully completed"
                } else {
                    responseMessage = "Public key pinning is successfully completed"
                }
            }
            
            DispatchQueue.main.async {
                completion(responseMessage)
            }
            
        }
        task.resume()
        
    }
    
}

extension NetworkManager: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            reject(with: completionHandler)
            return
        }
        
        if self.isCertificatePinning {
                        
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
            // SSL Policies for domain name check
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            //evaluate server certifiacte
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            
            //Local and Remote certificate Data
            let remoteCertificateData:NSData = SecCertificateCopyData(certificate!)
            let localCertificateData = Certificate.certificateData(for: sslPinningServer.cerName)
            
            //Compare certificates
            if (isServerTrusted &&
                remoteCertificateData.isEqual(to: localCertificateData)) {
                // Certificate pinning is successfully completed
                accept(with: serverTrust, completionHandler)
                return
            }
            
            // Pinning failed
            reject(with: completionHandler)
        } else {
            if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                // Server public key
                let serverPublicKey = SecCertificateCopyKey(serverCertificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!

                // Server Hash key
                let serverHashKey = (serverPublicKeyData as Data).sha256WithHeader()

                // Local Hash Key
                let localHashKey = sslPinningServer.publicKey
                
                if (serverHashKey == localHashKey) {
                    // Public key pinning is successfully completed
                    accept(with: serverTrust, completionHandler)
                    return
                }
                
                // Pinning failed
                reject(with: completionHandler)
            }
        }
    }
 
    func reject(with completionHandler: ((URLSession.AuthChallengeDisposition, URLCredential?) -> Void)) {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    func accept(with serverTrust: SecTrust, _ completionHandler: ((URLSession.AuthChallengeDisposition, URLCredential?) -> Void)) {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }

}
