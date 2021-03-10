//
//  TrustKitNetworkManager.swift
//  SSLPinning
//
//  Created by Milan Panchal on 10/03/21.
//

import TrustKit

final class TrustKitNetworkManager: NSObject, URLSessionDelegate {
    
    /// URLSession with configured certificate pinning
    private lazy var session: URLSession = {
        URLSession(configuration: URLSessionConfiguration.ephemeral,
                   delegate: self,
                   delegateQueue: OperationQueue.main)
    }()
    
    private let trustKitConfig: [String: Any] = [
        kTSKSwizzleNetworkDelegates: false,
        kTSKPinnedDomains: [
            "www.stackexchange.com": [
                kTSKDisableDefaultReportUri: true,
                kTSKEnforcePinning: true,
                kTSKIncludeSubdomains: true,
                kTSKPublicKeyHashes: [
                    "Egh2jmqyvXll2mvK7IZYVjB8OdtPg0BsUZXTdx0pWZQ="
                ],
            ],
            "github.com": [
                kTSKDisableDefaultReportUri: true,
                kTSKEnforcePinning: true,
                kTSKIncludeSubdomains: true,
                kTSKPublicKeyHashes: [
                    "4PhpWPCTGkqmmjRFussirzvNSi4LjL7WWhUSAVFIXDc="
                ],
            ]
        ]
    ]
    
    static let shared: TrustKitNetworkManager = {
        return TrustKitNetworkManager()
    }()

    override init() {
        TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
        super.init()
    }
    
    func callAPI(withURL url: URL, completion: @escaping (String) -> Void) {
        
        var responseMessage = ""

        session.dataTask(with: url) { (data, response, error) in
            if error != nil {
                print("error: \(error!.localizedDescription): \(error!)")
                responseMessage = "Pinning failed"
            } else if let data = data {
                print("Received data:\n\(data.toString)")
                responseMessage = "Public key pinning is successfully completed"
            }
            
            DispatchQueue.main.async {
                completion(responseMessage)
            }
            
        }.resume()
        
    }
    
    // MARK: TrustKit Pinning Reference
    
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
           
        print("Checking: URLAuthenticationChallenge")
        
        if TrustKit.sharedInstance().pinningValidator.handle(challenge, completionHandler: completionHandler) == false {
            // TrustKit did not handle this challenge: perhaps it was not for server trust
            // or the domain was not pinned. Fall back to the default behavior
            print("Error")
            completionHandler(.performDefaultHandling, nil)
        } else {
            print("Some error occured")
        }
    }
}
